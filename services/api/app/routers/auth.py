"""Simple JWT auth: one admin user from env. Writes audit events to DB. Phase B.1: RBAC + OIDC SSO."""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode, urlparse

import bcrypt
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.audit import log_audit
from app.db import get_db
from app.rate_limit import check_rate_limit
from app.request_context import request_id_ctx
from app.settings import settings

audit = logging.getLogger("secplat.audit")

# OIDC discovery cache (authorization_endpoint, token_endpoint, jwks_uri)
_oidc_config: dict | None = None
_oidc_config_fetched_at: float = 0.0
_oidc_jwks: dict | None = None
_oidc_jwks_fetched_at: float = 0.0
_oidc_jwks_uri: str | None = None
OIDC_CONFIG_TTL_SECONDS = 600
OIDC_JWKS_TTL_SECONDS = 600
OIDC_ALLOWED_SIGNING_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")
OIDC_CLOCK_SKEW_SECONDS = 60

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)

ALGORITHM = "HS256"
REFRESH_TOKEN_BYTES = 64
REFRESH_TOKEN_ROTATED_REASON = "rotated"
REFRESH_TOKEN_REVOKED_REASON = "revoked"
REFRESH_TOKEN_EXPIRED_REASON = "expired"
REFRESH_TOKEN_REPLAY_REASON = "replayed"


def _is_service_actor(username: str | None) -> bool:
    u = (username or "").strip()
    if not u:
        return False
    return u in {
        settings.SCANNER_SERVICE_USERNAME,
        settings.INGESTION_SERVICE_USERNAME,
        settings.CORRELATOR_SERVICE_USERNAME,
    }


def _actor_type(username: str | None) -> str:
    return "service" if _is_service_actor(username) else "user"


def _verify_password(plain: str) -> bool:
    if settings.ADMIN_PASSWORD_HASH:
        try:
            return bcrypt.checkpw(
                plain.encode("utf-8"), settings.ADMIN_PASSWORD_HASH.encode("utf-8")
            )
        except Exception:
            return False
    return plain == settings.ADMIN_PASSWORD


def _reject_default_password_in_prod():
    """In prod, refuse default admin/admin so operators must set ADMIN_PASSWORD_HASH or a strong ADMIN_PASSWORD."""
    if settings.ENV.lower() != "prod":
        return
    if settings.ADMIN_PASSWORD_HASH:
        return
    if settings.ADMIN_PASSWORD != "admin":
        return
    raise HTTPException(
        status_code=503,
        detail="Production requires ADMIN_PASSWORD_HASH or a non-default ADMIN_PASSWORD. See env.example.",
    )


def create_access_token(sub: str, role: str = "admin") -> str:
    expire = datetime.now(UTC) + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": sub, "role": role, "exp": expire}
    raw = jwt.encode(to_encode, settings.API_SECRET_KEY, algorithm=ALGORITHM)
    return raw if isinstance(raw, str) else raw.decode("utf-8")


def _create_refresh_token_raw() -> str:
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)


def _hash_refresh_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _refresh_token_expiry() -> datetime:
    return datetime.now(UTC) + timedelta(minutes=settings.JWT_REFRESH_TOKEN_EXPIRE_MINUTES)


def _store_refresh_token(
    db: Session,
    *,
    raw_token: str,
    username: str,
    role: str,
    request: Request | None = None,
) -> str:
    token_hash = _hash_refresh_token(raw_token)
    client_ip = _client_id(request) if request else None
    user_agent = ((request.headers.get("user-agent") or "")[:512] if request else None) or None
    db.execute(
        text(
            """
            INSERT INTO auth_refresh_tokens(
              token_hash,
              username,
              role,
              expires_at,
              client_ip,
              user_agent
            )
            VALUES(
              :token_hash,
              :username,
              :role,
              :expires_at,
              :client_ip,
              :user_agent
            )
            """
        ),
        {
            "token_hash": token_hash,
            "username": username,
            "role": role,
            "expires_at": _refresh_token_expiry(),
            "client_ip": client_ip,
            "user_agent": user_agent,
        },
    )
    return token_hash


def _issue_token_pair(
    db: Session,
    *,
    username: str,
    role: str,
    request: Request | None = None,
) -> "Token":
    access_token = create_access_token(username, role=role)
    refresh_token = _create_refresh_token_raw()
    _store_refresh_token(
        db,
        raw_token=refresh_token,
        username=username,
        role=role,
        request=request,
    )
    return Token(access_token=access_token, refresh_token=refresh_token)


def _resolve_active_role(db: Session, username: str) -> str | None:
    row = (
        db.execute(
            text("SELECT role, disabled FROM users WHERE username = :u"),
            {"u": username},
        )
        .mappings()
        .first()
    )
    if row:
        if row.get("disabled"):
            return None
        return row.get("role") or "viewer"
    if username == settings.ADMIN_USERNAME:
        return "admin"
    return None


def _revoke_refresh_token_by_hash(
    db: Session,
    *,
    token_hash: str,
    reason: str,
    replaced_by_hash: str | None = None,
) -> None:
    db.execute(
        text(
            """
            UPDATE auth_refresh_tokens
            SET revoked_at = NOW(),
                revoked_reason = :reason,
                replaced_by_hash = COALESCE(:replaced_by_hash, replaced_by_hash)
            WHERE token_hash = :token_hash
              AND revoked_at IS NULL
            """
        ),
        {
            "token_hash": token_hash,
            "reason": reason,
            "replaced_by_hash": replaced_by_hash,
        },
    )


def _log_refresh_attempt(
    db: Session,
    *,
    success: bool,
    request_id: str,
    username: str | None = None,
    reason: str | None = None,
) -> None:
    details: dict[str, object] = {
        "success": success,
        "method": "refresh_token",
        "actor_type": _actor_type(username) if username else "unknown",
    }
    if reason:
        details["reason"] = reason
    log_audit(
        db,
        "token.refresh",
        user_name=username,
        details=details,
        request_id=request_id or None,
    )


def decode_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, settings.API_SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


def decode_token_payload(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.API_SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


def get_role_for_username(db: Session, username: str) -> str:
    """Return role from users table, or 'admin' if not found (config-based user)."""
    try:
        row = (
            db.execute(
                text("SELECT role FROM users WHERE username = :u AND disabled = FALSE"),
                {"u": username},
            )
            .mappings()
            .first()
        )
        return (row["role"] or "admin") if row else "admin"
    except Exception:
        return "admin"


class Token(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"


class RefreshTokenBody(BaseModel):
    refresh_token: str


VALID_USER_ROLES = {"viewer", "analyst", "admin"}


def _normalize_username(username: str) -> str:
    value = (username or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="username required")
    return value


def _normalize_role(role: str | None, *, default: str = "viewer") -> str:
    value = (role or default).strip().lower()
    if value not in VALID_USER_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role. Use one of: {sorted(VALID_USER_ROLES)}",
        )
    return value


def _password_hash_or_none(password: str | None) -> str | None:
    if password is None:
        return None
    raw = password.strip()
    if len(raw) < 8:
        raise HTTPException(status_code=400, detail="password must be at least 8 characters")
    return bcrypt.hashpw(raw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _client_id(request: Request) -> str:
    return (
        request.client.host
        if request.client
        else request.headers.get("x-forwarded-for", "unknown").split(",")[0].strip()
    )


def _verify_user_password(db: Session, username: str, password: str) -> str | None:
    """If username exists in users with a password_hash, verify password and return role. Else return None."""
    row = (
        db.execute(
            text("SELECT role, password_hash FROM users WHERE username = :u AND disabled = FALSE"),
            {"u": username},
        )
        .mappings()
        .first()
    )
    if not row or not row.get("password_hash"):
        return None
    try:
        if not bcrypt.checkpw(
            password.encode("utf-8"), (row["password_hash"] or "").encode("utf-8")
        ):
            return None
    except Exception:
        return None
    return row["role"] or "viewer"


@router.post("/login", response_model=Token)
async def login(
    request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    req_id = request_id_ctx.get("")
    username_for_key = (form.username or "").strip().lower() or "unknown"
    key = f"login:{_client_id(request)}:{username_for_key}"
    _reject_default_password_in_prod()

    # 1) Try users table (username + password_hash)
    role = _verify_user_password(db, form.username, form.password)
    if role is not None:
        audit.info("action=login user=%s success=true request_id=%s", form.username, req_id)
        log_audit(
            db,
            "login",
            user_name=form.username,
            details={
                "success": True,
                "method": "password",
                "actor_type": _actor_type(form.username),
            },
            request_id=req_id or None,
        )
        token_pair = _issue_token_pair(db, username=form.username, role=role, request=request)
        db.commit()
        return token_pair

    # 2) Fall back to config admin
    if form.username == settings.ADMIN_USERNAME and _verify_password(form.password):
        audit.info("action=login user=%s success=true request_id=%s", form.username, req_id)
        log_audit(
            db,
            "login",
            user_name=form.username,
            details={
                "success": True,
                "method": "password",
                "actor_type": _actor_type(form.username),
            },
            request_id=req_id or None,
        )
        role = get_role_for_username(db, form.username)
        token_pair = _issue_token_pair(db, username=form.username, role=role, request=request)
        db.commit()
        return token_pair

    if not await check_rate_limit(key, settings.RATE_LIMIT_LOGIN_PER_MINUTE, 60.0):
        audit.info(
            "action=login user=%s success=false reason=rate_limited request_id=%s",
            form.username,
            req_id,
        )
        log_audit(
            db,
            "login",
            user_name=form.username,
            details={
                "success": False,
                "reason": "rate_limited",
                "actor_type": _actor_type(form.username),
            },
            request_id=req_id or None,
        )
        db.commit()
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")

    audit.info(
        "action=login user=%s success=false reason=invalid request_id=%s", form.username, req_id
    )
    log_audit(
        db,
        "login",
        user_name=form.username,
        details={"success": False, "reason": "invalid", "actor_type": _actor_type(form.username)},
        request_id=req_id or None,
    )
    db.commit()
    raise HTTPException(status_code=401, detail="Invalid username or password")


@router.post("/refresh", response_model=Token)
def refresh_token(
    body: RefreshTokenBody,
    request: Request,
    db: Session = Depends(get_db),
):
    req_id = request_id_ctx.get("")
    raw_token = (body.refresh_token or "").strip()
    if not raw_token:
        raise HTTPException(status_code=400, detail="refresh_token required")

    token_hash = _hash_refresh_token(raw_token)
    row = (
        db.execute(
            text(
                """
                SELECT token_hash, username, role, expires_at, revoked_at, revoked_reason
                FROM auth_refresh_tokens
                WHERE token_hash = :token_hash
                FOR UPDATE
                """
            ),
            {"token_hash": token_hash},
        )
        .mappings()
        .first()
    )
    if not row:
        _log_refresh_attempt(db, success=False, request_id=req_id, reason="not_found")
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    username = str(row.get("username") or "")
    if row.get("revoked_at") is not None:
        _log_refresh_attempt(
            db,
            success=False,
            request_id=req_id,
            username=username,
            reason=REFRESH_TOKEN_REPLAY_REASON,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    expires_at = row.get("expires_at")
    if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if not isinstance(expires_at, datetime) or expires_at <= datetime.now(UTC):
        _revoke_refresh_token_by_hash(
            db,
            token_hash=token_hash,
            reason=REFRESH_TOKEN_EXPIRED_REASON,
        )
        _log_refresh_attempt(
            db,
            success=False,
            request_id=req_id,
            username=username,
            reason=REFRESH_TOKEN_EXPIRED_REASON,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Refresh token expired")

    role = _resolve_active_role(db, username)
    if not role:
        _revoke_refresh_token_by_hash(
            db,
            token_hash=token_hash,
            reason=REFRESH_TOKEN_REVOKED_REASON,
        )
        _log_refresh_attempt(
            db,
            success=False,
            request_id=req_id,
            username=username,
            reason="user_inactive",
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    new_refresh_token = _create_refresh_token_raw()
    new_token_hash = _store_refresh_token(
        db,
        raw_token=new_refresh_token,
        username=username,
        role=role,
        request=request,
    )
    _revoke_refresh_token_by_hash(
        db,
        token_hash=token_hash,
        reason=REFRESH_TOKEN_ROTATED_REASON,
        replaced_by_hash=new_token_hash,
    )
    access_token = create_access_token(username, role=role)
    _log_refresh_attempt(db, success=True, request_id=req_id, username=username)
    db.commit()
    return Token(access_token=access_token, refresh_token=new_refresh_token)


def get_current_user_opt(
    creds: HTTPAuthorizationCredentials | None = Depends(security),
) -> str | None:
    if not creds:
        return None
    user = decode_token(creds.credentials)
    return user


def _decode_auth_payload(creds: HTTPAuthorizationCredentials | None) -> dict:
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token_payload(creds.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload


def require_auth(creds: HTTPAuthorizationCredentials | None = Depends(security)) -> str:
    payload = _decode_auth_payload(creds)
    return payload.get("sub") or ""


def get_current_role(creds: HTTPAuthorizationCredentials | None = Depends(security)) -> str:
    payload = _decode_auth_payload(creds)
    return (payload.get("role") or "admin").lower()


def require_role(allowed_roles: list[str]):
    """Dependency: require auth and that the user's role is in allowed_roles (from JWT)."""

    def _(creds: HTTPAuthorizationCredentials | None = Depends(security)) -> str:
        payload = _decode_auth_payload(creds)
        user = payload.get("sub")
        role = (
            payload.get("role") or "admin"
        ).lower()  # missing role = legacy token, treat as admin
        if role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return _


@router.get("/me")
def get_me(creds: HTTPAuthorizationCredentials | None = Depends(security)) -> dict:
    """Return current user and role from JWT. Used by frontend to hide UI by role."""
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token_payload(creds.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {
        "username": payload.get("sub"),
        "role": (payload.get("role") or "admin").lower(),
    }


@router.get("/users")
def list_users(db: Session = Depends(get_db), _user: str = Depends(require_role(["admin"]))):
    """List users with access (from users table). Admin only."""
    try:
        rows = (
            db.execute(
                text(
                    """
                    SELECT
                      username,
                      role,
                      disabled,
                      created_at,
                      (password_hash IS NOT NULL) AS password_configured
                    FROM users
                    ORDER BY username
                    """
                )
            )
            .mappings()
            .all()
        )
        items = [
            {
                "username": r["username"],
                "role": r["role"],
                "source": "db",
                "disabled": r["disabled"],
                "password_configured": bool(r.get("password_configured")),
            }
            for r in rows
        ]
    except Exception:
        items = [
            {
                "username": settings.ADMIN_USERNAME,
                "role": "admin",
                "source": "config",
                "password_configured": bool(settings.ADMIN_PASSWORD_HASH),
            }
        ]
    return {"items": items}


class CreateUserBody(BaseModel):
    username: str
    role: str = "viewer"
    password: str | None = None
    disabled: bool = False


class UpdateUserBody(BaseModel):
    role: str | None = None
    disabled: bool | None = None


class ResetPasswordBody(BaseModel):
    password: str


@router.post("/users")
def create_user(
    body: CreateUserBody,
    db: Session = Depends(get_db),
    admin_user: str = Depends(require_role(["admin"])),
):
    username = _normalize_username(body.username)
    role = _normalize_role(body.role)
    password_hash = _password_hash_or_none(body.password)
    if username == settings.ADMIN_USERNAME and role != "admin":
        raise HTTPException(status_code=400, detail="cannot downgrade configured admin role")

    row = (
        db.execute(
            text(
                """
                INSERT INTO users(username, role, password_hash, disabled)
                VALUES (:username, :role, :password_hash, :disabled)
                ON CONFLICT (username) DO NOTHING
                RETURNING username, role, disabled, created_at, (password_hash IS NOT NULL) AS password_configured
                """
            ),
            {
                "username": username,
                "role": role,
                "password_hash": password_hash,
                "disabled": bool(body.disabled),
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=409, detail="user already exists")
    log_audit(
        db,
        "user.create",
        user_name=admin_user,
        details={"username": username, "role": role, "disabled": bool(body.disabled)},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    out = dict(row)
    if hasattr(out.get("created_at"), "isoformat"):
        out["created_at"] = out["created_at"].isoformat()
    return out


@router.patch("/users/{username}")
def update_user(
    username: str,
    body: UpdateUserBody,
    db: Session = Depends(get_db),
    admin_user: str = Depends(require_role(["admin"])),
):
    normalized_username = _normalize_username(username)
    updates: dict[str, object] = {}
    if body.role is not None:
        updates["role"] = _normalize_role(body.role)
    if body.disabled is not None:
        updates["disabled"] = bool(body.disabled)
    if not updates:
        raise HTTPException(status_code=400, detail="no user fields provided")
    if normalized_username == settings.ADMIN_USERNAME and (
        updates.get("role") not in {None, "admin"} or updates.get("disabled") is True
    ):
        raise HTTPException(status_code=400, detail="cannot disable or downgrade configured admin")

    row = (
        db.execute(
            text(
                """
                UPDATE users
                SET
                  role = COALESCE(:role, role),
                  disabled = COALESCE(:disabled, disabled)
                WHERE username = :username
                RETURNING username, role, disabled, created_at, (password_hash IS NOT NULL) AS password_configured
                """
            ),
            {
                "username": normalized_username,
                "role": updates.get("role"),
                "disabled": updates.get("disabled"),
            },
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    log_audit(
        db,
        "user.update",
        user_name=admin_user,
        details={"username": normalized_username, "updates": updates},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    out = dict(row)
    if hasattr(out.get("created_at"), "isoformat"):
        out["created_at"] = out["created_at"].isoformat()
    return out


@router.post("/users/{username}/disable")
def disable_user(
    username: str,
    db: Session = Depends(get_db),
    admin_user: str = Depends(require_role(["admin"])),
):
    normalized_username = _normalize_username(username)
    if normalized_username == settings.ADMIN_USERNAME:
        raise HTTPException(status_code=400, detail="cannot disable configured admin")
    row = (
        db.execute(
            text(
                """
                UPDATE users
                SET disabled = TRUE
                WHERE username = :username
                RETURNING username, role, disabled, created_at, (password_hash IS NOT NULL) AS password_configured
                """
            ),
            {"username": normalized_username},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    log_audit(
        db,
        "user.disable",
        user_name=admin_user,
        details={"username": normalized_username},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    out = dict(row)
    if hasattr(out.get("created_at"), "isoformat"):
        out["created_at"] = out["created_at"].isoformat()
    return out


@router.post("/users/{username}/enable")
def enable_user(
    username: str,
    db: Session = Depends(get_db),
    admin_user: str = Depends(require_role(["admin"])),
):
    normalized_username = _normalize_username(username)
    row = (
        db.execute(
            text(
                """
                UPDATE users
                SET disabled = FALSE
                WHERE username = :username
                RETURNING username, role, disabled, created_at, (password_hash IS NOT NULL) AS password_configured
                """
            ),
            {"username": normalized_username},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    log_audit(
        db,
        "user.enable",
        user_name=admin_user,
        details={"username": normalized_username},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    out = dict(row)
    if hasattr(out.get("created_at"), "isoformat"):
        out["created_at"] = out["created_at"].isoformat()
    return out


@router.post("/users/{username}/reset-password")
def reset_user_password(
    username: str,
    body: ResetPasswordBody,
    db: Session = Depends(get_db),
    admin_user: str = Depends(require_role(["admin"])),
):
    normalized_username = _normalize_username(username)
    password_hash = _password_hash_or_none(body.password)
    row = (
        db.execute(
            text(
                """
                UPDATE users
                SET password_hash = :password_hash, disabled = FALSE
                WHERE username = :username
                RETURNING username, role, disabled, created_at, (password_hash IS NOT NULL) AS password_configured
                """
            ),
            {"username": normalized_username, "password_hash": password_hash},
        )
        .mappings()
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    log_audit(
        db,
        "user.reset_password",
        user_name=admin_user,
        details={"username": normalized_username},
        request_id=request_id_ctx.get(None),
    )
    db.commit()
    out = dict(row)
    if hasattr(out.get("created_at"), "isoformat"):
        out["created_at"] = out["created_at"].isoformat()
    return out


# ---------- OIDC SSO (Phase B.1) ----------


def _oidc_enabled() -> bool:
    return bool(
        settings.OIDC_ISSUER_URL
        and settings.OIDC_CLIENT_ID
        and settings.OIDC_CLIENT_SECRET
        and settings.OIDC_REDIRECT_URI
    )


def _normalize_issuer(value: str | None) -> str:
    return (value or "").rstrip("/")


def _is_local_host(hostname: str) -> bool:
    return hostname in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}


def _is_secure_oidc_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme == "https" or (
        parsed.scheme == "http" and _is_local_host((parsed.hostname or "").lower())
    )


def _validate_oidc_discovery(config: dict) -> dict:
    if not isinstance(config, dict):
        raise HTTPException(status_code=503, detail="oidc_discovery_invalid_document")

    expected_issuer = _normalize_issuer(settings.OIDC_ISSUER_URL)
    discovered_issuer = _normalize_issuer(str(config.get("issuer") or ""))
    if not discovered_issuer:
        raise HTTPException(status_code=503, detail="oidc_discovery_missing_issuer")
    if expected_issuer and discovered_issuer != expected_issuer:
        raise HTTPException(status_code=503, detail="oidc_discovery_issuer_mismatch")

    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = config.get(field)
        if not isinstance(value, str) or not value.strip():
            raise HTTPException(status_code=503, detail=f"oidc_discovery_missing_{field}")
        if not _is_secure_oidc_url(value):
            raise HTTPException(status_code=503, detail=f"oidc_discovery_insecure_{field}")
    return config


def _get_oidc_config(*, force_refresh: bool = False) -> dict:
    """Fetch and cache OpenID discovery document with validation."""
    global _oidc_config, _oidc_config_fetched_at
    now = time.time()
    if (
        not force_refresh
        and _oidc_config is not None
        and now - _oidc_config_fetched_at < OIDC_CONFIG_TTL_SECONDS
    ):
        return _oidc_config
    issuer = _normalize_issuer(settings.OIDC_ISSUER_URL)
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        with httpx.Client(timeout=10.0) as client:
            r = client.get(url)
            r.raise_for_status()
            config = _validate_oidc_discovery(r.json())
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"oidc_discovery_fetch_failed: {e}")
    _oidc_config = config
    _oidc_config_fetched_at = now
    return _oidc_config


def _get_oidc_jwks(jwks_uri: str, *, force_refresh: bool = False) -> dict:
    """Fetch and cache OIDC JWKS for signature validation."""
    global _oidc_jwks, _oidc_jwks_fetched_at, _oidc_jwks_uri
    now = time.time()
    if (
        not force_refresh
        and _oidc_jwks is not None
        and _oidc_jwks_uri == jwks_uri
        and now - _oidc_jwks_fetched_at < OIDC_JWKS_TTL_SECONDS
    ):
        return _oidc_jwks
    try:
        with httpx.Client(timeout=10.0) as client:
            r = client.get(jwks_uri)
            r.raise_for_status()
            parsed = r.json()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"oidc_jwks_fetch_failed: {e}")
    keys = parsed.get("keys") if isinstance(parsed, dict) else None
    if not isinstance(keys, list) or not keys:
        raise HTTPException(status_code=503, detail="oidc_jwks_missing_keys")
    _oidc_jwks = parsed
    _oidc_jwks_fetched_at = now
    _oidc_jwks_uri = jwks_uri
    return _oidc_jwks


def _select_jwk_for_token(id_token: str, jwks: dict) -> dict:
    """Pick the matching JWK by kid from token header."""
    try:
        header = jwt.get_unverified_header(id_token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"invalid_id_token_header: {e}")
    kid = header.get("kid")
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list) or not keys:
        raise HTTPException(status_code=401, detail="jwks_missing_keys")
    if kid:
        for k in keys:
            if isinstance(k, dict) and k.get("kid") == kid:
                return k
        raise HTTPException(status_code=401, detail="jwks_kid_not_found")
    # If no kid in header and JWKS has one key, use it.
    if len(keys) == 1 and isinstance(keys[0], dict):
        return keys[0]
    raise HTTPException(status_code=401, detail="jwks_ambiguous_key")


def _verify_oidc_id_token(id_token: str, oidc_config: dict, expected_nonce: str) -> dict:
    """Verify OIDC id_token signature and critical claims (iss, aud, nonce)."""
    issuer = _normalize_issuer(settings.OIDC_ISSUER_URL)
    jwks_uri = oidc_config.get("jwks_uri")
    if not jwks_uri:
        raise HTTPException(status_code=503, detail="oidc_discovery_missing_jwks_uri")
    try:
        token_header = jwt.get_unverified_header(id_token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"invalid_id_token_header: {e}")
    token_alg = str(token_header.get("alg") or "").strip()
    if token_alg not in OIDC_ALLOWED_SIGNING_ALGORITHMS:
        raise HTTPException(status_code=401, detail="invalid_id_token_alg")
    advertised_algs = oidc_config.get("id_token_signing_alg_values_supported")
    if isinstance(advertised_algs, list) and advertised_algs and token_alg not in advertised_algs:
        raise HTTPException(status_code=401, detail="invalid_id_token_alg_not_advertised")

    jwks = _get_oidc_jwks(jwks_uri)
    try:
        jwk = _select_jwk_for_token(id_token, jwks)
    except HTTPException as e:
        if e.detail == "jwks_kid_not_found":
            jwks = _get_oidc_jwks(jwks_uri, force_refresh=True)
            jwk = _select_jwk_for_token(id_token, jwks)
        else:
            raise
    try:
        claims = jwt.decode(
            id_token,
            jwk,
            algorithms=[token_alg],
            audience=settings.OIDC_CLIENT_ID,
            issuer=issuer,
            options={
                "verify_aud": True,
                "verify_iss": True,
                "verify_exp": True,
                "verify_nbf": True,
            },
            leeway=OIDC_CLOCK_SKEW_SECONDS,
        )
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"invalid_id_token: {e}")

    token_sub = claims.get("sub")
    if not isinstance(token_sub, str) or not token_sub.strip():
        raise HTTPException(status_code=401, detail="invalid_id_token_sub")

    token_nonce = claims.get("nonce")
    if expected_nonce and token_nonce != expected_nonce:
        raise HTTPException(status_code=401, detail="invalid_id_token_nonce")
    audience_claim = claims.get("aud")
    token_azp = claims.get("azp")
    client_id = settings.OIDC_CLIENT_ID
    if isinstance(audience_claim, list) and len(audience_claim) > 1 and token_azp != client_id:
        raise HTTPException(status_code=401, detail="invalid_id_token_azp")
    if token_azp and token_azp != client_id:
        raise HTTPException(status_code=401, detail="invalid_id_token_azp")
    return claims


def _sign_state(nonce: str) -> str:
    """Return a signed state value (expiry 10 min + nonce binding)."""
    payload_obj = {
        "exp": int(time.time()) + 600,
        "nonce": nonce,
        "rnd": secrets.token_urlsafe(16),
    }
    payload = json.dumps(payload_obj, separators=(",", ":"))
    sig = hmac.new(
        settings.API_SECRET_KEY.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    raw = f"{payload}.{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def _verify_state(state: str) -> dict | None:
    try:
        pad = 4 - len(state) % 4
        if pad != 4:
            state += "=" * pad
        raw = base64.urlsafe_b64decode(state.encode()).decode()
        payload, sig = raw.rsplit(".", 1)
        expected = hmac.new(
            settings.API_SECRET_KEY.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        parsed = json.loads(payload)
        exp = int(parsed.get("exp", 0))
        if exp < int(time.time()):
            return None
        nonce = parsed.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            return None
        return parsed
    except Exception:
        return None


@router.get("/config")
def auth_config():
    """Public: whether OIDC is enabled (frontend uses this to show SSO button)."""
    return {"oidc_enabled": _oidc_enabled()}


@router.get("/oidc/login")
async def oidc_login(request: Request):
    """Redirect to IdP authorization endpoint."""
    if not _oidc_enabled():
        raise HTTPException(status_code=404, detail="OIDC not configured")
    config = _get_oidc_config()
    nonce = secrets.token_urlsafe(16)
    state = _sign_state(nonce)
    params = {
        "response_type": "code",
        "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": settings.OIDC_REDIRECT_URI,
        "scope": settings.OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
    }
    auth_url = config["authorization_endpoint"] + "?" + urlencode(params)
    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    """Exchange code for tokens, resolve user, issue JWT, redirect to frontend with token."""
    req_id = request_id_ctx.get("")
    frontend_base = (settings.FRONTEND_URL or "http://localhost:3000").rstrip("/")
    login_fragment = f"{frontend_base}/login#"

    if error:
        audit.info("action=oidc_callback error=%s request_id=%s", error, req_id)
        return RedirectResponse(url=login_fragment + urlencode({"error": error}), status_code=302)
    state_data = _verify_state(state) if state else None
    if not code or not state_data:
        audit.info("action=oidc_callback error=invalid_state_or_code request_id=%s", req_id)
        return RedirectResponse(
            url=login_fragment + urlencode({"error": "invalid_callback"}), status_code=302
        )

    try:
        config = _get_oidc_config()
    except HTTPException as e:
        audit.info(
            "action=oidc_callback discovery_failed detail=%s request_id=%s",
            e.detail,
            req_id,
        )
        return RedirectResponse(
            url=login_fragment + urlencode({"error": "oidc_discovery_failed"}), status_code=302
        )

    token_url = config.get("token_endpoint")
    if not isinstance(token_url, str) or not token_url:
        audit.info("action=oidc_callback token_endpoint_missing request_id=%s", req_id)
        return RedirectResponse(
            url=login_fragment + urlencode({"error": "oidc_discovery_failed"}), status_code=302
        )
    try:
        with httpx.Client(timeout=10.0) as client:
            token_res = client.post(
                token_url,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": settings.OIDC_REDIRECT_URI,
                    "client_id": settings.OIDC_CLIENT_ID,
                    "client_secret": settings.OIDC_CLIENT_SECRET,
                },
                headers={"Accept": "application/json"},
            )
    except Exception as e:
        audit.info("action=oidc_callback token_exchange_error=%s request_id=%s", e, req_id)
        return RedirectResponse(
            url=login_fragment + urlencode({"error": "token_exchange_failed"}), status_code=302
        )
    if token_res.status_code != 200:
        audit.info(
            "action=oidc_callback token_exchange_failed status=%s request_id=%s",
            token_res.status_code,
            req_id,
        )
        return RedirectResponse(
            url=login_fragment + urlencode({"error": "token_exchange_failed"}), status_code=302
        )

    try:
        token_data = token_res.json()
    except Exception:
        return RedirectResponse(
            url=login_fragment + urlencode({"error": "token_exchange_failed"}), status_code=302
        )
    id_token = token_data.get("id_token")
    if not id_token:
        return RedirectResponse(
            url=login_fragment + urlencode({"error": "no_id_token"}), status_code=302
        )

    try:
        claims = _verify_oidc_id_token(id_token, config, expected_nonce=state_data["nonce"])
    except HTTPException as e:
        audit.info(
            "action=oidc_callback id_token_invalid detail=%s request_id=%s", e.detail, req_id
        )
        return RedirectResponse(
            url=login_fragment + urlencode({"error": "invalid_id_token"}), status_code=302
        )

    username = claims.get("preferred_username") or claims.get("email") or claims.get("sub")
    if not username:
        username = str(claims.get("sub", ""))
    if isinstance(username, str) and "@" in username:
        username = username.split("@")[0]
    if not username:
        return RedirectResponse(
            url=login_fragment + urlencode({"error": "no_username"}), status_code=302
        )

    row = (
        db.execute(
            text("SELECT role FROM users WHERE username = :u AND disabled = FALSE"),
            {"u": username},
        )
        .mappings()
        .first()
    )
    if not row:
        audit.info(
            "action=oidc_callback user_not_found username=%s request_id=%s", username, req_id
        )
        log_audit(
            db,
            "login",
            user_name=username,
            details={
                "success": False,
                "reason": "oidc_user_not_in_db",
                "method": "oidc",
                "actor_type": _actor_type(username),
            },
            request_id=req_id or None,
        )
        db.commit()
        return RedirectResponse(
            url=login_fragment + urlencode({"error": "user_not_found"}), status_code=302
        )

    role = row["role"] or "viewer"
    audit.info("action=login user=%s success=true method=oidc request_id=%s", username, req_id)
    log_audit(
        db,
        "login",
        user_name=username,
        details={"success": True, "method": "oidc", "actor_type": _actor_type(username)},
        request_id=req_id or None,
    )
    token_pair = _issue_token_pair(db, username=username, role=role, request=request)
    db.commit()
    fragment = urlencode(
        {
            "access_token": token_pair.access_token,
            "refresh_token": token_pair.refresh_token or "",
        }
    )
    return RedirectResponse(
        url=login_fragment + fragment,
        status_code=302,
    )
