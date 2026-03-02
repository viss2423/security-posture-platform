"""Simple JWT auth: one admin user from env. Writes audit events to DB. Phase B.1: RBAC + OIDC SSO."""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timedelta
from urllib.parse import quote, urlencode, urlparse

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
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": sub, "role": role, "exp": expire}
    raw = jwt.encode(to_encode, settings.API_SECRET_KEY, algorithm=ALGORITHM)
    return raw if isinstance(raw, str) else raw.decode("utf-8")


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
    token_type: str = "bearer"


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
    key = f"login:{_client_id(request)}"
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
        db.commit()
        return Token(access_token=create_access_token(form.username, role=role))

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
        db.commit()
        return Token(access_token=create_access_token(form.username, role=role))

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
                text("SELECT username, role, disabled, created_at FROM users ORDER BY username")
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
            }
            for r in rows
        ]
    except Exception:
        items = [{"username": settings.ADMIN_USERNAME, "role": "admin", "source": "config"}]
    return {"items": items}


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
    db.commit()

    access_token = create_access_token(username, role=role)
    return RedirectResponse(
        url=login_fragment + "access_token=" + quote(access_token, safe=""), status_code=302
    )
