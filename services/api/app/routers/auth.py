"""Simple JWT auth: one admin user from env. Writes audit events to DB. Phase B.1: RBAC + OIDC SSO."""
import base64
import hashlib
import hmac
import logging
import secrets
import time
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote

import bcrypt
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.settings import settings
from app.db import get_db
from app.rate_limit import check_rate_limit
from app.request_context import request_id_ctx
from app.audit import log_audit

audit = logging.getLogger("secplat.audit")

# OIDC discovery cache (authorization_endpoint, token_endpoint, jwks_uri)
_oidc_config: dict | None = None

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)

ALGORITHM = "HS256"


def _verify_password(plain: str) -> bool:
    if settings.ADMIN_PASSWORD_HASH:
        try:
            return bcrypt.checkpw(plain.encode("utf-8"), settings.ADMIN_PASSWORD_HASH.encode("utf-8"))
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
        row = db.execute(text("SELECT role FROM users WHERE username = :u AND disabled = FALSE"), {"u": username}).mappings().first()
        return (row["role"] or "admin") if row else "admin"
    except Exception:
        return "admin"


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


def _client_id(request: Request) -> str:
    return request.client.host if request.client else request.headers.get("x-forwarded-for", "unknown").split(",")[0].strip()


def _verify_user_password(db: Session, username: str, password: str) -> str | None:
    """If username exists in users with a password_hash, verify password and return role. Else return None."""
    row = db.execute(
        text("SELECT role, password_hash FROM users WHERE username = :u AND disabled = FALSE"),
        {"u": username},
    ).mappings().first()
    if not row or not row.get("password_hash"):
        return None
    try:
        if not bcrypt.checkpw(password.encode("utf-8"), (row["password_hash"] or "").encode("utf-8")):
            return None
    except Exception:
        return None
    return row["role"] or "viewer"


@router.post("/login", response_model=Token)
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    req_id = request_id_ctx.get("")
    key = f"login:{_client_id(request)}"
    if not await check_rate_limit(key, settings.RATE_LIMIT_LOGIN_PER_MINUTE, 60.0):
        audit.info("action=login user=%s success=false reason=rate_limited request_id=%s", form.username, req_id)
        log_audit(db, "login", user_name=form.username, details={"success": False, "reason": "rate_limited"}, request_id=req_id or None)
        db.commit()
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    _reject_default_password_in_prod()

    # 1) Try users table (username + password_hash)
    role = _verify_user_password(db, form.username, form.password)
    if role is not None:
        audit.info("action=login user=%s success=true request_id=%s", form.username, req_id)
        log_audit(db, "login", user_name=form.username, details={"success": True}, request_id=req_id or None)
        db.commit()
        return Token(access_token=create_access_token(form.username, role=role))

    # 2) Fall back to config admin
    if form.username == settings.ADMIN_USERNAME and _verify_password(form.password):
        audit.info("action=login user=%s success=true request_id=%s", form.username, req_id)
        log_audit(db, "login", user_name=form.username, details={"success": True}, request_id=req_id or None)
        role = get_role_for_username(db, form.username)
        db.commit()
        return Token(access_token=create_access_token(form.username, role=role))

    audit.info("action=login user=%s success=false reason=invalid request_id=%s", form.username, req_id)
    log_audit(db, "login", user_name=form.username, details={"success": False, "reason": "invalid"}, request_id=req_id or None)
    db.commit()
    raise HTTPException(status_code=401, detail="Invalid username or password")


def get_current_user_opt(creds: HTTPAuthorizationCredentials | None = Depends(security)) -> str | None:
    if not creds:
        return None
    user = decode_token(creds.credentials)
    return user


def require_auth(creds: HTTPAuthorizationCredentials | None = Depends(security)) -> str:
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = decode_token(creds.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user


def require_role(allowed_roles: list[str]):
    """Dependency: require auth and that the user's role is in allowed_roles (from JWT)."""
    def _(creds: HTTPAuthorizationCredentials | None = Depends(security)) -> str:
        if not creds:
            raise HTTPException(status_code=401, detail="Not authenticated")
        payload = decode_token_payload(creds.credentials)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        user = payload.get("sub")
        role = (payload.get("role") or "admin").lower()  # missing role = legacy token, treat as admin
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
        rows = db.execute(text("SELECT username, role, disabled, created_at FROM users ORDER BY username")).mappings().all()
        items = [
            {"username": r["username"], "role": r["role"], "source": "db", "disabled": r["disabled"]}
            for r in rows
        ]
    except Exception:
        items = [{"username": settings.ADMIN_USERNAME, "role": "admin", "source": "config"}]
    return {"items": items}


# ---------- OIDC SSO (Phase B.1) ----------

def _oidc_enabled() -> bool:
    return bool(settings.OIDC_ISSUER_URL and settings.OIDC_CLIENT_ID and settings.OIDC_CLIENT_SECRET and settings.OIDC_REDIRECT_URI)


def _get_oidc_config() -> dict:
    """Fetch and cache OpenID discovery document."""
    global _oidc_config
    if _oidc_config is not None:
        return _oidc_config
    issuer = (settings.OIDC_ISSUER_URL or "").rstrip("/")
    url = f"{issuer}/.well-known/openid-configuration"
    with httpx.Client(timeout=10.0) as client:
        r = client.get(url)
        r.raise_for_status()
        _oidc_config = r.json()
    return _oidc_config


def _sign_state() -> str:
    """Return a signed state value (expiry 10 min)."""
    payload = f"{int(time.time()) + 600}|{secrets.token_urlsafe(16)}"
    sig = hmac.new(
        settings.API_SECRET_KEY.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    raw = f"{payload}.{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def _verify_state(state: str) -> bool:
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
            return False
        ts_str, _ = payload.split("|", 1)
        return int(ts_str) >= int(time.time())
    except Exception:
        return False


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
    state = _sign_state()
    params = {
        "response_type": "code",
        "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": settings.OIDC_REDIRECT_URI,
        "scope": settings.OIDC_SCOPES,
        "state": state,
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
    if not code or not state or not _verify_state(state):
        audit.info("action=oidc_callback error=invalid_state_or_code request_id=%s", req_id)
        return RedirectResponse(url=login_fragment + urlencode({"error": "invalid_callback"}), status_code=302)

    config = _get_oidc_config()
    token_url = config["token_endpoint"]
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
    if token_res.status_code != 200:
        audit.info("action=oidc_callback token_exchange_failed status=%s request_id=%s", token_res.status_code, req_id)
        return RedirectResponse(url=login_fragment + urlencode({"error": "token_exchange_failed"}), status_code=302)

    token_data = token_res.json()
    id_token = token_data.get("id_token")
    if not id_token:
        return RedirectResponse(url=login_fragment + urlencode({"error": "no_id_token"}), status_code=302)

    # Decode id_token (no JWKS verify for MVP; we got it from our token exchange)
    try:
        claims = jwt.get_unverified_claims(id_token)
    except JWTError:
        return RedirectResponse(url=login_fragment + urlencode({"error": "invalid_id_token"}), status_code=302)

    username = claims.get("preferred_username") or claims.get("email") or claims.get("sub")
    if not username:
        username = str(claims.get("sub", ""))
    if isinstance(username, str) and "@" in username:
        username = username.split("@")[0]
    if not username:
        return RedirectResponse(url=login_fragment + urlencode({"error": "no_username"}), status_code=302)

    row = db.execute(
        text("SELECT role FROM users WHERE username = :u AND disabled = FALSE"),
        {"u": username},
    ).mappings().first()
    if not row:
        audit.info("action=oidc_callback user_not_found username=%s request_id=%s", username, req_id)
        log_audit(db, "login", user_name=username, details={"success": False, "reason": "oidc_user_not_in_db"}, request_id=req_id or None)
        db.commit()
        return RedirectResponse(url=login_fragment + urlencode({"error": "user_not_found"}), status_code=302)

    role = row["role"] or "viewer"
    audit.info("action=login user=%s success=true method=oidc request_id=%s", username, req_id)
    log_audit(db, "login", user_name=username, details={"success": True, "method": "oidc"}, request_id=req_id or None)
    db.commit()

    access_token = create_access_token(username, role=role)
    return RedirectResponse(url=login_fragment + "access_token=" + quote(access_token, safe=""), status_code=302)
