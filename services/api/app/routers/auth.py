"""Simple JWT auth: one admin user from env. Writes audit events to DB."""
import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.settings import settings
from app.db import get_db
from app.rate_limit import check_rate_limit
from app.request_context import request_id_ctx
from app.audit import log_audit

audit = logging.getLogger("secplat.audit")

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"


def _verify_password(plain: str) -> bool:
    if settings.ADMIN_PASSWORD_HASH:
        return pwd_context.verify(plain, settings.ADMIN_PASSWORD_HASH)
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


def create_access_token(sub: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": sub, "exp": expire}
    raw = jwt.encode(to_encode, settings.API_SECRET_KEY, algorithm=ALGORITHM)
    return raw if isinstance(raw, str) else raw.decode("utf-8")


def decode_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, settings.API_SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


def _client_id(request: Request) -> str:
    return request.client.host if request.client else request.headers.get("x-forwarded-for", "unknown").split(",")[0].strip()


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
    if form.username != settings.ADMIN_USERNAME or not _verify_password(form.password):
        audit.info("action=login user=%s success=false reason=invalid request_id=%s", form.username, req_id)
        log_audit(db, "login", user_name=form.username, details={"success": False, "reason": "invalid"}, request_id=req_id or None)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")
    audit.info("action=login user=%s success=true request_id=%s", form.username, req_id)
    log_audit(db, "login", user_name=form.username, details={"success": True}, request_id=req_id or None)
    db.commit()
    return Token(access_token=create_access_token(form.username))


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
