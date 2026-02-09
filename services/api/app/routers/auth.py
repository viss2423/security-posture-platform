"""Simple JWT auth: one admin user from env. No DB."""
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from app.settings import settings

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24h


def _verify_password(plain: str) -> bool:
    if settings.ADMIN_PASSWORD_HASH:
        return pwd_context.verify(plain, settings.ADMIN_PASSWORD_HASH)
    return plain == settings.ADMIN_PASSWORD


def create_access_token(sub: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
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


@router.post("/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends()):
    if form.username != settings.ADMIN_USERNAME or not _verify_password(form.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
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
