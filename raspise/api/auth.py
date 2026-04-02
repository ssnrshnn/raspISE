"""JWT-based authentication for the REST API and Admin UI."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import bcrypt
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from raspise.config import get_config
from raspise.db import get_db
from raspise.db.models import AdminUser

_ALGORITHM = "HS256"
_bearer    = HTTPBearer(auto_error=True)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_access_token(subject: str, expire_minutes: int | None = None) -> str:
    cfg = get_config()
    minutes = expire_minutes or cfg.api.token_expire_minutes
    expire  = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    payload = {"sub": subject, "exp": expire, "iat": datetime.now(timezone.utc)}
    return jwt.encode(payload, cfg.server.secret_key, algorithm=_ALGORITHM)


async def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> AdminUser:
    cfg = get_config()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload  = jwt.decode(credentials.credentials, cfg.server.secret_key, algorithms=[_ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    stmt = select(AdminUser).where(AdminUser.username == username, AdminUser.enabled == True)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if user is None:
        raise credentials_exception
    return user
