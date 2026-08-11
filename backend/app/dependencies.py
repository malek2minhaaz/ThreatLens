"""FastAPI dependencies (auth + database)."""
from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .database import get_db
from .models import AuthToken, User, utcnow

_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """
    Resolve the ``Authorization: Bearer <token>`` header to a User.

    Raises 401 when the header is missing, the token is unknown, or it has
    expired.
    """
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized

    token = db.query(AuthToken).filter(AuthToken.token == credentials.credentials).first()
    if token is None or token.expires_at < utcnow():
        raise unauthorized

    user = db.get(User, token.user_id)
    if user is None:
        raise unauthorized
    return user


def get_current_admin(user: User = Depends(get_current_user)) -> User:
    """Require the authenticated user to be an admin (403 otherwise)."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required.",
        )
    return user
