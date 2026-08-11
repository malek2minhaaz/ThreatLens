"""Authentication endpoints: register, login, logout, profile."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import get_current_user
from ..models import AuthToken, User, utcnow
from ..schemas import (
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    UpdateProfileRequest,
)
from ..services.rate_limit import login_limiter, register_limiter
from ..services.security import hash_password, new_bearer_token, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])

TOKEN_TTL_DAYS = 30


def _public_user(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "public_name": user.public_name,
        "is_admin": user.is_admin,
        "created_at": user.created_at.isoformat(),
    }


def _issue_token(db: Session, user: User) -> str:
    token = new_bearer_token()
    db.add(AuthToken(
        token=token,
        user_id=user.id,
        expires_at=utcnow() + timedelta(days=TOKEN_TTL_DAYS),
    ))
    db.commit()
    return token


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/register", summary="Create an account and get a token")
def register(
    payload: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    if not register_limiter.allow(_client_ip(request)):
        raise HTTPException(status_code=429, detail="Too many registration attempts. Try again later.")
    email = payload.email.lower()
    exists = db.query(User).filter(
        or_(User.username == payload.username, User.email == email)
    ).first()
    if exists:
        raise HTTPException(status_code=409, detail="Username or email is already registered.")

    user = User(
        username=payload.username,
        email=email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {"token": _issue_token(db, user), "user": _public_user(user)}


@router.post("/login", summary="Sign in and get a token")
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    if not login_limiter.allow(_client_ip(request)):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    identifier = payload.identifier.strip().lower()
    user = db.query(User).filter(
        or_(func.lower(User.username) == identifier, User.email == identifier)
    ).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    # Purge this user's expired tokens so auth_tokens doesn't grow unboundedly
    db.query(AuthToken).filter(
        AuthToken.user_id == user.id, AuthToken.expires_at < utcnow()
    ).delete(synchronize_session=False)
    db.commit()

    login_limiter.reset(_client_ip(request))
    return {"token": _issue_token(db, user), "user": _public_user(user)}


_bearer = HTTPBearer(auto_error=False)


@router.post("/logout", summary="Invalidate the current token")
def logout(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    if credentials is not None:
        db.query(AuthToken).filter(
            AuthToken.token == credentials.credentials, AuthToken.user_id == user.id
        ).delete()
        db.commit()
    return {"detail": "Logged out."}


@router.get("/me", summary="Fetch the current profile")
def me(user: User = Depends(get_current_user)) -> dict:
    return _public_user(user)


@router.put("/me", summary="Update display name and/or email")
def update_me(
    payload: UpdateProfileRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    if payload.email is not None:
        email = payload.email.lower()
        clash = db.query(User).filter(User.email == email, User.id != user.id).first()
        if clash:
            raise HTTPException(status_code=409, detail="Email is already in use.")
        user.email = email
    if payload.display_name is not None:
        user.display_name = payload.display_name.strip() or None
    db.commit()
    db.refresh(user)
    return _public_user(user)


@router.post("/change-password", summary="Change the account password")
def change_password(
    payload: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    user.password_hash = hash_password(payload.new_password)
    # Invalidate all existing sessions for safety
    db.query(AuthToken).filter(AuthToken.user_id == user.id).delete()
    db.commit()
    return {"detail": "Password updated. Please sign in again."}
