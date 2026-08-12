"""Pydantic request/response schemas."""
from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, EmailStr, Field

CONTENT_TYPES = ("email", "sms", "page_text")


# ---------------------------------------------------------------------------
# Scanner / phishing
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Payload for POST /api/scan-url."""

    url: str = Field(
        ...,
        min_length=4,
        max_length=2048,
        description="The URL to scan. A scheme is added automatically if missing.",
    )


class BulkScanRequest(BaseModel):
    """Payload for POST /api/scan-bulk (up to 25 URLs, deduplicated)."""

    urls: list[Annotated[str, Field(min_length=4, max_length=2048)]] = Field(
        ...,
        min_length=1,
        max_length=25,
        description="Up to 25 URLs to scan in parallel. Blank lines and duplicates are removed.",
    )


class PhishingRequest(BaseModel):
    """Payload for POST /api/analyze-phishing."""

    content: str = Field(
        ...,
        min_length=3,
        max_length=50000,
        description="Email body, SMS text, or page text to analyze.",
    )
    content_type: str = Field(
        default="email",
        description="One of: email | sms | page_text",
        pattern="^(email|sms|page_text)$",
    )


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    """Payload for POST /api/auth/register."""

    username: str = Field(..., min_length=3, max_length=24, pattern=r"^[a-zA-Z0-9_]+$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    """Payload for POST /api/auth/login. `identifier` is username OR email."""

    identifier: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class UpdateProfileRequest(BaseModel):
    """Payload for PUT /api/auth/me."""

    display_name: str | None = Field(None, min_length=1, max_length=50)
    email: EmailStr | None = None


class ChangePasswordRequest(BaseModel):
    """Payload for POST /api/auth/change-password."""

    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)


# ---------------------------------------------------------------------------
# Phishing tools
# ---------------------------------------------------------------------------

class InspectRequest(BaseModel):
    """Payload for POST /api/phishing/inspect (link inspector)."""

    content: str = Field(..., min_length=3, max_length=50000)


class HeadersRequest(BaseModel):
    """Payload for POST /api/phishing/headers (email header analyzer)."""

    content: str = Field(..., min_length=3, max_length=20000)


class SenderCheckRequest(BaseModel):
    """Payload for POST /api/phishing/sender-check."""

    sender: str = Field(..., min_length=3, max_length=254)


class WatchlistAddRequest(BaseModel):
    """Payload for POST /api/watchlist."""

    kind: str = Field(..., pattern="^(sender|domain|url)$")
    value: str = Field(..., min_length=2, max_length=2048)
    note: str | None = Field(None, max_length=200)


class WatchlistCheckRequest(BaseModel):
    """Payload for POST /api/watchlist/check."""

    content: str = Field(..., min_length=3, max_length=50000)


class AdminUserUpdate(BaseModel):
    """Payload for PATCH /api/admin/users/{id}."""

    is_admin: bool | None = None
    display_name: str | None = Field(None, min_length=1, max_length=50)
