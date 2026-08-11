"""SQLAlchemy ORM models for ThreatLens."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utcnow() -> datetime:
    """Naive UTC "now" — SQLite drops tzinfo on read, so store/compare naive."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


_utcnow = utcnow  # backward-compatible alias


class User(Base):
    """A registered ThreatLens user."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(24), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    @property
    def public_name(self) -> str:
        return self.display_name or self.username


class AuthToken(Base):
    """Opaque bearer token bound to a user (DB-backed sessions)."""

    __tablename__ = "auth_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class WatchlistEntry(Base):
    """A user's saved phishing indicator (sender email, domain or URL)."""

    __tablename__ = "watchlist_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(10), nullable=False)  # sender | domain | url
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    note: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ScanRecord(Base):
    """A persisted URL scan result (historical log)."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    url: Mapped[str] = mapped_column(String(2048), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(50))
    summary: Mapped[str] = mapped_column(Text, default="{}")   # JSON: request + breakdown
    findings: Mapped[str] = mapped_column(Text, default="[]")  # JSON: itemized findings
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)


class PhishingAnalysis(Base):
    """A persisted phishing-content analysis."""

    __tablename__ = "phishing_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    content_type: Mapped[str] = mapped_column(String(50), default="email")
    content_preview: Mapped[str] = mapped_column(String(500), default="")
    phishing_score: Mapped[int] = mapped_column(Integer)  # 0..100, higher = more likely phishing
    verdict: Mapped[str] = mapped_column(String(50))
    flags: Mapped[str] = mapped_column(Text, default="[]")  # JSON: itemized flags
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
