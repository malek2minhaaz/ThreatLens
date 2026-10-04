"""
ThreatLens - Application configuration.

All settings are read from environment variables (or a local `.env` file).
External API keys are OPTIONAL: every provider degrades gracefully.
"""
from __future__ import annotations

import os

from dotenv import load_dotenv

# Load variables from backend/.env if present
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))


class Settings:
    """Centralised settings object. Access via `get_settings()`."""

    APP_NAME: str = "ThreatLens"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = (
        "Threat detection platform: URL scanning, phishing content analysis "
        "and unified risk scoring."
    )

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./threatshield.db")

    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))

    # Admin: username that is auto-promoted to admin at startup (optional)
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "").strip()

    # Threat intelligence (optional)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    PHISHTANK_API_KEY: str = os.getenv("PHISHTANK_API_KEY", "").strip()

    # CORS origins (comma-separated, or * for dev)
    CORS_ORIGINS: list[str] = [
        o.strip()
        for o in os.getenv("CORS_ORIGINS", "*").split(",")
        if o.strip()
    ]

    # Admin email for notifications (optional)
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "").strip()

    # SMTP settings for email notifications (optional)
    SMTP_HOST: str = os.getenv("SMTP_HOST", "").strip()
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "").strip()
    SMTP_PASS: str = os.getenv("SMTP_PASS", "").strip()
    SMTP_FROM: str = os.getenv("SMTP_FROM", "noreply@threatlens.local").strip()

    # Tuning
    REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "10"))
    # Hard cap for the whole scan pipeline (WHOIS can be slow)
    MAX_SCAN_SECONDS: int = int(os.getenv("MAX_SCAN_SECONDS", "45"))


settings = Settings()
