"""
Security helpers: password hashing + token generation.

Uses only the standard library (PBKDF2-HMAC-SHA256 with a per-user random
salt) so there is no dependency on unmaintained passlib/bcrypt wheels.
"""
from __future__ import annotations

import hashlib
import secrets

_ITERATIONS = 210_000
_ALGO = "pbkdf2_sha256"


def hash_password(password: str) -> str:
    """Hash a password into ``pbkdf2_sha256$<salt>$<hex>`` (random salt)."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), _ITERATIONS)
    return f"{_ALGO}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a password against a stored hash."""
    try:
        algo, salt, hex_digest = stored.split("$", 2)
        if algo != _ALGO:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), _ITERATIONS)
        return secrets.compare_digest(digest.hex(), hex_digest)
    except (ValueError, TypeError):
        return False


def new_bearer_token() -> str:
    """Cryptographically random bearer token (64 hex chars)."""
    return secrets.token_hex(32)
