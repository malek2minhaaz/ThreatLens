"""Watchlist helpers: extract phishing indicators from text and match them
against the current user's saved watchlist entries."""
from __future__ import annotations

import re

from ..models import WatchlistEntry, utcnow

_BARE_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_FROM_RE = re.compile(r"(?im)^from\s*:\s*(.*)$")
_REPLY_RE = re.compile(r"(?im)^reply-to\s*:\s*(.*)$")


def extract_links(text: str) -> list[str]:
    """Plain URLs embedded in text (deduped, order preserved)."""
    seen: set[str] = set()
    urls: list[str] = []
    for u in _BARE_URL_RE.findall(text or ""):
        key = u.lower()
        if key not in seen:
            seen.add(key)
            urls.append(u)
    return urls


def extract_sender_domains(text: str) -> list[str]:
    """Domains from From/Reply-To headers and any inline email addresses."""
    candidates: list[str] = []
    for match in (_FROM_RE.search(text or ""), _REPLY_RE.search(text or "")):
        if match:
            candidates.append(match.group(1))
    candidates += re.findall(r"@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", text or "")
    domains: list[str] = []
    seen: set[str] = set()
    for c in candidates:
        for domain in re.findall(r"([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", c):
            d = domain.lower()
            if d not in seen:
                seen.add(d)
                domains.append(d)
    return domains


def match_watchlist(db, user_id: int, values: set[str]) -> list[dict]:
    """Return watchlist entries (case-insensitive) that match any value.

    Matching entries have ``last_seen_at`` bumped so users can see when a
    flagged indicator reappeared. Returns an empty list when nothing matches.
    """
    values = {v.strip().lower() for v in values if v and v.strip()}
    if not values:
        return []
    entries = (
        db.query(WatchlistEntry)
        .filter(WatchlistEntry.user_id == user_id)
        .order_by(WatchlistEntry.created_at.desc())
        .all()
    )
    matches: list[dict] = []
    for entry in entries:
        if entry.value.strip().lower() in values:
            entry.last_seen_at = utcnow()
            matches.append({
                "kind": entry.kind,
                "value": entry.value,
                "note": entry.note,
                "created_at": entry.created_at.isoformat(),
                "last_seen_at": entry.last_seen_at.isoformat(),
            })
    if matches:
        db.commit()
    return matches
