"""Phishing content analysis endpoints."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import get_current_user
from ..models import PhishingAnalysis, User
from ..schemas import PhishingRequest
from ..services.phishing_analyzer import analyze_phishing
from ..services.watchlist import extract_links, extract_sender_domains, match_watchlist

router = APIRouter(tags=["phishing"])


@router.post("/api/analyze-phishing", summary="Analyze text for phishing indicators")
def analyze_phishing_endpoint(
    payload: PhishingRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Run the rule-based NLP detector over email bodies, SMS or page text and
    return a 0-100 phishing likelihood with an itemized flag list.
    """
    result = analyze_phishing(payload.content, payload.content_type)

    record = PhishingAnalysis(
        user_id=user.id,
        content_type=payload.content_type,
        content_preview=payload.content[:400],
        phishing_score=result["phishing_score"],
        verdict=result["verdict"],
        flags=json.dumps(result["flags"]),
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # Surface any watchlist matches for the sender domains / links in this text
    values = set(extract_sender_domains(payload.content)) | set(extract_links(payload.content))
    result["watchlist_matches"] = match_watchlist(db, user.id, values)
    result["analysis_id"] = record.id
    return result
