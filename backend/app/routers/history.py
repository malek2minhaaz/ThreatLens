"""Historical scan log endpoints (dashboard history panel)."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import get_current_user
from ..models import PhishingAnalysis, ScanRecord, User

router = APIRouter(tags=["history"])


@router.get("/api/history", summary="List the current user's recent URL scans")
def list_history(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    total = db.query(ScanRecord).filter(ScanRecord.user_id == user.id).count()
    rows = (
        db.query(ScanRecord)
        .filter(ScanRecord.user_id == user.id)
        .order_by(desc(ScanRecord.created_at))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": (offset + limit) < total,
        "items": [
            {
                "id": r.id,
                "url": r.url,
                "risk_score": r.risk_score,
                "verdict": r.verdict,
                "created_at": r.created_at.isoformat(),
                "findings_count": len(json.loads(r.findings or "[]")),
            }
            for r in rows
        ],
    }


@router.get("/api/history/{scan_id}", summary="Fetch a full past scan report")
def get_history(
    scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    record = db.get(ScanRecord, scan_id)
    if record is None or record.user_id != user.id:
        raise HTTPException(status_code=404, detail="Scan not found.")
    summary = json.loads(record.summary or "{}")
    return {
        "id": record.id,
        "url": record.url,
        "risk_score": record.risk_score,
        "verdict": record.verdict,
        "created_at": record.created_at.isoformat(),
        "findings": json.loads(record.findings or "[]"),
        "category_totals": summary.get("category_totals", {}),
        "request": summary.get("request", {}),
        "metadata": summary.get("metadata", {}),
        "threat_intel": summary.get("threat_intel", {}),
        "providers": summary.get("providers", {}),
        "duration_ms": summary.get("duration_ms"),
    }


@router.get("/api/phishing-history", summary="List the current user's phishing analyses")
def list_phishing_history(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    total = db.query(PhishingAnalysis).filter(PhishingAnalysis.user_id == user.id).count()
    rows = (
        db.query(PhishingAnalysis)
        .filter(PhishingAnalysis.user_id == user.id)
        .order_by(desc(PhishingAnalysis.created_at))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": (offset + limit) < total,
        "items": [
            {
                "id": r.id,
                "content_type": r.content_type,
                "preview": r.content_preview,
                "phishing_score": r.phishing_score,
                "verdict": r.verdict,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ],
    }
