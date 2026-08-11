"""Threat-intel dashboard endpoints."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..dependencies import get_current_user
from ..models import ScanRecord, User

router = APIRouter(tags=["threat_intel"])


@router.get("/api/intel/status", summary="Which threat-intel providers are configured")
def intel_status(user: User = Depends(get_current_user)) -> dict:
    return {
        "virustotal": settings.VIRUSTOTAL_API_KEY != "",
        "google_safe_browsing": settings.GOOGLE_SAFE_BROWSING_API_KEY != "",
        "phishtank": settings.PHISHTANK_API_KEY != "",
    }


@router.get("/api/intel/feed", summary="Recent threat-intel verdicts from past scans")
def intel_feed(
    limit: int = Query(default=20, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    rows = (
        db.query(ScanRecord)
        .filter(ScanRecord.user_id == user.id)
        .order_by(desc(ScanRecord.created_at))
        .limit(limit)
        .all()
    )
    feed = []
    detections = 0
    for r in rows:
        try:
            summary = json.loads(r.summary or "{}")
            intel = summary.get("threat_intel", {}) or {}
        except (ValueError, TypeError):
            intel = {}
        vt = intel.get("virustotal", {}) or {}
        gsb = intel.get("google_safe_browsing", {}) or {}
        pt = intel.get("phishtank", {}) or {}
        malicious = int(vt.get("malicious", 0) or 0)
        if malicious or (gsb.get("threatened") or False) or (pt.get("in_database") or False):
            detections += 1
        feed.append({
            "scan_id": r.id,
            "url": r.url,
            "risk_score": r.risk_score,
            "created_at": r.created_at.isoformat(),
            "virustotal": {
                "status": vt.get("status"),
                "malicious": malicious,
                "suspicious": int(vt.get("suspicious", 0) or 0),
                "total_engines": int(vt.get("total_engines", 0) or 0),
            },
            "google_safe_browsing": {
                "status": gsb.get("status"),
                "threatened": bool(gsb.get("threatened")),
                "threat_types": [m.get("threat_type") for m in (gsb.get("matches") or [])],
            },
            "phishtank": {
                "status": pt.get("status"),
                "in_database": bool(pt.get("in_database")),
            },
        })
    return {"total": len(feed), "detections": detections, "feed": feed}
