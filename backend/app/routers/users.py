"""Per-user statistics and downloadable reports."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import get_current_user
from ..models import PhishingAnalysis, ScanRecord, User, utcnow

router = APIRouter(tags=["users"])


@router.get("/api/users/stats", summary="Aggregate stats for the current user")
def user_stats(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    scan_q = db.query(ScanRecord).filter(ScanRecord.user_id == user.id)
    phish_q = db.query(PhishingAnalysis).filter(PhishingAnalysis.user_id == user.id)

    total_scans = scan_q.count()
    avg_score = scan_q.with_entities(func.avg(ScanRecord.risk_score)).scalar()
    verdict_rows = (
        scan_q.with_entities(ScanRecord.verdict, func.count(ScanRecord.id))
        .group_by(ScanRecord.verdict)
        .all()
    )
    total_phishing = phish_q.count()
    avg_phish_score = phish_q.with_entities(func.avg(PhishingAnalysis.phishing_score)).scalar()

    recent_scans = [
        {
            "type": "scan",
            "detail": r.url,
            "risk_score": r.risk_score,
            "verdict": r.verdict,
            "created_at": r.created_at.isoformat(),
        }
        for r in scan_q.order_by(ScanRecord.created_at.desc()).limit(6).all()
    ]
    recent_phish = [
        {
            "type": "phishing",
            "detail": (r.content_preview[:60] + "…") if len(r.content_preview or "") > 60 else (r.content_preview or ""),
            "risk_score": r.phishing_score,
            "verdict": r.verdict,
            "created_at": r.created_at.isoformat(),
        }
        for r in phish_q.order_by(PhishingAnalysis.created_at.desc()).limit(6).all()
    ]
    activity = sorted(recent_scans + recent_phish, key=lambda a: a["created_at"], reverse=True)[:10]

    return {
        "total_scans": total_scans,
        "total_phishing_analyses": total_phishing,
        "avg_risk_score": round(avg_score, 1) if avg_score is not None else None,
        "avg_phishing_score": round(avg_phish_score, 1) if avg_phish_score is not None else None,
        "verdict_distribution": {v: c for v, c in verdict_rows},
        "dangerous_scans": dict(verdict_rows).get("DANGEROUS", 0),
        "recent_activity": activity,
    }


@router.get("/api/users/report", summary="Full activity report for the current user")
def user_report(
    limit: int = Query(default=200, ge=1, le=1000),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Everything needed to build a downloadable report (HTML/CSV/JSON)."""
    scan_q = db.query(ScanRecord).filter(ScanRecord.user_id == user.id)
    phish_q = db.query(PhishingAnalysis).filter(PhishingAnalysis.user_id == user.id)

    total_scans = scan_q.count()
    total_phishing = phish_q.count()
    avg_risk = scan_q.with_entities(func.avg(ScanRecord.risk_score)).scalar()
    avg_phish = phish_q.with_entities(func.avg(PhishingAnalysis.phishing_score)).scalar()
    verdict_rows = dict(
        scan_q.with_entities(ScanRecord.verdict, func.count(ScanRecord.id)).group_by(ScanRecord.verdict).all()
    )
    dangerous = verdict_rows.get("DANGEROUS", 0)

    scans = [
        {
            "id": r.id,
            "url": r.url,
            "risk_score": r.risk_score,
            "verdict": r.verdict,
            "findings_count": len(json.loads(r.findings or "[]")),
            "created_at": r.created_at.isoformat(),
        }
        for r in scan_q.order_by(ScanRecord.created_at.desc()).limit(limit).all()
    ]
    phishing = [
        {
            "id": r.id,
            "content_type": r.content_type,
            "preview": r.content_preview,
            "phishing_score": r.phishing_score,
            "verdict": r.verdict,
            "created_at": r.created_at.isoformat(),
        }
        for r in phish_q.order_by(PhishingAnalysis.created_at.desc()).limit(limit).all()
    ]

    return {
        "generated_at": utcnow().isoformat(),
        "user": {
            "username": user.username,
            "public_name": user.public_name,
            "email": user.email,
            "created_at": user.created_at.isoformat(),
        },
        "summary": {
            "total_scans": total_scans,
            "total_phishing": total_phishing,
            "dangerous_scans": dangerous,
            "detection_rate": round(dangerous / total_scans, 3) if total_scans else 0,
            "avg_risk_score": round(avg_risk, 1) if avg_risk is not None else None,
            "avg_phishing_score": round(avg_phish, 1) if avg_phish is not None else None,
            "verdict_distribution": verdict_rows,
        },
        "scans": scans,
        "phishing": phishing,
    }
