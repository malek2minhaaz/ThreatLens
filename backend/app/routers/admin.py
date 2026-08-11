"""Admin console endpoints (protected by the admin dependency)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..dependencies import get_current_admin
from ..models import AuthToken, PhishingAnalysis, ScanRecord, User, utcnow
from ..schemas import AdminUserUpdate

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _admin_user(user: User, scan_count: int = 0, phish_count: int = 0, last_scan_at: str | None = None) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "public_name": user.public_name,
        "is_admin": user.is_admin,
        "created_at": user.created_at.isoformat(),
        "scan_count": scan_count,
        "phishing_count": phish_count,
        "last_scan_at": last_scan_at,
    }


@router.get("/stats", summary="Global platform overview")
def admin_stats(
    _: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict:
    today_start = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    verdict_rows = (
        db.query(ScanRecord.verdict, func.count(ScanRecord.id))
        .group_by(ScanRecord.verdict)
        .all()
    )
    verdict_distribution = {v: c for v, c in verdict_rows}

    avg_risk = db.query(func.avg(ScanRecord.risk_score)).scalar()

    # Recent activity across all users
    scan_rows = (
        db.query(ScanRecord, User.username)
        .outerjoin(User, ScanRecord.user_id == User.id)
        .order_by(ScanRecord.created_at.desc())
        .limit(8)
        .all()
    )
    phish_rows = (
        db.query(PhishingAnalysis, User.username)
        .outerjoin(User, PhishingAnalysis.user_id == User.id)
        .order_by(PhishingAnalysis.created_at.desc())
        .limit(8)
        .all()
    )
    activity = sorted(
        [
            {
                "type": "scan",
                "username": username or "—",
                "detail": r.url,
                "risk_score": r.risk_score,
                "verdict": r.verdict,
                "created_at": r.created_at.isoformat(),
            }
            for r, username in scan_rows
        ]
        + [
            {
                "type": "phishing",
                "username": username or "—",
                "detail": (r.content_preview[:60] + "…") if len(r.content_preview or "") > 60 else (r.content_preview or "—"),
                "risk_score": r.phishing_score,
                "verdict": r.verdict,
                "created_at": r.created_at.isoformat(),
            }
            for r, username in phish_rows
        ],
        key=lambda a: a["created_at"],
        reverse=True,
    )[:10]

    # Top scanners
    top_rows = (
        db.query(User.username, func.count(ScanRecord.id).label("n"))
        .join(ScanRecord, ScanRecord.user_id == User.id)
        .group_by(User.username)
        .order_by(func.count(ScanRecord.id).desc())
        .limit(5)
        .all()
    )

    total_scans = db.query(ScanRecord).count()
    dangerous = verdict_distribution.get("DANGEROUS", 0)

    return {
        "users": db.query(User).count(),
        "admins": db.query(User).filter(User.is_admin.is_(True)).count(),
        "tokens": db.query(AuthToken).filter(AuthToken.expires_at >= utcnow()).count(),
        "total_scans": total_scans,
        "total_phishing": db.query(PhishingAnalysis).count(),
        "scans_today": db.query(ScanRecord).filter(ScanRecord.created_at >= today_start).count(),
        "dangerous_scans": dangerous,
        "detection_rate": round(dangerous / total_scans, 3) if total_scans else 0,
        "avg_risk_score": round(avg_risk, 1) if avg_risk is not None else None,
        "verdict_distribution": verdict_distribution,
        "providers": {
            "virustotal": settings.VIRUSTOTAL_API_KEY != "",
            "google_safe_browsing": settings.GOOGLE_SAFE_BROWSING_API_KEY != "",
            "phishtank": settings.PHISHTANK_API_KEY != "",
        },
        "top_users": [{"username": u, "scans": n} for u, n in top_rows],
        "recent_activity": activity,
    }


@router.get("/users", summary="List every user with per-user counts")
def list_users(
    _: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict:
    scan_counts = dict(
        db.query(ScanRecord.user_id, func.count(ScanRecord.id)).group_by(ScanRecord.user_id).all()
    )
    phish_counts = dict(
        db.query(PhishingAnalysis.user_id, func.count(PhishingAnalysis.id)).group_by(PhishingAnalysis.user_id).all()
    )
    last_scans = dict(
        db.query(ScanRecord.user_id, func.max(ScanRecord.created_at)).group_by(ScanRecord.user_id).all()
    )

    items = [
        _admin_user(
            u,
            scan_count=scan_counts.get(u.id, 0),
            phish_count=phish_counts.get(u.id, 0),
            last_scan_at=last_scans.get(u.id).isoformat() if last_scans.get(u.id) else None,
        )
        for u in db.query(User).order_by(User.created_at.asc()).all()
    ]
    return {"total": len(items), "items": items}


@router.patch("/users/{user_id}", summary="Promote/demote or rename a user")
def update_user(
    user_id: int,
    payload: AdminUserUpdate,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    if user_id == admin.id and payload.is_admin is False:
        raise HTTPException(status_code=400, detail="You cannot demote your own account.")
    if payload.is_admin is not None:
        user.is_admin = payload.is_admin
    if payload.display_name is not None:
        user.display_name = payload.display_name.strip() or None

    db.commit()
    db.refresh(user)

    scan_count = db.query(ScanRecord).filter(ScanRecord.user_id == user.id).count()
    phish_count = db.query(PhishingAnalysis).filter(PhishingAnalysis.user_id == user.id).count()
    last_scan = (
        db.query(func.max(ScanRecord.created_at)).filter(ScanRecord.user_id == user.id).scalar()
    )
    return _admin_user(
        user,
        scan_count=scan_count,
        phish_count=phish_count,
        last_scan_at=last_scan.isoformat() if last_scan else None,
    )


@router.delete("/users/{user_id}", summary="Delete a user and all their data")
def delete_user(
    user_id: int,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict:
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    db.query(AuthToken).filter(AuthToken.user_id == user_id).delete(synchronize_session=False)
    db.query(ScanRecord).filter(ScanRecord.user_id == user_id).delete(synchronize_session=False)
    db.query(PhishingAnalysis).filter(PhishingAnalysis.user_id == user_id).delete(synchronize_session=False)
    db.delete(user)
    db.commit()
    return {"detail": f"User {user.username} deleted."}


@router.get("/scans", summary="Recent scans from every user")
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    _: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict:
    rows = (
        db.query(ScanRecord, User.username)
        .outerjoin(User, ScanRecord.user_id == User.id)
        .order_by(ScanRecord.created_at.desc())
        .limit(limit)
        .all()
    )
    items = [
        {
            "id": r.id,
            "username": username or "—",
            "url": r.url,
            "risk_score": r.risk_score,
            "verdict": r.verdict,
            "created_at": r.created_at.isoformat(),
        }
        for r, username in rows
    ]
    return {"total": len(items), "items": items}
