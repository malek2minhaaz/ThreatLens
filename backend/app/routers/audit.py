"""Audit log endpoints — records admin and system actions."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import desc
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import get_current_admin
from ..models import AuditLog, User

router = APIRouter(prefix="/api/audit", tags=["audit"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def log_action(db: Session, user: User | None, action: str, detail: str = "", ip: str | None = None) -> None:
    """Helper to write an audit entry."""
    db.add(AuditLog(
        user_id=user.id if user else None,
        action=action,
        detail=detail,
        ip_address=ip,
    ))
    db.commit()


@router.get("/log", summary="List recent audit log entries")
def list_audit_log(
    limit: int = Query(default=50, ge=1, le=200),
    _admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict:
    rows = (
        db.query(AuditLog)
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
        .all()
    )
    return {
        "total": db.query(AuditLog).count(),
        "items": [
            {
                "id": r.id,
                "user_id": r.user_id,
                "action": r.action,
                "detail": r.detail,
                "ip_address": r.ip_address,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ],
    }
