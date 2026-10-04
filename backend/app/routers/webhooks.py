"""Webhook endpoints — subscribe to scan events."""
from __future__ import annotations

import hashlib
import hmac
import json

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import get_current_user
from ..models import User, Webhook
from ..schemas import WatchlistAddRequest

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


@router.get("", summary="List your webhooks")
def list_webhooks(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    rows = (
        db.query(Webhook)
        .filter(Webhook.user_id == user.id)
        .order_by(Webhook.created_at.desc())
        .all()
    )
    return {
        "items": [
            {
                "id": w.id,
                "url": w.url,
                "events": json.loads(w.events or "[]"),
                "is_active": w.is_active,
                "last_triggered_at": w.last_triggered_at.isoformat() if w.last_triggered_at else None,
                "created_at": w.created_at.isoformat(),
            }
            for w in rows
        ]
    }


@router.post("", summary="Create a webhook")
def create_webhook(
    payload: dict,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    url = (payload.get("url") or "").strip()
    events = payload.get("events", ["scan.dangerous"])
    if not url or not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Provide a valid HTTP(S) URL.")
    secret = hmac.new(b"threatlens", url.encode(), hashlib.sha256).hexdigest()[:32]
    w = Webhook(user_id=user.id, url=url, secret=secret, events=json.dumps(events))
    db.add(w)
    db.commit()
    db.refresh(w)
    return {
        "id": w.id,
        "url": w.url,
        "secret": w.secret,
        "events": events,
        "detail": "Webhook created. Sign payloads with this secret.",
    }


@router.delete("/{webhook_id}", summary="Delete a webhook")
def delete_webhook(
    webhook_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    w = db.get(Webhook, webhook_id)
    if w is None or w.user_id != user.id:
        raise HTTPException(status_code=404, detail="Webhook not found.")
    db.delete(w)
    db.commit()
    return {"detail": "Webhook deleted."}


async def fire_webhooks(db: Session, user_id: int, event: str, payload: dict) -> None:
    """Fire all active webhooks for a user matching the event type."""
    rows = db.query(Webhook).filter(Webhook.user_id == user_id, Webhook.is_active == True).all()  # noqa: E712
    for w in rows:
        events = json.loads(w.events or "[]")
        if event not in events and "*" not in events:
            continue
        body = json.dumps({"event": event, "data": payload}).encode()
        sig = hmac.new(w.secret.encode(), body, hashlib.sha256).hexdigest()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    w.url,
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-ThreatLens-Signature": sig,
                        "X-ThreatLens-Event": event,
                    },
                )
            w.last_triggered_at = __import__("datetime").datetime.utcnow()
            db.commit()
        except Exception:  # noqa: BLE001
            pass  # don't let webhook failures break the scan
