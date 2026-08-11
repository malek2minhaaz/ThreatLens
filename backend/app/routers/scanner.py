"""URL scanning endpoints."""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import get_current_user
from ..models import ScanRecord, User
from ..schemas import ScanRequest
from ..services.scanner import InvalidURLError, scan_url

router = APIRouter(tags=["scanner"])


@router.post("/api/scan-url", summary="Scan a URL for threats")
async def scan_url_endpoint(
    payload: ScanRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Run the full scanning pipeline against a URL and return a unified risk
    report (score 0-100, 100 = safe) with an itemized breakdown.
    """
    try:
        result = await scan_url(payload.url)
    except InvalidURLError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid URL: {exc}") from exc
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail="Scan timed out — the target may be slow or unresponsive.",
        ) from exc
    except Exception as exc:  # noqa: BLE001 - guarantee a structured error
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    # Persist to the historical log (SQLite)
    record = ScanRecord(
        user_id=user.id,
        url=result["request"]["normalized_url"],
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        summary=json.dumps({
            "request": result["request"],
            "category_totals": result["category_totals"],
            "metadata": result["metadata"],
            "threat_intel": result["threat_intel"],
            "providers": result["providers"],
            "duration_ms": result["duration_ms"],
            "scanned_at": result["scanned_at"],
        }),
        findings=json.dumps(result["findings"]),
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    result["scan_id"] = record.id
    return result
