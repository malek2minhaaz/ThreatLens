"""URL scanning endpoints."""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import SessionLocal, get_db
from ..dependencies import get_current_user
from ..models import ScanRecord, User
from ..schemas import BulkScanRequest, ScanRequest
from ..services.rate_limit import scan_limiter
from ..services.scanner import InvalidURLError, scan_url

router = APIRouter(tags=["scanner"])

MAX_BULK_URLS = 25
BULK_CONCURRENCY = 5

def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _persist_scan(db: Session, user: User, result: dict) -> int:
    """Persist a completed scan to the historical log; returns the record id."""
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
    return record.id


@router.post("/api/scan-url", summary="Scan a URL for threats")
async def scan_url_endpoint(
    payload: ScanRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Run the full scanning pipeline against a URL and return a unified risk
    report (score 0-100, 100 = safe) with an itemized breakdown.
    """
    if not scan_limiter.allow(f"scan:{user.id}"):
        raise HTTPException(status_code=429, detail="Too many scan requests. Try again later.")
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

    result["scan_id"] = _persist_scan(db, user, result)
    return result


@router.post("/api/scan-bulk", summary="Scan up to 25 URLs at once")
async def scan_bulk_endpoint(
    payload: BulkScanRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """
    Scan multiple URLs concurrently (bounded parallelism). Every URL runs the
    full pipeline and is persisted to history. Individual failures are reported
    per-URL instead of failing the whole batch.
    """
    urls = list(dict.fromkeys(u.strip() for u in payload.urls if u.strip()))[:MAX_BULK_URLS]
    if not urls:
        raise HTTPException(status_code=422, detail="Provide at least one URL to scan.")

    semaphore = asyncio.Semaphore(BULK_CONCURRENCY)

    async def worker(raw: str) -> dict:
        async with semaphore:
            try:
                result = await scan_url(raw)
            except InvalidURLError as exc:
                return {"url": raw, "error": f"Invalid URL: {exc}"}
            except asyncio.TimeoutError:
                return {"url": raw, "error": "Scan timed out — the target may be slow or unresponsive."}
            except Exception as exc:  # noqa: BLE001 - per-URL degradation
                return {"url": raw, "error": f"Scan failed: {exc}"}
            # Use a fresh DB session per worker to avoid race conditions
            worker_db = SessionLocal()
            try:
                scan_id = _persist_scan(worker_db, user, result)
            finally:
                worker_db.close()
            return {
                "url": result["request"]["normalized_url"],
                "scan_id": scan_id,
                "risk_score": result["risk_score"],
                "verdict": result["verdict"],
                "risk_level": result["risk_level"],
                "category_totals": result["category_totals"],
                "findings": result["findings"],
                "duration_ms": result["duration_ms"],
            }

    results = await asyncio.gather(*(worker(u) for u in urls))

    summary = {"safe": 0, "low_risk": 0, "suspicious": 0, "dangerous": 0, "failed": 0}
    for r in results:
        if "error" in r:
            summary["failed"] += 1
        elif r.get("verdict") == "SAFE":
            summary["safe"] += 1
        elif r.get("verdict") == "LOW RISK":
            summary["low_risk"] += 1
        elif r.get("verdict") == "SUSPICIOUS":
            summary["suspicious"] += 1
        else:
            summary["dangerous"] += 1

    return {"total": len(urls), "results": results, "summary": summary}
