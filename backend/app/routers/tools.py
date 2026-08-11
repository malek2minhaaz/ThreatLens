"""Phishing toolset: link inspector, email header analyzer, sender domain
check, phishing trends and the user watchlist."""
from __future__ import annotations

import asyncio
import json
import re
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..dependencies import get_current_user
from ..models import PhishingAnalysis, ScanRecord, User, WatchlistEntry, utcnow
from ..schemas import (
    HeadersRequest,
    InspectRequest,
    SenderCheckRequest,
    WatchlistAddRequest,
    WatchlistCheckRequest,
)
from ..services import heuristics, metadata as meta
from ..services.phishing_analyzer import analyze_phishing
from ..services.rate_limit import tool_limiter
from ..services.risk_scoring import compute_risk
from ..services.scanner import scan_url
from ..services.url_parser import parse_url
from ..services.watchlist import extract_links, extract_sender_domains, match_watchlist

router = APIRouter(tags=["phishing-tools"])

MAX_INSPECT_LINKS = 8
FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com",
    "outlook.com", "live.com", "aol.com", "icloud.com", "protonmail.com", "proton.me",
    "mail.com", "gmx.com", "zoho.com",
}

_INSPECT_SCAN_SECONDS = 30  # per-link cap; the pipeline caps the whole batch too


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Link inspector
# ---------------------------------------------------------------------------

async def _scan_one(raw_url: str) -> dict:
    """Scan a single link with the full pipeline, capped by an outer timeout."""
    async with asyncio.timeout(_INSPECT_SCAN_SECONDS):
        return await scan_url(raw_url)


@router.post("/api/phishing/inspect", summary="Analyze text and scan every embedded link")
async def inspect_content(
    payload: InspectRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Message-level phishing analysis + a full URL scan of every link inside."""
    if not tool_limiter.allow(_client_ip(request)):
        raise HTTPException(status_code=429, detail="Too many inspections. Try again later.")

    content = payload.content
    message = analyze_phishing(content, "email")

    # Dedupe links, prefer URLs from the analyzer (handles hxxp variants too)
    links: list[str] = []
    seen: set[str] = set()
    for u in list(message["stats"]["links"]) + extract_links(content):
        key = u.lower()
        if key not in seen:
            seen.add(key)
            links.append(u)
    links = links[:MAX_INSPECT_LINKS]

    scan_results = await asyncio.gather(*[_scan_one(u) for u in links], return_exceptions=True)

    records: list[ScanRecord] = []
    ok_indices: list[int] = []
    link_reports: list[dict] = []
    for i, (url, res) in enumerate(zip(links, scan_results)):
        if isinstance(res, BaseException):
            link_reports.append({"url": url, "error": str(res)[:200]})
            continue
        record = ScanRecord(
            user_id=user.id,
            url=res["request"]["normalized_url"],
            risk_score=res["risk_score"],
            verdict=res["verdict"],
            summary=json.dumps({
                "request": res["request"],
                "category_totals": res["category_totals"],
                "metadata": res["metadata"],
                "threat_intel": res["threat_intel"],
                "providers": res["providers"],
                "duration_ms": res["duration_ms"],
                "scanned_at": res["scanned_at"],
                "source": "link-inspector",
            }),
            findings=json.dumps(res["findings"]),
        )
        db.add(record)
        records.append(record)
        ok_indices.append(len(link_reports))
        link_reports.append({
            "url": url,
            "normalized_url": res["request"]["normalized_url"],
            "risk_score": res["risk_score"],
            "verdict": res["verdict"],
            "risk_level": res["risk_level"],
            "findings_count": len(res["findings"]),
            "duration_ms": res["duration_ms"],
            "scan_id": None,
        })

    analysis = PhishingAnalysis(
        user_id=user.id,
        content_type="email",
        content_preview=content[:400],
        phishing_score=message["phishing_score"],
        verdict=message["verdict"],
        flags=json.dumps(message["flags"]),
    )
    db.add(analysis)
    db.flush()
    for record, idx in zip(records, ok_indices):
        link_reports[idx]["scan_id"] = record.id
    db.commit()

    values = set(extract_sender_domains(content))
    for rep in link_reports:
        if "normalized_url" in rep:
            try:
                values.add(parse_url(rep["normalized_url"]).registrable)
            except ValueError:
                pass
    watchlist_matches = match_watchlist(db, user.id, values)

    return {
        "analysis_id": analysis.id,
        "message": message,
        "links": link_reports,
        "scanned_count": len(ok_indices),
        "failed_count": len(link_reports) - len(ok_indices),
        "watchlist_matches": watchlist_matches,
    }


# ---------------------------------------------------------------------------
# Email header analyzer
# ---------------------------------------------------------------------------

def _header_value(content: str, name: str) -> str | None:
    """Extract a header value, joining folded (continuation) lines."""
    match = re.search(rf"(?im)^{re.escape(name)}\s*:\s*(.*(?:\r?\n[ \t]+.*)*)$", content)
    if not match:
        return None
    return re.sub(r"\r?\n[ \t]+", " ", match.group(1)).strip()


def _email_domain(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", value)
    return match.group(1).lower() if match else None


def analyze_email_headers(content: str) -> dict:
    """Rule-based inspection of raw email headers for spoofing indicators."""
    flags: list[dict] = []

    def add(label: str, points: int, severity: str, detail: str) -> None:
        flags.append({"label": label, "points": points, "severity": severity, "detail": detail})

    from_h = _header_value(content, "From")
    reply = _header_value(content, "Reply-To")
    retpath = _header_value(content, "Return-Path")
    subject = _header_value(content, "Subject")
    sender = _header_value(content, "Sender")
    received_count = len(re.findall(r"(?im)^received\s*:\s*(.*(?:\r?\n[ \t]+.*)*)$", content))

    auth_res = (_header_value(content, "Authentication-Results") or "") + " " + (_header_value(content, "spf") or "")
    spf = re.search(r"\bspf=(\w+)", auth_res)
    dkim = re.search(r"\bdkim=(\w+)", auth_res)
    dmarc = re.search(r"\bdmarc=(\w+)", auth_res)
    auth = {"spf": spf.group(1) if spf else None, "dkim": dkim.group(1) if dkim else None,
            "dmarc": dmarc.group(1) if dmarc else None}

    if not from_h:
        add("Missing From header", 30, "critical", "No From header found — raw dump may be truncated or the header was stripped.")
    else:
        from_domain = _email_domain(from_h)
        reply_domain = _email_domain(reply)
        ret_domain = _email_domain(retpath)

        if from_domain in FREE_MAIL_DOMAINS:
            add("Sender uses a free personal email", 10, "medium",
                f"From domain '{from_domain}' is a free mail provider — a real bank/company never sends from one.")
        if "xn--" in from_h.lower():
            add("Punycode / IDN in From", 15, "high",
                "Internationalized domain in the From header can mimic ASCII characters (homograph attack).")
        local = (from_h.split("@")[0] if from_h and "@" in from_h else "")
        if local.isdigit() and len(local) >= 4:
            add("Numeric sender local-part", 5, "low", f"From local-part '{local}' is numeric — a spam hallmark.")

        if reply and reply.lower().strip() != from_h.lower().strip() and reply_domain != from_domain:
            add("Reply-To differs from From", 20, "critical",
                f"Reply-To ({reply[:70]}) points elsewhere — replies would go to the attacker, not the claimed sender.")
        elif reply and reply_domain and reply_domain != from_domain:
            add("Reply-To domain differs from From", 15, "high",
                f"Reply-To ({reply[:70]}) uses a different domain than From.")

        if retpath and ret_domain and from_domain and ret_domain != from_domain:
            add("Return-Path domain differs from From", 15, "high",
                f"Return-Path ({retpath[:70]}) does not match the claimed sender domain.")

    if received_count >= 3:
        add("Long relay chain", 5, "medium", f"{received_count} Received hops — legitimate mail rarely bounces through many servers.")
    if auth["spf"] == "fail":
        add("SPF authentication failed", 20, "critical", "SPF check failed — the sending server is not authorized for this domain.")
    if auth["dkim"] == "fail":
        add("DKIM signature failed", 20, "critical", "DKIM verification failed — the message is not signed by the claimed domain.")
    if auth["dmarc"] == "fail":
        add("DMARC policy failed", 25, "critical", "DMARC failed — the message fails alignment with the claimed domain.")
    if not any(auth.values()):
        add("No authentication results", 5, "low", "No SPF/DKIM/DMARC results found in the headers.")

    raw = sum(int(f.get("points", 0)) for f in flags)
    score = min(100, raw)
    if score >= 55:
        verdict, confidence = "PHISHING", "high" if score >= 75 else "medium"
    elif score >= 25:
        verdict, confidence = "SUSPICIOUS", "medium"
    else:
        verdict, confidence = "SAFE", "low"

    return {
        "score": score,
        "verdict": verdict,
        "confidence": confidence,
        "flags": flags,
        "parsed": {
            "from": from_h,
            "from_domain": _email_domain(from_h),
            "reply_to": reply,
            "return_path": retpath,
            "sender": sender,
            "subject": subject,
            "received_count": received_count,
            "auth": auth,
        },
    }


@router.post("/api/phishing/headers", summary="Analyze raw email headers for spoofing")
def analyze_headers_endpoint(
    payload: HeadersRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    result = analyze_email_headers(payload.content)

    record = PhishingAnalysis(
        user_id=user.id,
        content_type="email",
        content_preview=payload.content[:400],
        phishing_score=result["score"],
        verdict=result["verdict"],
        flags=json.dumps(result["flags"]),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    result["analysis_id"] = record.id
    return result


# ---------------------------------------------------------------------------
# Sender domain check
# ---------------------------------------------------------------------------

def _extract_domain(sender: str) -> str | None:
    s = sender.strip()
    if not s:
        return None
    match = re.search(r"@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", s)
    if match:
        return match.group(1)
    if "://" in s or s.startswith("www."):
        try:
            return parse_url(s).registrable
        except ValueError:
            return None
    if "." in s and re.match(r"^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$", s):
        return s
    return None


@router.post("/api/phishing/sender-check", summary="Check a sender's domain reputation")
async def sender_check_endpoint(
    payload: SenderCheckRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    if not tool_limiter.allow(_client_ip(request)):
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")

    domain = _extract_domain(payload.sender)
    if not domain:
        raise HTTPException(status_code=400, detail="Could not extract a domain from that sender.")

    try:
        parsed = parse_url("http://" + domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid domain: {exc}") from exc

    findings = heuristics.run_heuristics(parsed)

    official = {d.lower() for doms in heuristics.POPULAR_BRANDS.values() for d in doms}
    if parsed.registrable.lower() in official:
        findings.append({
            "label": "Matches an official brand domain",
            "points": 10,
            "severity": "info",
            "detail": f"'{parsed.registrable}' is a known official domain.",
        })

    # WHOIS domain age (optional — degrades gracefully when unavailable/slow)
    whois = None
    loop = asyncio.get_running_loop()
    try:
        async with asyncio.timeout(8):
            whois = await loop.run_in_executor(None, meta.fetch_whois, parsed)
    except (asyncio.TimeoutError, Exception):  # noqa: BLE001
        whois = None
    age_finding = meta.domain_age_finding(whois) if whois else None
    if age_finding:
        findings.append(age_finding)

    for f in findings:
        f["category"] = "Sender Domain"
    report = compute_risk(findings)

    watchlist_matches = match_watchlist(db, user.id, {parsed.registrable})

    return {
        "sender": payload.sender,
        "domain": parsed.registrable,
        "risk_score": report.score,
        "verdict": report.verdict,
        "risk_level": report.risk_level,
        "findings": report.findings,
        "whois": {
            "available": whois.get("available"),
            "registration_date": whois.get("registration_date"),
            "registered_days_ago": whois.get("registered_days_ago"),
        } if whois else None,
        "watchlist_matches": watchlist_matches,
    }


# ---------------------------------------------------------------------------
# Phishing trends
# ---------------------------------------------------------------------------

@router.get("/api/phishing/trends", summary="Phishing score trends and tactics for the user")
def phishing_trends(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    since = utcnow() - timedelta(days=30)
    rows = (
        db.query(PhishingAnalysis)
        .filter(PhishingAnalysis.user_id == user.id, PhishingAnalysis.created_at >= since)
        .order_by(PhishingAnalysis.created_at.asc())
        .all()
    )

    days: dict[str, list[int]] = {}
    verdicts: dict[str, int] = {}
    flag_counts: dict[str, int] = {}
    for r in rows:
        day = r.created_at.strftime("%Y-%m-%d")
        days.setdefault(day, []).append(r.phishing_score)
        verdicts[r.verdict] = verdicts.get(r.verdict, 0) + 1
        try:
            parsed_flags = json.loads(r.flags or "[]")
        except json.JSONDecodeError:
            continue
        for f in parsed_flags:
            label = f.get("label", "Unknown")
            flag_counts[label] = flag_counts.get(label, 0) + 1

    series = [
        {"date": day, "avg_score": round(sum(scores) / len(scores), 1), "count": len(scores)}
        for day, scores in sorted(days.items())
    ]
    top_flags = sorted(flag_counts.items(), key=lambda kv: -kv[1])[:6]

    total = db.query(PhishingAnalysis).filter(PhishingAnalysis.user_id == user.id).count()
    avg_all = (
        db.query(func.avg(PhishingAnalysis.phishing_score))
        .filter(PhishingAnalysis.user_id == user.id)
        .scalar()
    )

    return {
        "series": series,
        "verdict_distribution": verdicts,
        "top_flags": [{"label": label, "count": count} for label, count in top_flags],
        "total_analyses": total,
        "avg_score": round(avg_all, 1) if avg_all is not None else None,
    }


# ---------------------------------------------------------------------------
# Watchlist
# ---------------------------------------------------------------------------

def _watchlist_item(entry: WatchlistEntry) -> dict:
    return {
        "id": entry.id,
        "kind": entry.kind,
        "value": entry.value,
        "note": entry.note,
        "created_at": entry.created_at.isoformat(),
        "last_seen_at": entry.last_seen_at.isoformat() if entry.last_seen_at else None,
    }


@router.get("/api/watchlist", summary="List the current user's watchlist")
def list_watchlist(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    items = (
        db.query(WatchlistEntry)
        .filter(WatchlistEntry.user_id == user.id)
        .order_by(WatchlistEntry.created_at.desc())
        .all()
    )
    return {"items": [_watchlist_item(i) for i in items], "total": len(items)}


@router.post("/api/watchlist", summary="Add an indicator to the watchlist")
def add_watchlist(
    payload: WatchlistAddRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    value = payload.value.strip()
    duplicate = (
        db.query(WatchlistEntry)
        .filter(
            WatchlistEntry.user_id == user.id,
            func.lower(WatchlistEntry.value) == value.lower(),
        )
        .first()
    )
    if duplicate:
        raise HTTPException(status_code=409, detail="That entry is already on your watchlist.")

    entry = WatchlistEntry(user_id=user.id, kind=payload.kind, value=value, note=payload.note)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return _watchlist_item(entry)


@router.delete("/api/watchlist/{entry_id}", summary="Remove an entry from the watchlist")
def delete_watchlist(
    entry_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    entry = (
        db.query(WatchlistEntry)
        .filter(WatchlistEntry.id == entry_id, WatchlistEntry.user_id == user.id)
        .first()
    )
    if entry is None:
        raise HTTPException(status_code=404, detail="Watchlist entry not found.")
    db.delete(entry)
    db.commit()
    return {"detail": "Removed from watchlist."}


@router.post("/api/watchlist/check", summary="Check text against the watchlist")
def check_watchlist(
    payload: WatchlistCheckRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    if not tool_limiter.allow(_client_ip(request)):
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.")
    values = set(extract_sender_domains(payload.content)) | set(extract_links(payload.content))
    for u in list(values):
        try:
            values.add(parse_url(u).registrable)
        except ValueError:
            pass
    return {"matches": match_watchlist(db, user.id, values)}
