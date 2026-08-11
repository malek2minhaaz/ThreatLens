"""
ThreatLens scan pipeline.

Orchestrates the full URL analysis:

1. Parse & normalize the URL
2. Heuristics (offline, instant)
3. Metadata (WHOIS + SSL + HTTP, run in parallel via a thread pool)
4. Threat intelligence (VirusTotal / Safe Browsing / PhishTank, optional keys)
5. Risk scoring → unified 0-100 score with itemized findings
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

from ..config import settings
from . import heuristics, metadata as meta, threat_intel as intel
from .risk_scoring import compute_risk
from .url_parser import parse_url

CATEGORY_LABELS = {
    "heuristics": "Heuristics",
    "metadata": "Metadata",
    "threat_intel": "Threat Intelligence",
}


class InvalidURLError(ValueError):
    """Raised when the submitted URL cannot be parsed or is not http(s)."""


def _finalize_findings(findings: list[dict]) -> list[dict]:
    """Attach the human-readable category name to every finding."""
    out = []
    for f in findings:
        f = dict(f)
        f["category"] = CATEGORY_LABELS.get(f.get("_category", "heuristics"), "Other")
        f.pop("_category", None)
        out.append(f)
    return out


async def scan_url(raw_url: str) -> dict:
    """
    Run the complete scan pipeline against `raw_url`.

    Never raises for external failures: every subsystem degrades to a
    documented "info" finding so the user still gets a full report.
    """
    started = time.monotonic()

    # ---- 1. Parse ---------------------------------------------------------
    try:
        parsed = parse_url(raw_url)
    except ValueError as exc:
        raise InvalidURLError(str(exc)) from exc

    # ---- 2. Heuristics (instant, offline) ---------------------------------
    heuristic_findings = heuristics.run_heuristics(parsed)
    for f in heuristic_findings:
        f["_category"] = "heuristics"

    # ---- 3. Metadata (parallel: WHOIS, SSL, HTTP) --------------------------
    loop = asyncio.get_running_loop()
    async with asyncio.timeout(settings.MAX_SCAN_SECONDS):
        whois, ssl_info, http = await asyncio.gather(
            loop.run_in_executor(None, meta.fetch_whois, parsed),
            loop.run_in_executor(None, meta.fetch_ssl, parsed),
            loop.run_in_executor(None, meta.fetch_http, parsed),
        )

    metadata_findings: list[dict] = []
    _meta_fs: list[dict] = []
    for f in (meta.domain_age_finding(whois), meta.ssl_finding(ssl_info, parsed)):
        if f:
            _meta_fs.append(f)
    _meta_fs.extend(meta.http_finding(http))
    for f in _meta_fs:
        f = dict(f)
        f["_category"] = "metadata"
        metadata_findings.append(f)

    # ---- 4. Threat intelligence (optional providers) -----------------------
    # Run off the event loop: the providers use blocking `requests` calls and
    # bounded polling sleeps which must never freeze the API.
    intel_results = await loop.run_in_executor(None, intel.run_threat_intel, parsed)
    intel_findings = intel.threat_intel_findings(intel_results)
    for f in intel_findings:
        f["_category"] = "threat_intel"

    # ---- 5. Risk scoring ----------------------------------------------------
    all_findings = _finalize_findings(heuristic_findings + metadata_findings + intel_findings)
    report = compute_risk(all_findings)

    elapsed_ms = int((time.monotonic() - started) * 1000)

    return {
        "request": parsed.to_dict(),
        "risk_score": report.score,
        "verdict": report.verdict,
        "risk_level": report.risk_level,
        "findings": report.findings,
        "category_totals": report.category_totals,
        "metadata": {
            "whois": whois,
            "ssl": ssl_info,
            "http": http,
        },
        "threat_intel": intel_results,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": elapsed_ms,
        "providers": {
            "virustotal": settings.VIRUSTOTAL_API_KEY != "",
            "google_safe_browsing": settings.GOOGLE_SAFE_BROWSING_API_KEY != "",
            "phishtank": settings.PHISHTANK_API_KEY != "",
        },
    }
