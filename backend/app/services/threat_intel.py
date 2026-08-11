"""
Threat intelligence integrations.

All three providers are OPTIONAL. When the corresponding API key is missing
the provider is skipped with ``{"status": "skipped"}``. Every network call is
wrapped so failures never abort the scan.
"""
from __future__ import annotations

import base64
import time

import requests

from ..config import settings
from .url_parser import ParsedUrl

_HEADERS = {"User-Agent": "ThreatLens/1.0"}
_TIMEOUT = settings.REQUEST_TIMEOUT


# ---------------------------------------------------------------------------
# VirusTotal (v3 API)
# ---------------------------------------------------------------------------

def check_virustotal(url: str) -> dict:
    """Submit URL to VirusTotal and pull the analysis verdict."""
    if not settings.VIRUSTOTAL_API_KEY:
        return {"status": "skipped", "reason": "VIRUSTOTAL_API_KEY not configured."}

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY, **_HEADERS}
    try:
        # 1) Enqueue the URL for analysis (idempotent — returns cached analysis)
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]

        # 2) Poll the analysis result (bounded retries)
        stats = None
        for _ in range(5):
            time.sleep(2)
            ar = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=_TIMEOUT,
            )
            ar.raise_for_status()
            attrs = ar.json()["data"]["attributes"]
            if attrs.get("status") == "completed":
                stats = attrs["stats"]
                break

        if stats is None:
            return {"status": "error", "error": "VirusTotal analysis did not complete in time."}

        return {
            "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()),
            "permalink": f"https://www.virustotal.com/gui/url/{url_id(url)}",
        }
    except requests.exceptions.RequestException as exc:
        return {"status": "error", "error": f"VirusTotal request failed: {type(exc).__name__}"}
    except (KeyError, ValueError) as exc:
        return {"status": "error", "error": f"VirusTotal response malformed: {type(exc).__name__}"}


def url_id(url: str) -> str:
    """VirusTotal URL identifier (base64 of the URL)."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


# ---------------------------------------------------------------------------
# Google Safe Browsing (v4 API)
# ---------------------------------------------------------------------------

def check_google_safe_browsing(url: str) -> dict:
    """Query Google Safe Browsing for URL threat matches."""
    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return {"status": "skipped", "reason": "GOOGLE_SAFE_BROWSING_API_KEY not configured."}

    payload = {
        "client": {"clientId": "threatlens", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": settings.GOOGLE_SAFE_BROWSING_API_KEY},
            json=payload,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
        if not matches:
            return {"status": "ok", "matches": [], "threatened": False}
        return {
            "status": "ok",
            "matches": [
                {
                    "threat_type": m.get("threatType"),
                    "platform_type": m.get("platformType"),
                    "threat_url": m.get("threat", {}).get("url"),
                    "cache_duration": m.get("cacheDuration"),
                }
                for m in matches
            ],
            "threatened": True,
        }
    except requests.exceptions.RequestException as exc:
        return {"status": "error", "error": f"Safe Browsing request failed: {type(exc).__name__}"}


# ---------------------------------------------------------------------------
# PhishTank
# ---------------------------------------------------------------------------

def check_phishtank(url: str) -> dict:
    """Check whether the URL is listed in the PhishTank database."""
    if not settings.PHISHTANK_API_KEY:
        return {"status": "skipped", "reason": "PHISHTANK_API_KEY not configured."}

    try:
        resp = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json", "app_key": settings.PHISHTANK_API_KEY},
            headers=_HEADERS,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("in_database"):
            return {
                "status": "ok",
                "in_database": True,
                "phish_id": data.get("phish_id"),
                "verified": data.get("verified"),
                "verified_at": data.get("verified_at"),
            }
        return {"status": "ok", "in_database": False}
    except requests.exceptions.RequestException as exc:
        return {"status": "error", "error": f"PhishTank request failed: {type(exc).__name__}"}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_threat_intel(p: ParsedUrl) -> dict:
    """Run all configured providers and aggregate their findings."""
    target = p.normalized
    results = {
        "virustotal": check_virustotal(target),
        "google_safe_browsing": check_google_safe_browsing(target),
        "phishtank": check_phishtank(target),
    }
    return results


def threat_intel_findings(intel: dict) -> list[dict]:
    """Translate threat-intel responses into risk findings."""
    findings: list[dict] = []

    vt = intel.get("virustotal", {})
    if vt.get("status") == "ok":
        mal, susp = vt.get("malicious", 0), vt.get("suspicious", 0)
        if mal >= 3:
            findings.append({"label": "Flagged by multiple AV engines",
                             "points": -80, "severity": "critical",
                             "detail": f"{mal} of {vt.get('total_engines', '?')} VirusTotal engines flagged this URL as malicious."})
        elif mal >= 1:
            findings.append({"label": "Flagged by antivirus engines",
                             "points": -60, "severity": "critical",
                             "detail": f"{mal} VirusTotal engine(s) flagged this URL as malicious."})
        if susp >= 1:
            findings.append({"label": "Suspicious on VirusTotal",
                             "points": -15, "severity": "medium",
                             "detail": f"{susp} engine(s) rated the URL suspicious."})
    elif vt.get("status") == "error":
        findings.append({"label": "VirusTotal lookup failed", "points": 0,
                         "severity": "info", "detail": vt.get("error", "")})

    gsb = intel.get("google_safe_browsing", {})
    if gsb.get("status") == "ok" and gsb.get("threatened"):
        types = ", ".join(m["threat_type"] for m in gsb["matches"])
        findings.append({"label": "Listed by Google Safe Browsing",
                         "points": -100, "severity": "critical",
                         "detail": f"Threat type(s): {types}."})
    elif gsb.get("status") == "error":
        findings.append({"label": "Safe Browsing lookup failed", "points": 0,
                         "severity": "info", "detail": gsb.get("error", "")})

    pt = intel.get("phishtank", {})
    if pt.get("status") == "ok" and pt.get("in_database"):
        findings.append({"label": "Listed in PhishTank database",
                         "points": -100, "severity": "critical",
                         "detail": f"Phish ID {pt.get('phish_id')}, verified: {pt.get('verified')}."})
    elif pt.get("status") == "error":
        findings.append({"label": "PhishTank lookup failed", "points": 0,
                         "severity": "info", "detail": pt.get("error", "")})

    return findings
