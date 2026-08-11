"""
Metadata inspection module.

Collects passive + active telemetry about a URL:

* WHOIS  → registration date (domain age), registrar, name servers
* SSL    → certificate issuer, validity window, self-signed detection
* HTTP   → status code, response headers, full redirect chain

Every function is defensive: external services (WHOIS servers, target hosts)
are often slow or unreachable, so failures degrade to ``None`` values instead
of raising. The blocking calls are meant to be executed via a thread pool
(see ``scanner.py``) so the API never blocks the event loop.
"""
from __future__ import annotations

import concurrent.futures
import datetime as dt
import ipaddress
import ssl
import socket

import requests
from urllib.parse import urlparse

from ..config import settings
from .url_parser import ParsedUrl

_WHOIS_TIMEOUT = 12
_SSL_TIMEOUT = 8
_HTTP_TIMEOUT = 12
_UA = (
    "Mozilla/5.0 (compatible; ThreatLens/1.0; +https://github.com/threatlens)"
)

# ---------------------------------------------------------------------------
# SSRF guardrails
# ---------------------------------------------------------------------------

def _blocked_target(host: str) -> str | None:
    """
    Return a reason string when `host` must not be contacted, else None.

    Prevents the scanner from becoming an SSRF proxy into internal networks:
    loopback, link-local, RFC1918, CGNAT, multicast, reserved and unspecified
    addresses are refused, both as literal IPs and via DNS resolution.
    """
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return _classify_ip(ip)
    except ValueError:
        pass  # not a literal IP — resolve below

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return "DNS resolution failed for host."

    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        reason = _classify_ip(ip)
        if reason:
            return f"Host resolves to a {reason} address ({ip}) and was blocked."
    return None


def _classify_ip(ip) -> str | None:
    """Describe why an IP is off-limits, or None when it is public."""
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_unspecified:
        return "unspecified"
    return None


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def fetch_whois(p: ParsedUrl) -> dict:
    """
    Query WHOIS for the registrable domain.

    Returns a dict with creation_date, age_days, registrar and nameservers,
    or ``{"available": False, "error": "..."}`` when the lookup fails.

    Compatible with both python-whois APIs in the wild:
      * ``whois.query(domain)`` (classic 0.8.x)
      * ``whois.whois(domain)`` (0.9.x fork, returns a WhoisEntry)
    """
    result: dict = {"available": False, "error": None}
    if not p.registrable or p.is_ip:
        result["error"] = "WHOIS requires a registrable domain (IP addresses have none)."
        return result

    try:
        import whois  # python-whois — optional dependency, degrade if missing

        def _query():
            if hasattr(whois, "query"):
                return whois.query(p.registrable)  # classic API
            return whois.whois(p.registrable)      # 0.9.x fork API

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_query)
            w = future.result(timeout=_WHOIS_TIMEOUT)

        if w is None:
            result["error"] = "No WHOIS record found for domain."
            return result

        created = _first_date(_attr(w, "creation_date"))
        expired = _first_date(_attr(w, "expiration_date"))

        result.update({
            "available": True,
            "registrar": _first_str(_attr(w, "registrar")),
            "creation_date": created.isoformat() if created else None,
            "expiration_date": expired.isoformat() if expired else None,
            "name_servers": _first_str(_attr(w, "name_servers"), many=True)[:5],
            "status": _first_str(_attr(w, "status"), many=True)[:5],
        })

        if created:
            age = dt.datetime.now(dt.timezone.utc) - created
            result["age_days"] = max(0, age.days)
            result["age_display"] = human_age(age.days)
        return result

    except concurrent.futures.TimeoutError:
        result["error"] = "WHOIS lookup timed out."
    except ImportError:
        result["error"] = "python-whois not installed; WHOIS check skipped."
    except Exception as exc:  # noqa: BLE001 - network/WHOIS servers are unreliable
        result["error"] = f"WHOIS lookup failed: {type(exc).__name__}"
    return result


def _attr(obj, name):
    """Read an attribute whether it is a dataclass-like object or a dict."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _first_str(value, many: bool = False):
    """Normalise possibly-list values from whois into str or list[str]."""
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v] if many else (str(value[0]) if value else None)
    return value if value is None else str(value)


def _first_date(value) -> dt.datetime | None:
    """python-whois returns datetimes, ISO strings, or lists of either."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return None
    # 0.9.x fork may return a datetime-subclass object
    if isinstance(value, dt.datetime):
        parsed = value
    elif hasattr(value, "datetime") and isinstance(value.datetime, dt.datetime):
        parsed = value.datetime
    elif isinstance(value, str):
        parsed = _parse_iso(value)
        if parsed is None:
            return None
    else:
        return None
    # naive datetime → assume UTC
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _parse_iso(value: str) -> dt.datetime | None:
    """Best-effort ISO-8601 (and RFC-style) date parsing."""
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d"):
        try:
            return dt.datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def human_age(days: int) -> str:
    if days < 1:
        return "less than a day"
    if days < 30:
        return f"{days} days"
    if days < 365:
        return f"{days // 30} months"
    return f"{days / 365:.1f} years"


def _x509_name_attr(name, attr: str, default: str = "") -> str:
    """
    Pull a single attribute (e.g. organizationName) out of the nested X509
    relative-name tuple returned by ``getpeercert()``.

    Structure: ((('organizationName', 'Let's Encrypt'),), (...), ...)
    """
    if not isinstance(name, (list, tuple)):
        return default
    for entry in name:
        if isinstance(entry, (list, tuple)) and entry:
            pair = entry[0]
            if isinstance(pair, (list, tuple)) and len(pair) >= 2 and pair[0] == attr:
                return str(pair[1])
    return default


# ---------------------------------------------------------------------------
# SSL certificate
# ---------------------------------------------------------------------------

def fetch_ssl(p: ParsedUrl) -> dict:
    """Inspect the TLS certificate presented by the host (port 443)."""
    result: dict = {"available": False, "error": None}
    host = p.host
    if not host:
        result["error"] = "No host to inspect."
        return result
    if (blocked := _blocked_target(host)) is not None:
        result["error"] = f"Refused internal target: {blocked}"
        return result

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=_SSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        if not cert:
            result["error"] = "No certificate presented."
            return result

        not_before = dt.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        not_after = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        now = dt.datetime.now(dt.timezone.utc)
        days_remaining = (not_after - now).days

        result.update({
            "available": True,
            "valid": not_before <= now <= not_after,
            "issuer": _x509_name_attr(cert.get("issuer", ()), "organizationName", "Unknown CA"),
            "subject": _x509_name_attr(cert.get("subject", ()), "commonName", host),
            "valid_from": not_before.isoformat(),
            "valid_to": not_after.isoformat(),
            "days_remaining": days_remaining,
            "san": cert.get("subjectAltName", []),
        })
        return result
    except ssl.SSLCertVerificationError as exc:
        result.update({"available": True, "valid": False, "error": f"Certificate verification failed: {type(exc).__name__}"})
        return result
    except (ssl.SSLError, socket.timeout, OSError, ValueError) as exc:
        result["error"] = f"TLS handshake failed: {type(exc).__name__}"
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"SSL inspection failed: {type(exc).__name__}"
    return result


# ---------------------------------------------------------------------------
# HTTP / redirects
# ---------------------------------------------------------------------------

def fetch_http(p: ParsedUrl) -> dict:
    """Fetch headers + follow redirects; capture status, chain and final host."""
    result: dict = {"available": False, "error": None}
    if (blocked := _blocked_target(p.host)) is not None:
        result["error"] = f"Refused internal target: {blocked}"
        return result
    try:
        # stream=True + immediate close → we only consume the headers, never
        # download the body (a malicious URL could point at a multi-GB file).
        resp = requests.get(
            p.normalized,
            timeout=_HTTP_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": _UA, "Accept": "*/*"},
            verify=True,
            stream=True,
        )
        chain = [h.url for h in resp.history] + [resp.url]
        final_host = urlparse(resp.url).hostname or p.host
        redirect_blocked = (
            final_host != p.host and _blocked_target(final_host) is not None
        )
        result.update({
            "available": True,
            "status_code": resp.status_code,
            "final_url": resp.url,
            "final_host": final_host,
            "redirect_count": len(resp.history),
            "redirect_chain": chain,
            "server_header": resp.headers.get("Server"),
            "content_type": resp.headers.get("Content-Type"),
            "final_domain_changed": final_host != p.host,
            "redirect_to_internal": redirect_blocked,
        })
        resp.close()
        return result
    except requests.exceptions.SSLError:
        result["error"] = "SSL verification failed while fetching the URL."
    except requests.exceptions.TooManyRedirects:
        result.update({"available": True, "error": "too_many_redirects", "redirect_count": 10,
                       "final_url": p.normalized, "final_host": p.host, "final_domain_changed": False})
    except requests.exceptions.Timeout:
        result["error"] = "HTTP request timed out."
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection failed — host unreachable."
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"HTTP request failed: {type(exc).__name__}"
    return result


# ---------------------------------------------------------------------------
# Domain-age findings used by the risk engine
# ---------------------------------------------------------------------------

def domain_age_finding(whois: dict) -> dict | None:
    """Translate WHOIS age into a risk finding."""
    if not whois.get("available") or whois.get("age_days") is None:
        return {
            "label": "Domain age unknown",
            "points": 0,
            "severity": "info",
            "detail": "WHOIS data unavailable — this check was skipped.",
        }
    days = whois["age_days"]
    if days < 14:
        return {
            "label": "Domain registered very recently",
            "points": -40,
            "severity": "critical",
            "detail": f"Domain is {whois.get('age_display')} old (< 14 days) — new domains are high-risk.",
        }
    if days < 90:
        return {
            "label": "Young domain",
            "points": -20,
            "severity": "high",
            "detail": f"Domain is {whois.get('age_display')} old (< 3 months).",
        }
    if days < 365:
        return {
            "label": "Relatively new domain",
            "points": -10,
            "severity": "medium",
            "detail": f"Domain is {whois.get('age_display')} old (< 1 year).",
        }
    if days < 3 * 365:
        return {
            "label": "Established domain",
            "points": 0,
            "severity": "info",
            "detail": f"Domain is {whois.get('age_display')} old (1–3 years).",
        }
    return {
        "label": "Long-standing domain",
        "points": 5,
        "severity": "positive",
        "detail": f"Domain is {whois.get('age_display')} old (> 3 years) — age lends credibility.",
    }


def ssl_finding(ssl_info: dict, p: ParsedUrl) -> dict | None:
    """Translate SSL inspection results into a risk finding."""
    if not p.has_https:
        return {
            "label": "Site not served over HTTPS",
            "points": -5,
            "severity": "low",
            "detail": "No TLS inspection performed because the URL uses http://.",
        }
    if not ssl_info.get("available"):
        return {
            "label": "TLS certificate not verifiable",
            "points": -20,
            "severity": "high",
            "detail": ssl_info.get("error") or "No certificate found on port 443.",
        }
    if not ssl_info.get("valid"):
        return {
            "label": "Invalid TLS certificate",
            "points": -30,
            "severity": "critical",
            "detail": ssl_info.get("error") or "Certificate failed validation.",
        }
    days = ssl_info.get("days_remaining", 0)
    if days < 14:
        return {
            "label": "TLS certificate expiring soon",
            "points": -10,
            "severity": "medium",
            "detail": f"Certificate expires in {days} days.",
        }
    return {
        "label": "Valid TLS certificate",
        "points": 10,
        "severity": "positive",
        "detail": f"Certificate issued by {ssl_info.get('issuer')}, expires in {days} days.",
    }


def http_finding(http: dict) -> list[dict]:
    """Translate HTTP/redirect results into risk findings (always a list)."""
    if not http.get("available"):
        return [{
            "label": "HTTP probe failed",
            "points": 0,
            "severity": "info",
            "detail": http.get("error") or "The URL could not be fetched.",
        }]
    findings: list[dict] = []
    if http.get("final_domain_changed"):
        findings.append({
            "label": "Redirects to a different domain",
            "points": -20,
            "severity": "high",
            "detail": f"'{http.get('final_host')}' differs from the submitted host — verify the destination.",
        })
    if http.get("redirect_to_internal"):
        findings.append({
            "label": "Redirect chain targets an internal address",
            "points": -50,
            "severity": "critical",
            "detail": "The redirect destination resolves to a private/internal address — the URL is likely malicious or an open redirect.",
        })
    if http.get("redirect_count", 0) >= 3:
        findings.append({
            "label": "Long redirect chain",
            "points": -10,
            "severity": "medium",
            "detail": f"{http['redirect_count']} redirects observed before final destination.",
        })
    status = http.get("status_code")
    if status and status >= 400:
        findings.append({
            "label": f"HTTP {status} response",
            "points": -5,
            "severity": "low",
            "detail": f"Target responded with status {status}.",
        })
    if not findings:
        findings.append({
            "label": "Reachable HTTP endpoint",
            "points": 0,
            "severity": "info",
            "detail": f"Responded HTTP {status} with {http.get('redirect_count', 0)} redirect(s).",
        })
    return findings
