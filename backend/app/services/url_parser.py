"""
URL parsing & normalization utilities.

Normalises raw user input into a well-formed URL and extracts the building
blocks the rest of the pipeline needs (scheme, host, domain, registrable
domain, TLD, IP detection, ...).
"""
from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

import tldextract

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_DEFAULT_PORTS = {"http": 80, "https": 443}

# Prefixes that indicate a host is an IPv4/IPv6 literal
_IPV6_BRACKET_RE = re.compile(r"^\[([0-9a-fA-F:]+)\]$")


@dataclass
class ParsedUrl:
    """Structured, validated view of a submitted URL."""

    raw: str
    normalized: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str
    is_ip: bool = False
    ip_version: int | None = None
    sld: str = ""          # second-level domain, e.g. "paypal"
    tld: str = ""          # e.g. "com"
    registrable: str = ""  # e.g. "paypal.com"
    subdomain: str = ""    # e.g. "secure.login"
    url_length: int = 0
    has_https: bool = False
    default_port: bool = True

    def to_dict(self) -> dict:
        return {
            "submitted_url": self.raw,
            "normalized_url": self.normalized,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "is_ip": self.is_ip,
            "ip_version": self.ip_version,
            "domain": self.sld,
            "tld": self.tld,
            "registrable_domain": self.registrable,
            "subdomain": self.subdomain,
            "url_length": self.url_length,
            "has_https": self.has_https,
        }


def normalize_url(raw: str) -> str:
    """Add a scheme when missing and strip surrounding whitespace."""
    url = raw.strip()
    if not url:
        raise ValueError("URL cannot be empty.")
    if not _SCHEME_RE.match(url):
        url = "http://" + url
    return url


def is_ip_address(host: str) -> tuple[bool, int | None]:
    """
    Return (True, version) when `host` is a literal IPv4/IPv6 address.

    IPv6 literals may arrive wrapped in brackets, e.g. ``[::1]:8080``.
    """
    candidate = host
    bracket = _IPV6_BRACKET_RE.match(host)
    if bracket:
        candidate = bracket.group(1)
    try:
        ip = ipaddress.ip_address(candidate)
        return True, ip.version
    except ValueError:
        return False, None


def entropy(text: str) -> float:
    """Shannon entropy (bits per character) of a string."""
    if not text:
        return 0.0
    length = len(text)
    counts: dict[str, int] = {}
    for ch in text.lower():
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def parse_url(raw: str) -> ParsedUrl:
    """Normalise and dissect a URL into its components."""
    normalized = normalize_url(raw)
    parsed = urlparse(normalized)

    # Only http/https are ever fetched — blocks file://, gopher://, data: etc.
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are allowed.")

    host = parsed.hostname or ""
    port = parsed.port

    # Split host from any port info for IP checks
    bare_host = host
    is_ip, ip_version = is_ip_address(bare_host)

    extracted = tldextract.extract(host)
    subdomain = extracted.subdomain or ""
    sld = extracted.domain or ""
    tld = extracted.suffix or ""

    registrable = f"{sld}.{tld}" if sld and tld else (sld or host)

    return ParsedUrl(
        raw=raw,
        normalized=normalized,
        scheme=parsed.scheme.lower(),
        host=host,
        port=port,
        path=parsed.path or "/",
        query=parsed.query,
        fragment=parsed.fragment,
        is_ip=is_ip,
        ip_version=ip_version,
        sld=sld,
        tld=tld,
        registrable=registrable,
        subdomain=subdomain,
        url_length=len(normalized),
        has_https=parsed.scheme.lower() == "https",
        default_port=(port is None or port == _DEFAULT_PORTS.get(parsed.scheme.lower())),
    )
