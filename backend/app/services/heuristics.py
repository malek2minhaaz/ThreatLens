"""
Heuristic analysis module.

Runs fast, deterministic, offline checks over a parsed URL:

* Typosquatting / brand impersonation (Levenshtein distance + brand-in-domain)
* Suspicious / free-for-all TLDs
* High-entropy & randomized-looking domain strings
* Structural red flags (IP-based URLs, '@', length, hyphens, subdomain stacks,
  punycode, non-standard ports, URL shorteners, credential-looking paths)
"""
from __future__ import annotations

import re

from .url_parser import ParsedUrl, entropy

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# TLDs frequently abused by phishing / scam campaigns (free or cheap, no
# identity verification). This is a heuristic — not all .xyz domains are evil.
SUSPICIOUS_TLDS: set[str] = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "loan",
    "men", "win", "bid", "date", "racing", "review", "stream", "download",
    "gdn", "country", "kim", "science", "party", "link", "wang", "xin",
    "monster", "rest", "fit", "accountant", "trade", "website", "site",
    "online", "live", "club", "cyou", "icu", "buzz", "quest", "cam", "mom",
    "lol", "zip", "mov",
}

# Brand names attackers love to impersonate, with their official domains.
POPULAR_BRANDS: dict[str, list[str]] = {
    "google": ["google.com"], "youtube": ["youtube.com"], "gmail": ["gmail.com"],
    "facebook": ["facebook.com"], "instagram": ["instagram.com"], "whatsapp": ["whatsapp.com"],
    "twitter": ["twitter.com", "x.com"], "telegram": ["telegram.org"],
    "tiktok": ["tiktok.com"], "snapchat": ["snapchat.com"],
    "paypal": ["paypal.com"], "amazon": ["amazon.com"], "ebay": ["ebay.com"],
    "apple": ["apple.com"], "icloud": ["icloud.com"], "microsoft": ["microsoft.com"],
    "outlook": ["outlook.com"], "office": ["office.com"], "onedrive": ["onedrive.com"],
    "netflix": ["netflix.com"], "spotify": ["spotify.com"], "twitch": ["twitch.tv"],
    "linkedin": ["linkedin.com"], "github": ["github.com"], "dropbox": ["dropbox.com"],
    "steam": ["steampowered.com"], "epicgames": ["epicgames.com"],
    "coinbase": ["coinbase.com"], "binance": ["binance.com"], "blockchain": ["blockchain.com"],
    "metamask": ["metamask.io"], "chase": ["chase.com"], "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"], "citibank": ["citi.com"],
    "capitalone": ["capitalone.com"], "hsbc": ["hsbc.com"], "barclays": ["barclays.co.uk"],
    "fedex": ["fedex.com"], "ups": ["ups.com"], "usps": ["usps.com"], "dhl": ["dhl.com"],
    "walmart": ["walmart.com"], "target": ["target.com"], "bestbuy": ["bestbuy.com"],
    "airbnb": ["airbnb.com"], "booking": ["booking.com"], "expedia": ["expedia.com"],
    "adobe": ["adobe.com"], "salesforce": ["salesforce.com"], "wordpress": ["wordpress.com"],
}

# URL shorteners / redirect services that hide the real destination.
URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id",
    "v.gd", "soo.gd", "t.ly", "lnkd.in", "x.co", "qr.ae", "cutt.us",
}

# Words that, combined with a brand, scream "credential harvesting".
CREDENTIAL_HINTS: list[str] = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "wallet", "auth", "password", "recover", "unlock", "validate", "billing",
]

_HYPHEN_RE = re.compile(r"-")
_DIGIT_RE = re.compile(r"\d")
_ALNUM_RE = re.compile(r"[a-z0-9]")


# ---------------------------------------------------------------------------
# Distance helpers
# ---------------------------------------------------------------------------

def levenshtein(a: str, b: str, max_dist: int = 2) -> int:
    """Levenshtein distance between two strings, capped at `max_dist + 1`."""
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        if min(curr) > max_dist:
            return max_dist + 1
        prev = curr
    return prev[len(b)]


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_typosquatting(p: ParsedUrl) -> dict | None:
    """Detect brand impersonation via edit distance or brand-in-domain tricks."""
    if not p.sld:
        return None
    target = p.sld.lower()
    hits: list[str] = []
    worst_points = 0  # track the most severe penalty found (most negative)

    for brand, official_domains in POPULAR_BRANDS.items():
        # Official domain → no penalty
        if p.registrable.lower() in official_domains:
            continue

        dist = levenshtein(target, brand)
        if dist == 1 and len(brand) >= 4:
            hits.append(f"'{target}' is 1 character away from '{brand}' (official: {official_domains[0]})")
            worst_points = min(worst_points, -35)
        elif dist == 2 and len(brand) >= 6:
            hits.append(f"'{target}' is 2 characters away from '{brand}' (official: {official_domains[0]})")
            worst_points = min(worst_points, -25)
        elif brand in target:
            # Brand embedded with credential wording: "paypal-secure", "amazon-login"
            embedded_hint = next((h for h in CREDENTIAL_HINTS if h in target), None)
            if embedded_hint and (len(target) - len(brand)) >= len(embedded_hint):
                hits.append(f"'{target}' embeds '{brand}' with credential hint '{embedded_hint}'")
                worst_points = min(worst_points, -25)
            elif len(target) > len(brand) + 2:
                hits.append(f"'{target}' contains '{brand}' plus extra text")
                worst_points = min(worst_points, -20)

    if not hits:
        return None
    return {
        "label": "Typosquatting / brand impersonation",
        "points": worst_points,
        "severity": "critical" if worst_points <= -30 else "high",
        "detail": "; ".join(dict.fromkeys(hits[:3])),  # de-dupe, cap length
    }


def check_suspicious_tld(p: ParsedUrl) -> dict | None:
    if p.tld.lower() in SUSPICIOUS_TLDS:
        return {
            "label": "Suspicious TLD",
            "points": -20,
            "severity": "high",
            "detail": f"TLD '.{p.tld}' is a free/cheap zone heavily abused by phishing campaigns.",
        }
    # Legit brand + wrong TLD: e.g. paypal-support.xyz → flagged by typosquatting too.
    return None


def check_high_entropy(p: ParsedUrl) -> dict | None:
    """Randomized / algorithmically generated domain strings are a strong signal."""
    if not p.sld or len(p.sld) < 8:
        return None
    h = entropy(p.sld)
    digits = len(_DIGIT_RE.findall(p.sld))
    digit_ratio = digits / len(p.sld)

    if h > 4.1 or (h > 3.6 and digit_ratio > 0.45):
        return {
            "label": "High-entropy / randomized domain",
            "points": -15,
            "severity": "medium",
            "detail": (
                f"Domain '{p.sld}' has entropy {h:.2f} bits/char"
                + (f" with {digit_ratio:.0%} digits" if digit_ratio > 0.3 else "")
                + " — typical of algorithmically generated domains."
            ),
        }
    return None


def check_structure(p: ParsedUrl) -> list[dict]:
    """Structural red flags that don't need any external data."""
    findings: list[dict] = []
    url_lower = p.normalized.lower()

    if p.is_ip:
        findings.append({
            "label": "IP address instead of domain",
            "points": -30,
            "severity": "critical",
            "detail": f"URL targets raw IP {p.host} — legitimate services rarely do this.",
        })

    if "@" in url_lower.replace("://", ""):
        findings.append({
            "label": "Deceptive '@' in URL",
            "points": -25,
            "severity": "critical",
            "detail": "The '@' tricks browsers into showing a different domain as the destination.",
        })

    if p.port and not p.default_port:
        findings.append({
            "label": "Non-standard port",
            "points": -10,
            "severity": "medium",
            "detail": f"Uses uncommon port {p.port} — often seen in self-hosted phishing kits.",
        })

    if not p.has_https:
        findings.append({
            "label": "No HTTPS encryption",
            "points": -5,
            "severity": "low",
            "detail": "Served over plain HTTP; credentials would travel unencrypted.",
        })

    if len(p.subdomain.split(".")) >= 3:
        findings.append({
            "label": "Excessive subdomains",
            "points": -10,
            "severity": "medium",
            "detail": f"Subdomain stack '{p.subdomain}' is deep and often used to hide the real host.",
        })

    if p.sld and p.sld.count("-") >= 2 and len(p.sld) >= 6:
        findings.append({
            "label": "Excessive hyphens in domain",
            "points": -10,
            "severity": "medium",
            "detail": f"'{p.sld}' contains {p.sld.count('-')} hyphens — a common squatting pattern.",
        })

    if p.url_length > 75:
        findings.append({
            "label": "Overly long URL",
            "points": -10,
            "severity": "medium",
            "detail": f"{p.url_length} characters — long URLs are used to bury the real destination.",
        })

    if p.query and ("redirect" in p.query.lower() or "url=" in p.query.lower()):
        findings.append({
            "label": "Open-redirect style parameter",
            "points": -10,
            "severity": "medium",
            "detail": f"Query string contains a redirect target: '{p.query[:60]}'.",
        })

    if any(s in p.registrable.lower() for s in URL_SHORTENERS):
        findings.append({
            "label": "URL shortener",
            "points": -15,
            "severity": "medium",
            "detail": f"'{p.registrable}' is a link shortener — the real destination is hidden.",
        })

    # Punycode / internationalized domain abuse
    if "xn--" in p.host.lower():
        findings.append({
            "label": "Punycode/IDN domain",
            "points": -15,
            "severity": "medium",
            "detail": "Internationalized domain can visually mimic ASCII characters (homograph attack).",
        })

    if len(_ALNUM_RE.findall(p.sld or "")) > 0:
        # Digit-heavy SLD (e.g. "google365-2026") tends to be ephemeral squatting
        digits = len(_DIGIT_RE.findall(p.sld))
        if digits >= 4 and len(p.sld) >= 8:
            findings.append({
                "label": "Digit-heavy domain",
                "points": -5,
                "severity": "low",
                "detail": f"'{p.sld}' contains {digits} digits — often generated for mass campaigns.",
            })

    # Credential harvesting in path
    if p.path and p.path.lower() != "/":
        path_tokens = [t for t in re.split(r"[^a-z0-9]", p.path.lower()) if t]
        if any(t in CREDENTIAL_HINTS for t in path_tokens) and p.sld and p.sld not in {
            b for b in POPULAR_BRANDS if p.sld == b
        }:
            findings.append({
                "label": "Credential-related path",
                "points": -10,
                "severity": "medium",
                "detail": f"Path '{p.path[:60]}' contains login/verify wording — common in fake portals.",
            })

    return findings


def run_heuristics(p: ParsedUrl) -> list[dict]:
    """Run all offline heuristic checks; return a list of findings."""
    findings: list[dict] = []
    for check in (check_suspicious_tld, check_high_entropy, check_typosquatting):
        result = check(p)
        if result:
            findings.append(result)
    findings.extend(check_structure(p))
    return findings
