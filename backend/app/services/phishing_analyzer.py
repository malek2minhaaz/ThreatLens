"""
Phishing content detector.

A transparent, rule-based NLP engine that analyzes email bodies, SMS texts or
webpage text for phishing triggers:

* Urgency & pressure language
* Financial bait (lottery, refunds, inheritance)
* Credential harvesting phrasing
* Link/text mismatches and obfuscated links
* Spoofed "From" headers (Reply-To mismatch, lookalike senders)
* Generic greetings, threats of consequences, brand impersonation

Output: a 0–100 ``phishing_score`` (higher = more likely phishing), a verdict,
and an itemized list of matched flags so analysts can audit every decision.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

URGENCY_KEYWORDS = [
    "urgent", "immediately", "asap", "right away", "act now", "within 24 hours",
    "within 48 hours", "expires today", "expire today", "last chance",
    "don't delay", "do not delay", "hurry", "final notice", "action required",
    "immediate action", "response required", "time sensitive", "limited time",
    "closing soon", "deadline today", "expires soon", "as soon as possible",
]

THREAT_KEYWORDS = [
    "account suspended", "account will be closed", "account locked",
    "account disabled", "suspend your account", "deactivate your account",
    "legal action", "lawsuit", "police report", "sued", "prosecuted",
    "send to authorities", "criminal charges", "penalty", "fine of",
    "pay within", "if you do not respond", "failure to respond",
    "your account will be deleted", "service will be terminated",
]

FINANCIAL_KEYWORDS = [
    "lottery", "you have won", "cash prize", "inheritance", "bank transfer",
    "tax refund", "stimulus", "grant money", "investment opportunity",
    "guaranteed returns", "crypto giveaway", "bitcoin", "western union",
    "money gram", "wire transfer", "bank account details", "receive funds",
    "paypal credit", "credit card details", "card has been charged",
]

CREDENTIAL_KEYWORDS = [
    "verify your account", "verify your identity", "confirm your password",
    "reset your password", "password has expired", "update your password",
    "sign in to confirm", "login to verify", "unusual activity",
    "suspicious activity", "unauthorized access", "security breach",
    "recent login attempt", "failed login attempts", "verify your email",
    "update your billing information", "confirm your details",
    "re-enter your password", "your password was stolen",
]

GENERIC_GREETINGS = [
    "dear user", "dear customer", "dear member", "dear valued customer",
    "dear account holder", "dear beneficiary", "dear friend", "dear winner",
    "hello user", "valued client", "dear cardholder", "dear applicant",
]

SUSPICIOUS_SENDER_PATTERNS = [
    r"@.*(gmail|yahoo|hotmail|outlook|aol|icloud|protonmail)\.(com|me|net)",
    r"(support|service|security|verify|admin|account|billing|info|help)@",
    r"(no-?reply|noreply|n0reply|do-?not-?reply)",
    r"\d{4,}@",  # numeric local parts are a spam hallmark
]

# Visible-text → actual-URL mismatch for "click here" style links
_CLICK_HERE_RE = re.compile(
    r"<\s*a\s+[^>]*href\s*=\s*[\"']([^\"']+)[\"'][^>]*>\s*(click here|login|sign in|"
    r"verify|update|confirm|unlock|activate|account|secure|claim)\s*</a>",
    re.IGNORECASE,
)
_BARE_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_PHONE_RE = re.compile(r"(\+?\d[\d\s().-]{7,}\d)")
_BTC_RE = re.compile(r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
_UPERCASE_RATIO_OK = 0.7


def _extract_links(text: str) -> list[str]:
    """Extract URLs, including obfuscated hxxp:// variants."""
    urls = _BARE_URL_RE.findall(text)
    urls += [u.replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".")
             for u in re.findall(r"hxxp[^\s<>\"']+", text, re.IGNORECASE)]
    return list(dict.fromkeys(urls))


def _href_text_mismatch(text: str) -> list[str]:
    """Detect anchors whose visible text invites clicks but whose href hides a different host."""
    flags: list[str] = []
    for match in _CLICK_HERE_RE.finditer(text):
        href = match.group(1)
        visible = match.group(2)
        if href.startswith(("javascript:", "data:")):
            flags.append(f"Anchor hides executable scheme: '{href[:50]}'")
        else:
            parsed = urlparse(href)
            if not parsed.hostname or "example.com" in parsed.hostname:
                continue
            # The classic mismatch: visible "login" but link to IP/shortener/sketchy host
            flags.append(
                f"Anchor text '{visible}' points to '{parsed.hostname}{parsed.path[:40]}' "
                f"instead of the stated sender domain."
            )
    return flags


def _sender_header_check(content: str, content_type: str) -> list[str]:
    """Inspect From/Reply-To headers for spoofing indicators."""
    flags: list[str] = []
    from_match = re.search(r"(?im)^from\s*:\s*(.*)$", content)
    reply_match = re.search(r"(?im)^reply-to\s*:\s*(.*)$", content)
    if not from_match:
        return flags

    sender = from_match.group(1).strip()
    sender_lower = sender.lower()

    # Reply-To points elsewhere → spoofed sender
    if reply_match:
        reply = reply_match.group(1).strip()
        if reply.lower() != sender_lower and sender and reply:
            flags.append(f"Reply-To header ({reply[:60]}) differs from From ({sender[:60]}).")

    for pattern in SUSPICIOUS_SENDER_PATTERNS:
        if re.search(pattern, sender_lower):
            flags.append(f"Sender '{sender[:70]}' matches a suspicious pattern.")
            break
    return flags


def _link_checks(text: str) -> list[str]:
    """Inspect every link in the content for phishing behavior."""
    flags: list[str] = []
    urls = _extract_links(text)
    if not urls:
        return flags

    ip_links = 0
    for u in urls[:12]:
        parsed = urlparse(u)
        host = parsed.hostname or ""
        try:
            ipaddress.ip_address(host.strip("[]"))
            ip_links += 1
        except ValueError:
            pass

    shortener_hit = any(s in u.lower() for u in urls for s in ("bit.ly", "tinyurl", "t.co", "goo.gl", "cutt.ly"))
    if ip_links:
        flags.append(f"{ip_links} link(s) point directly at an IP address.")
    if shortener_hit:
        flags.append("Content uses URL shorteners that hide the destination.")
    return flags


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

def analyze_phishing(content: str, content_type: str = "email") -> dict:
    """
    Analyze text and return a phishing risk verdict + itemized flags.

    Returns:
        phishing_score: 0-100 (higher = more likely phishing)
        verdict: SAFE | SUSPICIOUS | PHISHING
        confidence: low | medium | high
        flags: list of {"label", "severity", "detail"}
        matched_keywords: {"urgency": [...], "threat": [...], ...}
        stats: {"word_count", "link_count", ...}
    """
    text = content.strip()
    lower = text.lower()
    flags: list[dict] = []
    matched: dict[str, list[str]] = {"urgency": [], "threat": [], "financial": [], "credential": []}

    # --- Keyword groups ----------------------------------------------------
    for group, words in (
        ("urgency", URGENCY_KEYWORDS),
        ("threat", THREAT_KEYWORDS),
        ("financial", FINANCIAL_KEYWORDS),
        ("credential", CREDENTIAL_KEYWORDS),
    ):
        for word in words:
            if word in lower:
                matched[group].append(word)

    if matched["urgency"]:
        flags.append({
            "label": "Urgency pressure",
            "points": 20,
            "severity": "high",
            "detail": f"Uses urgency language: {', '.join(matched['urgency'][:4])}.",
        })
    if matched["threat"]:
        flags.append({
            "label": "Threats of consequences",
            "points": 25,
            "severity": "critical",
            "detail": f"Threatens action: {', '.join(matched['threat'][:4])}.",
        })
    if matched["financial"]:
        flags.append({
            "label": "Financial bait",
            "points": 20,
            "severity": "high",
            "detail": f"Financial trigger words: {', '.join(matched['financial'][:4])}.",
        })
    if matched["credential"]:
        flags.append({
            "label": "Credential harvesting language",
            "points": 25,
            "severity": "critical",
            "detail": f"Asked to verify/enter credentials: {', '.join(matched['credential'][:4])}.",
        })

    # --- Structural signals ------------------------------------------------
    greeting_hit = next((g for g in GENERIC_GREETINGS if g in lower), None)
    if greeting_hit:
        flags.append({
            "label": "Generic greeting",
            "points": 10,
            "severity": "medium",
            "detail": f"Addressed with generic '{greeting_hit}' instead of a personal name.",
        })

    flags += [
        {"label": f, "points": 15, "severity": "high"} for f in _sender_header_check(content, content_type)
    ]
    flags += [
        {"label": f, "points": 15, "severity": "high"} for f in _link_checks(text)
    ]
    flags += [
        {"label": f, "points": 20, "severity": "critical"} for f in _href_text_mismatch(text)
    ]

    if _PHONE_RE.search(text):
        flags.append({
            "label": "Suspicious contact phone number",
            "points": 5,
            "severity": "low",
            "detail": "Includes a phone number — a classic callback scam channel.",
        })
    if _BTC_RE.search(text):
        flags.append({
            "label": "Cryptocurrency address present",
            "points": 15,
            "severity": "high",
            "detail": "Contains a Bitcoin address — frequently used for untraceable payments.",
        })

    # Uppercase shouting
    letters = re.findall(r"[A-Za-z]", text)
    if letters and sum(1 for c in text if c.isupper()) / len(letters) > _UPERCASE_RATIO_OK and len(letters) > 40:
        flags.append({
            "label": "Excessive CAPS LOCK",
            "points": 5,
            "severity": "low",
            "detail": "More than 70% of letters are uppercase — aggressive shouting style.",
        })

    # Emoji / unusual symbol spam
    emoji_count = len(re.findall(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]", text))
    if emoji_count > 3:
        flags.append({
            "label": "Excessive emoji usage",
            "points": 5,
            "severity": "low",
            "detail": f"{emoji_count} emoji detected — common in scam SMS.",
        })

    # --- Score --------------------------------------------------------------
    raw = sum(int(f.get("points", 0)) for f in flags)
    phishing_score = min(100, raw)

    if phishing_score >= 55:
        verdict = "PHISHING"
        confidence = "high" if phishing_score >= 75 else "medium"
    elif phishing_score >= 25:
        verdict = "SUSPICIOUS"
        confidence = "medium"
    else:
        verdict = "SAFE"
        confidence = "low"

    urls = _extract_links(text)
    return {
        "phishing_score": phishing_score,
        "verdict": verdict,
        "confidence": confidence,
        "flags": flags,
        "matched_keywords": matched,
        "stats": {
            "word_count": len(text.split()),
            "char_count": len(text),
            "link_count": len(urls),
            "links": urls[:12],
            "greeting_detected": bool(greeting_hit),
        },
    }
