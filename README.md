# 🛡️ ThreatLens — Threat Detection & URL Scanner

An end-to-end threat detection platform that scans URLs, analyzes phishing
content, and produces a **unified 0–100 risk score** (100 = safe, 0 = dangerous)
with a fully itemized breakdown.

| Layer        | Technology                          |
| ------------ | ----------------------------------- |
| **Backend**  | Python 3.11+ · FastAPI · Uvicorn    |
| **Frontend** | HTML5 · CSS3 · Vanilla JavaScript (multi-page, card-based UI) |
| **Database** | SQLite (SQLAlchemy ORM)             |
| **Auth**     | Account system, PBKDF2 password hashing, DB-backed bearer tokens |
| **Threat intel** | VirusTotal · Google Safe Browsing · PhishTank (all optional) |

**Dashboard pages:** `login.html` · `register.html` · `scanner.html` · `phishing.html` (5-tool phishing kit) · `learn.html` (examples + quiz) · `history.html` · `intel.html` · `profile.html` — each section is a standalone HTML page with a shared JS-injected header/footer. `index.html` is an entry splash that routes you to login or the scanner.

---

## 1. System Architecture

```
┌────────────────────┐        ┌───────────────────────────────────────────────────────┐
│   Browser (SPA)    │  HTTP  │                     FastAPI Backend                     │
│  HTML/CSS/JS app   │ ─────► │                                                       │
│  (served at /)     │        │  POST /api/scan-url                                    │
└────────────────────┘        │        │                                              │
                              │        ▼                                              │
                              │  ┌─────────────────────────────┐                     │
                              │  │      Scan Pipeline          │                     │
                              │  │                             │                     │
                              │  │  1. Parse & Normalize       │ ──► tldextract       │
                              │  │  2. Heuristics (offline)    │ ──► typosquatting,   │
                              │  │     entropy, TLD, IP, flags │     Levenshtein      │
                              │  │  3. Metadata (parallel ⚡)   │ ──► WHOIS (thread),  │
                              │  │     · WHOIS domain age      │     SSL, HTTP +      │
                              │  │     · SSL certificate       │     redirect chain   │
                              │  │     · HTTP status/redirects │                     │
                              │  │  4. Threat Intelligence     │ ──► VirusTotal        │
                              │  │     (skipped without keys)  │     Safe Browsing    │
                              │  │                             │     PhishTank        │
                              │  │  5. Risk Scoring Engine     │ ──► 0-100 score +    │
                              │  │                             │     itemized findings│
                              │  └──────────────┬──────────────┘                     │
                              │                 │                                     │
                              │                 ▼                                     │
                              │          ┌──────────────┐      ┌──────────────────┐   │
                              │          │  SQLite (DB) │◄────►│ Scan history log │   │
                              │          └──────────────┘      └──────────────────┘   │
                              │                                                       │
                              │  POST /api/analyze-phishing                            │
                              │        │                                               │
                              │        ▼                                               │
                              │  Rule-based NLP: urgency keywords, spoofed headers,    │
                              │  link/text mismatch, credential bait → 0-100 score    │
                              └───────────────────────────────────────────────────────┘
```

**Key design decisions**

1. **Resilience first** — every external subsystem (WHOIS, SSL, HTTP, all three
   threat-intel feeds) is wrapped in try/except and degrades to an *info*
   finding. A scan never fails because a WHOIS server is slow or an API key is
   missing.
2. **Non-blocking pipeline** — the API is async; blocking I/O (WHOIS, SSL
   handshake, HTTP fetch) runs in a thread pool and executes in parallel.
3. **Transparent scoring** — the risk engine is a simple additive model. Every
   deduction is returned to the client with a human-readable reason, so
   analysts can audit *why* a URL scored the way it did.
4. **Optional keys** — ThreatLens works with **zero API keys**. Configure any
   of VirusTotal / Safe Browsing / PhishTank in `.env` to enrich results.

### Scoring model (100 = safe, 0 = dangerous)

| Signal                                  | Points |
| --------------------------------------- | ------ |
| Listed in Safe Browsing / PhishTank     | −100   |
| Multiple AV engines flag (≥3)           | −80    |
| Flagged by ≥1 AV engine                 | −60    |
| Domain age < 14 days                    | −40    |
| Typosquatting (1 char off a brand)      | −35    |
| IP-based URL / invalid TLS cert         | −30    |
| Young domain (< 90 days)                | −20    |
| Suspicious TLD / different-domain redirect / no TLS | −20   |
| High-entropy domain / URL shortener     | −15    |
| Redirect chain ≥ 3 / excessive subdomains / hyphens | −10 |
| Valid TLS certificate                   | +10    |
| Domain age > 3 years                    | +5     |

**Verdict thresholds:** `≥85 SAFE` · `70–84 LOW RISK` · `40–69 SUSPICIOUS` · `<40 DANGEROUS`

---

## 2. Project Structure

```
ThreatLens/
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI app, static mount, startup DB init
│   │   ├── config.py               # env-based settings (API keys, timeouts)
│   │   ├── database.py             # SQLAlchemy engine / session
│   │   ├── models.py               # ORM models (scans, phishing_analyses)
│   │   ├── schemas.py              # Pydantic request models
│   │   ├── routers/
│   │   │   ├── scanner.py          # POST /api/scan-url
│   │   │   ├── phishing.py         # POST /api/analyze-phishing
│   │   │   └── history.py          # GET /api/history, /api/history/{id}, /api/phishing-history
│   │   └── services/
│   │       ├── scanner.py          # pipeline orchestrator (parallel metadata)
│   │       ├── url_parser.py       # normalization + parsing (tldextract)
│   │       ├── heuristics.py       # typosquatting, entropy, TLD, structural flags
│   │       ├── metadata.py         # WHOIS, SSL cert, HTTP + redirect chain
│   │       ├── threat_intel.py     # VirusTotal / Safe Browsing / PhishTank
│   │       ├── phishing_analyzer.py# rule-based NLP content detector
│   │       └── risk_scoring.py     # additive 0-100 scoring engine
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── index.html                  # entry splash → routes to login / scanner
│   ├── login.html · register.html  # auth pages
│   ├── scanner.html                # URL scanner + full report view
│   ├── phishing.html               # phishing content analyzer
│   ├── history.html                # scan/phishing history (card grid, search & filters)
│   ├── intel.html                  # threat-intel providers + verdict feed (cards)
│   ├── profile.html                # account stats & settings
│   └── static/
│       ├── css/style.css           # dark cyber theme (+ card views, toolbars)
│       └── js/
│           ├── app.js              # shared shell (header/footer), auth gating, API client
│           └── pages/              # per-page logic: auth, scanner, phishing, history, intel, profile
└── README.md
```

---

## 3. Setup & Running Locally

### Prerequisites
- Python **3.11+**
- (Recommended) a free [VirusTotal](https://www.virustotal.com/gui/join-us) API key

### Steps

```bash
# 1. Create & activate a virtual environment
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows (Git Bash): source .venv/Scripts/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment (optional but recommended)
cp .env.example .env
#    edit .env and add your threat-intel keys, e.g.:
#    VIRUSTOTAL_API_KEY=your_key_here

# 4. Run the server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Then open **http://localhost:8000** — you'll land on the login page. Register an
account (or use the demo credentials you create) to reach the dashboard.
Interactive API docs are at **http://localhost:8000/api/docs** (add a bearer
token via the Authorize button to exercise protected endpoints).

> The SQLite database (`threatshield.db`) is created automatically on first run.
> Existing databases are migrated in place (a `user_id` column is added).

---

## 4. API Reference

### `POST /api/scan-url`
Scans a URL end-to-end. Returns the risk report.

```bash
curl -X POST http://localhost:8000/api/scan-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-account-verify.tk/login"}'
```

**Response highlights**
```jsonc
{
  "scan_id": 1,
  "request": { "normalized_url": "...", "domain": "paypal-account-verify", "tld": "tk", ... },
  "risk_score": 25,
  "verdict": "DANGEROUS",
  "risk_level": "critical",
  "findings": [
    { "category": "Heuristics", "label": "Typosquatting / brand impersonation",
      "points": -25, "severity": "high", "detail": "..." },
    { "category": "Metadata", "label": "Domain registered very recently",
      "points": -40, "severity": "critical", "detail": "Domain is 3 days old (< 14 days)..." }
  ],
  "category_totals": { "Heuristics": -75, "Metadata": -40 },
  "metadata": { "whois": {...}, "ssl": {...}, "http": {...} },
  "threat_intel": { "virustotal": {...}, "google_safe_browsing": {...}, "phishtank": {...} },
  "providers": { "virustotal": true, "google_safe_browsing": false, "phishtank": false },
  "duration_ms": 2140
}
```

### Authentication

All endpoints except `POST /api/auth/register`, `POST /api/auth/login` and
`GET /api/health` require a bearer token. Login is limited to 10 attempts /
15 min per IP and registration to 5 / hour (in-memory, per process):

```bash
# Register (returns a token)
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alex", "email": "alex@mail.com", "password": "ThreatLens!2026"}'

# Login (username or email)
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier": "alex", "password": "ThreatLens!2026"}'

# Use the token on every request
curl -X POST http://localhost:8000/api/scan-url \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

| Method | Path | Description |
| ------ | ---- | ----------- |
| POST | `/api/auth/register` | Create an account → `{token, user}` |
| POST | `/api/auth/login` | Sign in (username **or** email) → `{token, user}` |
| POST | `/api/auth/logout` | Invalidate the current token |
| GET | `/api/auth/me` | Current profile |
| PUT | `/api/auth/me` | Update display name / email |
| POST | `/api/auth/change-password` | Change password (invalidates all sessions) |
| GET | `/api/users/stats` | Per-user stats (scans, scores, verdict distribution) |
| GET | `/api/users/report` | Full activity report (profile + summary + scans + phishing) for HTML/CSV/JSON downloads |
| GET | `/api/intel/status` | Which threat-intel providers are configured |
| GET | `/api/intel/feed` | Recent threat-intel verdicts from your scans |
| GET | `/api/admin/stats` | **Admin** — global platform overview |
| GET | `/api/admin/users` | **Admin** — all users with per-user counts |
| PATCH | `/api/admin/users/{id}` | **Admin** — promote/demote or rename a user |
| DELETE | `/api/admin/users/{id}` | **Admin** — delete a user and all their data |
| GET | `/api/admin/scans` | **Admin** — recent scans from every user |

### Admin panel

To make yourself (or any user) an admin, add their username to `backend/.env`
and restart the server — the account is promoted automatically on startup:

```bash
# backend/.env
ADMIN_USERNAME=alex
```

Once promoted, an **Admin** link appears in the dashboard nav and
`admin.html` shows global stats, user management (promote/demote/delete)
and every user's recent scans. All admin endpoints return `403` for
non-admins.

A built-in admin account is also provisioned for local use:

| Username  | Password   |
| --------- | ---------- |
| `admin024` | `admin2412` |

Admins sign in on the **same login page** as everyone else — after login they
are redirected to `admin.html`, while regular users go to the scanner.

### `POST /api/analyze-phishing`
Analyzes email / SMS / page text with the rule-based NLP engine.

```bash
curl -X POST http://localhost:8000/api/analyze-phishing \
  -H "Content-Type: application/json" \
  -d '{"content_type": "email", "content": "URGENT: your account will be closed..."}'
```

Returns `phishing_score` (0–100, higher = more likely phishing), `verdict`
(`SAFE | SUSPICIOUS | PHISHING`), `confidence`, itemized `flags`, matched
keyword groups, and any `watchlist_matches`.

### Phishing toolkit

Extra phishing tools live in the **Phishing Lab** page (tabs) and the
**Learn** page:

| Method | Path | Description |
| ------ | ---- | ----------- |
| POST | `/api/phishing/inspect` | Message-level analysis **plus a full URL scan of every embedded link** (up to 8, in parallel; results persisted to history) |
| POST | `/api/phishing/headers` | Parse raw email headers → spoofing flags (Reply-To/Return-Path mismatch, SPF/DKIM/DMARC, relay chains, IDN tricks) |
| POST | `/api/phishing/sender-check` | Reputation check on a sender's domain (typosquatting, TLD, entropy, WHOIS age) |
| GET | `/api/phishing/trends` | 30-day phishing score trend + top tactics for the user (profile chart) |
| GET | `/api/watchlist` | List the user's saved phishing indicators |
| POST | `/api/watchlist` | Add a `{kind: sender|domain|url, value, note?}` entry |
| DELETE | `/api/watchlist/{id}` | Remove an entry |
| POST | `/api/watchlist/check` | Match text against the watchlist (also auto-surfaced in analyses/inspections) |

Watchlist matches are shown automatically whenever a saved sender/domain/URL
appears in a content analysis, link inspection or sender check.

### Other endpoints
| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/api/history?limit=20` | Recent URL scans |
| GET | `/api/history/{id}` | Full persisted scan report |
| GET | `/api/phishing-history` | Recent phishing analyses |
| GET | `/api/health` | Service health |

---

## 5. Deployment Notes

**Production considerations**
- Run behind a reverse proxy (nginx/Caddy) with TLS termination.
- Uvicorn workers: `uvicorn app.main:app --workers 4` (the scanner is
  async + thread-pooled, so workers scale well).
- **Tighten CORS**: change `allow_origins=["*"]` in `backend/app/main.py` to
  your dashboard origin.
- Swap SQLite → Postgres by changing `DATABASE_URL` in `.env`
  (`postgresql+psycopg2://user:pass@host/db`), no code changes needed.
- Add rate limiting (e.g. `slowapi`) in front of `/api/scan-url` to prevent
  abuse of outbound requests.

**SSRF hardening (built-in, but understand the limits)**
- The scanner refuses to contact loopback, link-local, RFC1918/private,
  multicast and reserved addresses (both literal IPs and DNS-resolved hosts),
  and only ever fetches `http`/`https` URLs. See `_blocked_target()` in
  `backend/app/services/metadata.py`.
- If you run this publicly, put it behind an allow-listed egress proxy and add
  auth, so attackers can't use `/api/scan-url` as a general-purpose fetcher.

**Docker (optional)**
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend /app/backend
COPY frontend /app/frontend
WORKDIR /app/backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 6. Roadmap Ideas

- Machine-learning classifier (fine-tuned DistilBERT) layered on the rule
  engine for phishing content.
- IP reputation feeds (AbuseIPDB, AlienVault OTX).
- Scheduled re-scans + alerting (webhooks/Slack).
- CSV/PDF report export.

---

*Built for education & defensive use. Always verify suspicious links through
official channels before taking action.*
