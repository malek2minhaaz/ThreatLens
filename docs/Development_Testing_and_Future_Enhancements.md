# ThreatLens - Development, Testing and Future Enhancements

**Analysed implementation:** `backend/app/`, `frontend/`, `extension/` and `backend/test_e2e.py` on 4 October 2026. This chapter continues the report after *System Design and Database Development* (chapters 6-9) and distinguishes behaviour that is implemented and verified from behaviour that is designed but not yet wired.

## 10. Development Phase

### 10.1 Start project coding

Development followed an incremental, layer-by-layer process. Each backend capability was completed and exercised through the API before the matching screen was built, so the user interface was always driven by a working endpoint rather than a mock.

| Step | Activity | Deliverable |
|---|---|---|
| 1 | Environment setup | Python 3.11+ virtual environment, `backend/requirements.txt` installed, `.env` created from `.env.example`. |
| 2 | Project scaffolding | `backend/app` package with `main.py`, `config.py`, `database.py`, `models.py`, `schemas.py`; `frontend/` and `extension/` trees. |
| 3 | Data layer first | SQLAlchemy ORM models and the SQLite database, created automatically at startup. |
| 4 | API-first build | Authentication, then the URL scanner, then phishing analysis, then history, tools, admin and reporting routes. |
| 5 | Interface build | Static dashboard pages consuming the finished endpoints, followed by the Chrome extension. |
| 6 | Hardening | Input validation, rate limiting, SSRF guards, audit logging and the end-to-end test suite. |

**Development environment and toolchain.**

| Item | Choice |
|---|---|
| Language | Python 3.11+ (backend), JavaScript ES2020+ (frontend and extension) |
| Web framework | FastAPI with Uvicorn |
| Data layer | SQLAlchemy 2 ORM; SQLite by default, PostgreSQL via `DATABASE_URL` |
| Validation | Pydantic 2 models in `schemas.py` |
| Key libraries | `tldextract`, `python-whois`, `requests`, `python-dotenv`, `email-validator` |
| Frontend | HTML5, CSS3 and vanilla JavaScript (no build step, no framework) |
| Extension | Chrome Manifest V3 |
| Version control | Git; single `main` branch with feature work reviewed as commits |

**Coding conventions applied.**

1. **Separation of concerns** - routers validate HTTP input and enforce authorization; services hold detection logic; the ORM isolates persistence.
2. **Type hints everywhere** - `from __future__ import annotations` plus Pydantic models on every request body.
3. **Fail-soft external calls** - every WHOIS, TLS, HTTP and threat-intel call is wrapped so a provider outage becomes an informational finding, never a failed scan.
4. **Single settings object** - all configuration and secrets are read once through `config.py` and never hard-coded.
5. **Comments explain intent** - docstrings and inline notes state *why* (for example the SQLite `ALTER TABLE` foreign-key limitation), not what the code already says.

### 10.2 User interface and screen layout design

The dashboard is a multi-page application. Each screen is a standalone HTML file with a shared JavaScript-injected header and footer (`frontend/static/js/app.js`), a dark cyber theme in `frontend/static/css/style.css`, and a card-based layout: a toolbar/action card at the top, controls, then a results card with a score ring, verdict badge and itemised findings.

| Screen | File | Purpose | Key layout elements |
|---|---|---|---|
| Entry splash | `index.html` | Routes the visitor to login or the scanner | Hero panel with primary call-to-action buttons |
| Login | `login.html` | Username/email and password sign-in | Centred auth card, inline validation, error banner |
| Register | `register.html` | Create an account | Auth card with username, email and password rules |
| Scanner | `scanner.html` | Single and bulk URL scanning with full report | URL input toolbar, score ring, verdict badge, colour-coded finding cards, bulk-results table with CSV export |
| Phishing Lab | `phishing.html` | Five-tool phishing kit in tabs | Tabs: content analysis, link inspection, header analysis, sender reputation, watchlist; per-tool result cards |
| Learn | `learn.html` | Security education: worked examples and a quiz | Example cards plus an interactive quiz with scoring |
| History | `history.html` | Past scans and analyses | Card grid with search, verdict filters and detail expansion |
| Threat Intel | `intel.html` | Configured providers and verdict feed | Provider status cards plus a live verdict feed |
| Profile | `profile.html` | Account details, activity stats and trends | Profile form, statistics tiles and a 30-day trend view |
| Admin | `admin.html` | Platform administration | Global stat tiles, user table (promote/demote/delete) and cross-user recent scans |

**Interaction design principles.**

- **Progressive disclosure** - the score and verdict are shown first; the itemised findings, raw metadata and threat-intel sections expand only when opened, keeping the first view readable.
- **Consistent feedback states** - every action shows a loading state, a success result or an explicit error message; a scan that partially degrades (for example WHOIS timeout) still renders with the available signals.
- **Accessible colour semantics** - verdicts use green/amber/orange/red in addition to text labels so colour is never the only signal.
- **Responsive layout** - the card and grid layout reflows from desktop to mobile without JavaScript framework dependencies.

### 10.3 Core functionalities and modules

**Backend services (`backend/app/services/`).**

| Module | Responsibility |
|---|---|
| `scanner.py` | Pipeline orchestrator: parse, heuristics, parallel metadata, threat intel, scoring, persistence. |
| `url_parser.py` | URL normalization and parsing (scheme, registrable domain, subdomains, TLD) using `tldextract`. |
| `heuristics.py` | Offline detection: typosquatting against a brand list (Levenshtein), Shannon entropy, suspicious TLDs, IP-literal URLs, hyphens and subdomain counts. |
| `metadata.py` | WHOIS domain age, TLS certificate inspection and HTTP status plus redirect chain; runs concurrently in a thread pool and enforces SSRF blocking. |
| `threat_intel.py` | Optional VirusTotal, Google Safe Browsing and PhishTank clients; each degrades gracefully when unconfigured. |
| `risk_scoring.py` | Additive 0-100 safety score; every deduction is returned with a human-readable reason and severity. |
| `phishing_analyzer.py` | Rule-based content engine: urgency, threats, financial bait, credential requests, header anomalies and risky links. |
| `watchlist.py` | Matches submitted content against the user's saved senders, domains and URLs. |
| `security.py` | PBKDF2-HMAC-SHA256 password hashing and token generation/validation. |
| `rate_limit.py` | In-memory sliding-window limiter for login, registration, scan and tool routes. |

**API modules (`backend/app/routers/`).** Ten routers expose 33 endpoints: `auth`, `users`, `intel`, `scanner`, `phishing`, `tools`, `history`, `admin`, `audit` and `webhooks`. Highlights:

- **Authentication** - register, login (username or email), logout, profile read/update and password change; all protected routes require a bearer token.
- **Scanning** - `POST /api/scan-url` for a single URL and `POST /api/scan-bulk` for up to 25 URLs with bounded parallelism and per-URL failure isolation.
- **Phishing** - content analysis plus link inspection, raw-header spoofing analysis, sender reputation and a personal watchlist.
- **Reporting** - per-user statistics, a consolidated activity report (HTML/CSV/JSON), threat-intel status and feed, and admin statistics, user management and cross-user scans.

**Frontend modules.** Shared shell, authentication gating and API client in `app.js`, with per-page controllers under `frontend/static/js/pages/` (`auth`, `scanner`, `phishing`, `phishing-tools`, `history`, `intel`, `learn`, `profile`, `admin`).

**Browser extension.** A Manifest V3 extension (`extension/`) for in-browser scanning: toolbar popup with a score ring, context-menu scans for the page/link/selection, a colour-coded toolbar badge and full-report tabs.

### 10.4 System integration

Integration was performed from the outside in: external providers first, then the internal pipeline, then the clients.

| Integration | Mechanism | Failure behaviour |
|---|---|---|
| Frontend to API | `fetch` with a bearer token from `localStorage`; JSON request/response | Token expiry (401) re-routes the user to login |
| Extension to API | Same REST API via the configured server URL and stored credentials | Badge shows an error state; settings validate on sign-in |
| Scanner pipeline | Async orchestrator; blocking WHOIS/TLS/HTTP work dispatched to a thread pool and run in parallel | Per-signal timeout; full scan capped by `MAX_SCAN_SECONDS` |
| Threat intel | Optional HTTP clients selected by the presence of API keys | Unconfigured or failing providers are marked unavailable and skipped |
| Persistence | SQLAlchemy session per request; scan and analysis reports saved as JSON snapshots | Report is still returned if history persistence is the only failure |
| Admin and audit | Admin routes guarded by an admin dependency; actions written to `audit_log` | Non-admins receive `403`; audit failure never blocks the action |

**End-to-end request path.**

`dashboard / extension -> FastAPI -> authentication -> scan or analysis service -> SQLAlchemy -> SQLite/PostgreSQL -> JSON response`

A URL scan normalizes the URL, applies offline heuristics, runs WHOIS, TLS and HTTP inspection in parallel, calls any configured threat-intel providers, combines all findings into the 0-100 safety score and verdict, persists the report and returns the full itemised breakdown.

**Integration notes carried forward.** The design document records items to resolve before production finalisation: bulk scanning does not yet charge the per-user limiter per URL; SQLite foreign keys are not enabled per connection; the declared anonymised-history delete policy and the admin delete route disagree; and the `api_keys` and `webhooks` tables have CRUD routes but are not yet invoked by the scan flow. These are treated as integration debt rather than hidden, and are tracked again in section 12.

## 11. Testing and Report Generation

### 11.1 Software testing using test cases

Testing combined an automated end-to-end suite with structured manual test cases. The automated suite is `backend/test_e2e.py`, a dependency-free smoke test that exercises the running server over HTTP using `urllib`. It registers a unique throwaway user, then drives the full auth, scanner, phishing, history, reporting and session lifecycle and asserts on responses with a `check()` helper; any failed assertion exits non-zero.

**Automated end-to-end test cases.**

| ID | Test case | Input | Expected result |
|---|---|---|---|
| TC-01 | Register new account | Unique username, email, strong password | `200` with token and matching user record |
| TC-02 | Reject duplicate registration | Same username/email again | `409 Conflict` |
| TC-03 | Login by email | Email plus correct password | `200` with a fresh token |
| TC-04 | Reject wrong password | Username plus wrong password | `401 Unauthorized` |
| TC-05 | Fetch own profile | `GET /api/auth/me` with token | `200` with the registered email and username |
| TC-06 | Reject unauthenticated request | `GET /api/history` with no token | `401 Unauthorized` |
| TC-07 | Scan a safe URL | `https://example.com` | Score `>= 85`, verdict `SAFE` |
| TC-08 | Safely resolved metadata | Same scan | WHOIS available, TLS valid, HTTP `200` |
| TC-09 | Persist scan with owner | Same scan | Numeric `scan_id` returned and stored against the user |
| TC-10 | Scan a typosquat URL | `http://paypal-account-verify.tk/login` | Score `< 40`, verdict `DANGEROUS` |
| TC-11 | Detect typosquatting | Same scan | A finding labelled "Typosquat" is present |
| TC-12 | Detect suspicious TLD | Same scan | A finding labelled "Suspicious TLD" is present |
| TC-13 | Block SSRF target | `http://127.0.0.1:8000/api/health` | Loopback/internal address refused before fetching |
| TC-14 | Flag a phishing email | Urgency + credential bait + spoofed sender | Verdict `PHISHING` |
| TC-15 | Do not flag a benign message | Order confirmation SMS | Verdict `SAFE` |
| TC-16 | List user history | `GET /api/history?limit=10` | `total >= 2`, rows scoped to the user |
| TC-17 | Aggregate user statistics | `GET /api/users/stats` | Scan and analysis counts match activity |
| TC-18 | Threat-intel status | `GET /api/intel/status` | Keys exactly `virustotal`, `google_safe_browsing`, `phishtank` |
| TC-19 | Threat-intel feed | `GET /api/intel/feed?limit=10` | `total >= 2` with a `feed` array |
| TC-20 | Update profile | `PUT /api/auth/me` with a display name | `200`, value persisted on re-read |
| TC-21 | Change password revokes sessions | Correct current password plus a new one | Old token now returns `401` |
| TC-22 | Login with new password | Username plus new password | `200` with a token |
| TC-23 | Logout invalidates token | `POST /api/auth/logout` | Reusing the token returns `401` |

**Manual and exploratory test cases.**

| ID | Area | Test case | Expected result |
|---|---|---|---|
| MT-01 | Input validation | Submit an empty URL, a non-URL string and an over-length URL | Validation error, no scan performed |
| MT-02 | Bulk scan | Scan a mixed batch including one invalid URL | Valid URLs return results; invalid entry reports its own error; batch does not fail |
| MT-03 | Rate limiting | Exceed the login attempt window | Subsequent attempts are throttled |
| MT-04 | Authorization | Request admin endpoints as a normal user | `403 Forbidden` |
| MT-05 | Degraded providers | Run with no API keys configured | Scan still completes with heuristics and metadata only |
| MT-06 | Provider timeout | Point WHOIS at an unresponsive server | Scan completes with an informational finding |
| MT-07 | Header analysis | Raw headers with `Reply-To`/`Return-Path` mismatch and failed SPF | Spoofing flags reported |
| MT-08 | Watchlist | Add a sender, then analyse text containing it | Watchlist match surfaced in the analysis |
| MT-09 | History isolation | Sign in as two users | Each sees only their own scans and analyses |
| MT-10 | Responsive UI | Open every screen at desktop and mobile widths | Layout reflows; no horizontal overflow |
| MT-11 | Extension | Load unpacked, sign in, scan current tab and a context-menu link | Score ring, badge colour and report tab render correctly |
| MT-12 | Report export | Download the activity report as HTML, CSV and JSON | All three open and contain the user's data |

**Test environment.** Server started with `uvicorn app.main:app --host 0.0.0.0 --port 8000`; the suite targets `http://127.0.0.1:8000`. Because external providers are optional, results are deterministic in offline mode and richer when keys are present.

**Verified results.** The suite was executed against the analysed build on 4 October 2026 by starting the server with `uvicorn app.main:app` and running `python test_e2e.py`. All 23 automated cases (TC-01 to TC-23) passed: the suite printed `OK` for each assertion and finished with `ALL TESTS PASSED` and exit status 0. Running the suite from a clean environment also exposed one packaging defect - `httpx` is imported by the webhooks router but was missing from `requirements.txt`; it has since been added so a fresh install starts the server. The manual cases were exercised during development and, where they exposed gaps, those gaps are recorded in the design document's implementation observations.

### 11.2 System report generation

ThreatLens produces reports at three levels.

| Report | Trigger | Contents |
|---|---|---|
| Per-scan report | Every `POST /api/scan-url` | Normalized request, 0-100 score, verdict, category totals, itemised findings with points and severity, metadata (WHOIS/TLS/HTTP), provider results and elapsed time |
| Per-phishing report | Every `POST /api/analyze-phishing` and tool call | Phishing score, verdict, confidence, itemised flags, matched keyword groups and watchlist matches |
| User activity report | `GET /api/users/report`, downloadable in HTML, CSV and JSON | Profile, summary statistics, scan list and phishing list |
| Platform report | Admin `GET /api/admin/stats` and `GET /api/admin/users` | Global scan/user/verdict totals and per-user activity |
| Document reports | Offline scripts `scripts/generate_pdf.py` and `scripts/generate_siem_pdf.py` | The system-design document and the SIEM correlation-rules report as PDFs |

Reports are stored as immutable JSON snapshots in the `scans` and `phishing_analyses` tables, so a past report remains reproducible even if detection rules change later.

## 12. Future Enhancements

**Detection and intelligence.**

1. **Machine-learning phishing classifier** - layer a fine-tuned DistilBERT model over the rule engine to catch novel wording, keeping the rule engine as an explainable fallback.
2. **Additional reputation feeds** - integrate AbuseIPDB and AlienVault OTX for IP and domain reputation, and add domain-age and certificate-transparency checks.
3. **Image and QR analysis** - detect brand-logo spoofing in screenshots and decode QR-code "quishing" links.
4. **URL reputation caching and scheduled re-scans** - re-evaluate previously scanned URLs on a schedule and alert when a verdict changes.

**Platform and integration.**

5. **Webhook delivery** - invoke the existing `fire_webhooks` helper from the scan flow so subscriptions actually receive `scan.dangerous` events, with retry, signing and SSRF-safe delivery.
6. **API-key authentication** - implement issue, use and revoke flows for the already-modelled `api_keys` table so scripts and CI can authenticate without a browser token.
7. **Email and Slack notifications** - use the configured SMTP settings for alerts on dangerous verdicts and digest emails.
8. **Bulk-scan rate limiting** - charge the per-user limiter per URL so a batch cannot bypass the intended quota.

**Data and operations.**

9. **Versioned migrations** - adopt Alembic to replace `create_all()` plus the legacy-column patch, and enforce SQLite foreign keys or move to PostgreSQL with native `JSONB`.
10. **Consistent retention policy** - align ORM constraints and the admin delete route on anonymised history (retain operational history, null the actor).
11. **Centralised observability** - structured logging, metrics and tracing for scan latency, provider failure rates and rate-limit hits.
12. **Caching layer** - Redis for WHOIS/TLS/HTTP metadata and threat-intel responses to cut scan latency and outbound traffic.

**Interface and experience.**

13. **Role-based access control** - extend the binary admin flag to analyst/viewer roles with scoped permissions.
14. **Report export expansion** - server-side PDF export and scheduled emailed reports.
15. **Mobile and PWA support** - an installable progressive web app and offline access to recent history.
16. **Internationalisation** - multi-language UI and locale-aware domain heuristics.

## 13. References

1. S. Ramírez, *FastAPI Documentation*, FastAPI, 2024. [Online]. Available: https://fastapi.tiangolo.com/
2. Encode, *Uvicorn Documentation*, 2024. [Online]. Available: https://www.uvicorn.org/
3. SQLAlchemy Authors, *SQLAlchemy 2.0 Documentation*, 2024. [Online]. Available: https://docs.sqlalchemy.org/
4. Pydantic Services Inc., *Pydantic V2 Documentation*, 2024. [Online]. Available: https://docs.pydantic.dev/
5. Python Software Foundation, *Python Standard Library - hashlib (PBKDF2-HMAC-SHA256)*, 2024. [Online]. Available: https://docs.python.org/3/library/hashlib.html
6. Python Software Foundation, *Python Standard Library - sqlite3*, 2024. [Online]. Available: https://docs.python.org/3/library/sqlite3.html
7. J. Kurkowski, *tldextract Documentation*, 2024. [Online]. Available: https://github.com/john-kurkowski/tldextract
8. *python-whois Documentation*, 2024. [Online]. Available: https://pypi.org/project/python-whois/
9. K. Reitz, *Requests: HTTP for Humans*, 2024. [Online]. Available: https://requests.readthedocs.io/
10. VirusTotal, *VirusTotal API v3 Documentation*, 2024. [Online]. Available: https://developers.virustotal.com/reference/overview
11. Google, *Safe Browsing API (v4) Documentation*, 2024. [Online]. Available: https://developers.google.com/safe-browsing
12. PhishTank, *PhishTank Developer Information*, 2024. [Online]. Available: https://phishtank.org/developer_info.php
13. Google, *Chrome Extensions - Manifest V3*, Chrome Developers, 2024. [Online]. Available: https://developer.chrome.com/docs/extensions/mv3/
14. OWASP Foundation, *Server-Side Request Forgery Prevention Cheat Sheet*, 2024. [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
15. OWASP Foundation, *Password Storage Cheat Sheet*, 2024. [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
16. NIST, *Special Publication 800-63B: Digital Identity Guidelines - Authentication and Lifecycle Management*, 2017. [Online]. Available: https://pages.nist.gov/800-63-3/sp800-63b.html
17. V. I. Levenshtein, "Binary codes capable of correcting deletions, insertions, and reversals," *Soviet Physics Doklady*, vol. 10, no. 8, pp. 707-710, 1966.
18. C. E. Shannon, "A Mathematical Theory of Communication," *Bell System Technical Journal*, vol. 27, no. 3, pp. 379-423, 1948.
19. R. Fielding et al., *RFC 9110: HTTP Semantics*, IETF, 2022. [Online]. Available: https://www.rfc-editor.org/rfc/rfc9110
20. J. Klensin, *RFC 5321: Simple Mail Transfer Protocol*, IETF, 2008. [Online]. Available: https://www.rfc-editor.org/rfc/rfc5321
21. M. Kucherawy and E. Zwicky, *RFC 7489: Domain-based Message Authentication, Reporting, and Conformance (DMARC)*, IETF, 2015. [Online]. Available: https://www.rfc-editor.org/rfc/rfc7489
