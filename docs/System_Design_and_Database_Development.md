# ThreatLens - System Design and Database Development

**Analysed implementation:** `backend/app/`, `frontend/`, and `extension/` on 7 September 2026. This document distinguishes implemented behaviour from planned-but-inactive structures.

## 6. System Design & Database Development

### 6.1 Architecture

| Layer | Implemented components | Responsibility |
|---|---|---|
| Presentation | Static HTML/CSS/vanilla JavaScript dashboard; Chrome Manifest V3 extension | Collect user input, keep the bearer token, render scan reports, history, trends and admin views. |
| API | FastAPI application with auth, scanner, phishing, tools, history, intel, users, admin, audit and webhook routers | Validates requests, enforces authorization, coordinates services and returns JSON. |
| Domain services | URL parser, heuristic engine, metadata inspector, threat-intel clients, risk scorer, phishing analyser, watchlist matcher, security and rate limiter | Performs detection, risk classification, content analysis and security controls. |
| Data access | SQLAlchemy 2 ORM over SQLite by default; PostgreSQL is supported by changing `DATABASE_URL` | Stores identities, sessions, scan results, analyses, watchlists, audit events, API-key records and webhook subscriptions. |
| External services | WHOIS, SSL/TLS inspection, HTTP inspection; optionally VirusTotal, Google Safe Browsing and PhishTank | Supplies enrichment and reputation signals. Provider failure is designed to degrade gracefully. |

The core request path is:

`dashboard / extension -> FastAPI -> authentication -> scan or analysis service -> SQLAlchemy -> SQLite/PostgreSQL -> JSON response`

For a URL scan, the scanner normalizes the URL, applies offline heuristics, then runs WHOIS, TLS and HTTP inspection in parallel. It calls configured threat-intelligence providers, combines all findings into a safety score and verdict, then persists the report in `scans`. A score of **100 is safest** and **0 is most dangerous**.

| Safety-score range | Verdict | Meaning |
|---:|---|---|
| 85-100 | `SAFE` | No meaningful risk detected. |
| 70-84 | `LOW RISK` | Minor indicators only. |
| 40-69 | `SUSPICIOUS` | Requires user caution or further review. |
| 0-39 | `DANGEROUS` | Strong malicious or phishing indicators. |

Phishing-content analysis is a separate rule-based flow. It evaluates urgency, threats, financial bait, credential requests, sender/header anomalies and risky links. Its `phishing_score` has the opposite interpretation: **higher is more likely phishing** (`SAFE` < 25, `SUSPICIOUS` 25-54, `PHISHING` >= 55).

### 6.2 Security and resilience controls

| Control | Implementation |
|---|---|
| Password protection | PBKDF2-HMAC-SHA256 with 210,000 iterations; only `password_hash` is stored. |
| Session management | Opaque, database-backed bearer tokens with a 30-day expiry and logout revocation. |
| Authorization | Dependency-based current-user and current-admin checks. |
| Input validation | Pydantic limits URL, content, user name, password and watchlist-input lengths and formats. |
| SSRF mitigation | Metadata service rejects loopback, private, link-local, multicast and reserved targets, including DNS-resolved hosts. |
| Rate limiting | In-memory sliding-window limits for login, registration, scan and tools routes. |
| External-call resilience | Metadata operations run concurrently; the full scan has `MAX_SCAN_SECONDS` timeout. |

### 6.3 Implementation observations to resolve before production finalisation

1. `scan-bulk` authenticates users but does not call the per-user `scan_limiter`; a bulk request may scan up to 25 URLs with five concurrent workers. Apply a bulk-cost or per-item limit.
2. The SQLite engine does not enable `PRAGMA foreign_keys = ON`. In SQLite, declared `ON DELETE CASCADE` and `ON DELETE SET NULL` actions need this enabled to be enforced.
3. The declared model policy preserves scans and phishing analyses with `ON DELETE SET NULL`, but `DELETE /api/admin/users/{id}` explicitly deletes both tables first. Choose and implement one policy; this document recommends preservation/anonymisation.
4. `api_keys` is modelled but no API-key issue, authentication or revocation route currently uses it.
5. Webhook subscriptions have CRUD routes and a `fire_webhooks` helper, but no scan route invokes that helper. Subscriptions therefore do not currently receive scan notifications.
6. `Base.metadata.create_all()` plus a small legacy-column patch is not a repeatable migration strategy. Adopt Alembic (or an equivalent versioned migration process) before changing production data.

## 7. UML Diagrams

The editable Draw.io source files are the UML deliverables:

| Diagram | Purpose | File |
|---|---|---|
| 7.1 Use-case diagram | Shows actors and externally observable system functions. Admin is a specialised authenticated user; threat-intel providers and the browser extension are external actors. | [07_01_use_case_diagram.drawio](diagrams/07_01_use_case_diagram.drawio) |
| 7.2 Class diagram | Shows persistent entities, value objects and the scan, scoring, phishing, security and rate-limit services. | [07_02_class_diagram.drawio](diagrams/07_02_class_diagram.drawio) |
| 7.3 Activity diagram | Shows the actual single-URL scan path: bearer-token validation, limiting, validation, parallel analysis, scoring, persistence and error outcomes. | [07_03_activity_diagram.drawio](diagrams/07_03_activity_diagram.drawio) |

**Use-case scope.** Visitors can register and sign in. Authenticated users can scan one or more URLs, analyse phishing content, inspect links/headers/senders, use a personal watchlist, view history/trends/intel and create/delete webhook subscriptions. Administrators additionally view global statistics, users, scans and the audit log, and can promote, demote or delete users. The diagram’s webhook-delivery case is a target behaviour, not a current runtime integration (see observation 5).

**Class relationships.** `User` has zero or more tokens, watchlist entries, API-key records and webhooks. It can have zero or more scan records, phishing analyses and audit entries; these three relationships are optional on the child side so historical records can be anonymised. `ScanRecord` contains a denormalised, immutable report snapshot rather than a normalized result table.

## 8. Data Dictionary

### 8.1 `users`

| Column | Type | Rules / index | Description |
|---|---|---|---|
| `id` | INTEGER | PK, indexed | Surrogate user identifier. |
| `username` | VARCHAR(24) | NOT NULL, UNIQUE, indexed | Login name; request schema permits letters, digits and underscore. |
| `email` | VARCHAR(254) | NOT NULL, UNIQUE, indexed | Normalised lower-case account email. |
| `password_hash` | VARCHAR(255) | NOT NULL | PBKDF2 password representation; never expose in API output. |
| `display_name` | VARCHAR(50) | NULL | Optional name shown in the UI. |
| `is_admin` | BOOLEAN | NOT NULL, default `false` | Grants admin-route access. |
| `created_at` | DATETIME | NOT NULL, default UTC now | Account creation timestamp. |

### 8.2 `auth_tokens`

| Column | Type | Rules / index | Description |
|---|---|---|---|
| `id` | INTEGER | PK, indexed | Token record identifier. |
| `token` | VARCHAR(64) | NOT NULL, UNIQUE, indexed | Opaque bearer-token value. Treat as a secret. |
| `user_id` | INTEGER | NOT NULL, FK -> `users.id`, indexed, `ON DELETE CASCADE` | Token owner. |
| `created_at` | DATETIME | NOT NULL, default UTC now | Token issue time. |
| `expires_at` | DATETIME | NOT NULL | Token expiry; currently 30 days after issue. |

### 8.3 `scans`

| Column | Type | Rules / index | Description |
|---|---|---|---|
| `id` | INTEGER | PK, indexed | Scan-report identifier. |
| `user_id` | INTEGER | NULL, FK -> `users.id`, indexed, `ON DELETE SET NULL` | User that initiated the scan; optional for retained/anonymised history. |
| `url` | VARCHAR(2048) | NOT NULL, indexed | Normalised scanned URL. |
| `risk_score` | INTEGER | NOT NULL; intended range 0-100 | Safety score: 100 safest, 0 most dangerous. |
| `verdict` | VARCHAR(50) | NOT NULL | `SAFE`, `LOW RISK`, `SUSPICIOUS` or `DANGEROUS`. |
| `summary` | TEXT | NOT NULL, JSON text, default `{}` | Request metadata, category totals, provider data, elapsed time and timestamp. |
| `findings` | TEXT | NOT NULL, JSON text, default `[]` | Itemised detection findings. |
| `created_at` | DATETIME | NOT NULL, default UTC now, indexed | Report creation time. |

### 8.4 `phishing_analyses`

| Column | Type | Rules / index | Description |
|---|---|---|---|
| `id` | INTEGER | PK, indexed | Analysis-record identifier. |
| `user_id` | INTEGER | NULL, FK -> `users.id`, indexed, `ON DELETE SET NULL` | User that submitted the content. |
| `content_type` | VARCHAR(50) | NOT NULL, default `email` | One of `email`, `sms` or `page_text`. |
| `content_preview` | VARCHAR(500) | NOT NULL, default empty string | First 400 characters of submitted content in the current endpoint; avoids retaining the full body. |
| `phishing_score` | INTEGER | NOT NULL; intended range 0-100 | Likelihood score; higher means more likely phishing. |
| `verdict` | VARCHAR(50) | NOT NULL | `SAFE`, `SUSPICIOUS` or `PHISHING`. |
| `flags` | TEXT | NOT NULL, JSON text, default `[]` | Itemised phishing indicators. |
| `created_at` | DATETIME | NOT NULL, default UTC now, indexed | Analysis creation time. |

### 8.5 `watchlist_entries`

| Column | Type | Rules / index | Description |
|---|---|---|---|
| `id` | INTEGER | PK, indexed | Watchlist-entry identifier. |
| `user_id` | INTEGER | NOT NULL, FK -> `users.id`, indexed, `ON DELETE CASCADE` | Owner of the private watchlist item. |
| `kind` | VARCHAR(10) | NOT NULL | `sender`, `domain` or `url`. |
| `value` | VARCHAR(2048) | NOT NULL | Indicator to match, compared case-insensitively by the application. |
| `note` | VARCHAR(200) | NULL | Optional user annotation. |
| `created_at` | DATETIME | NOT NULL, default UTC now | Entry creation time. |
| `last_seen_at` | DATETIME | NULL | Reserved for the most recent matching observation; not updated by current matching code. |

### 8.6 `audit_log`

| Column | Type | Rules / index | Description |
|---|---|---|---|
| `id` | INTEGER | PK, indexed | Audit-event identifier. |
| `user_id` | INTEGER | NULL, FK -> `users.id`, indexed, `ON DELETE SET NULL` | Actor; null for a system event or retained deleted-user history. |
| `action` | VARCHAR(100) | NOT NULL | Event name, for example `user.promote`, `user.demote` or `user.delete`. |
| `detail` | TEXT | NULL | Human-readable detail or JSON detail. |
| `ip_address` | VARCHAR(45) | NULL | IPv4 or IPv6 client address. |
| `created_at` | DATETIME | NOT NULL, default UTC now, indexed | Event time. |

### 8.7 `api_keys`

| Column | Type | Rules / index | Description |
|---|---|---|---|
| `id` | INTEGER | PK, indexed | API-key record identifier. |
| `user_id` | INTEGER | NOT NULL, FK -> `users.id`, indexed, `ON DELETE CASCADE` | Key owner. |
| `key_hash` | VARCHAR(128) | NOT NULL, UNIQUE, indexed | Hash of the API key; raw key should never be stored. |
| `name` | VARCHAR(100) | NOT NULL, default `default` | User-facing key label. |
| `prefix` | VARCHAR(8) | NOT NULL | Short non-secret identifier for display. |
| `is_active` | BOOLEAN | NOT NULL, default `true` | Enables revocation without deleting the record. |
| `last_used_at` | DATETIME | NULL | Latest successful use. |
| `created_at` | DATETIME | NOT NULL, default UTC now | Creation time. |
| `expires_at` | DATETIME | NULL | Optional expiry time. |

### 8.8 `webhooks`

| Column | Type | Rules / index | Description |
|---|---|---|---|
| `id` | INTEGER | PK, indexed | Webhook subscription identifier. |
| `user_id` | INTEGER | NOT NULL, FK -> `users.id`, indexed, `ON DELETE CASCADE` | Subscriber. |
| `url` | VARCHAR(2048) | NOT NULL | HTTPS destination supplied by the user. Validate and protect against SSRF before production use. |
| `secret` | VARCHAR(64) | NOT NULL | Per-subscription signing secret. It is currently stored as a raw secret and should be encrypted at rest or replaced by a verifiable key-management design. |
| `events` | TEXT | NOT NULL, JSON text | Event-name array, default `["scan.dangerous"]`. |
| `is_active` | BOOLEAN | NOT NULL, default `true` | Enables temporarily disabling delivery. |
| `last_triggered_at` | DATETIME | NULL | Latest delivery attempt. |
| `created_at` | DATETIME | NOT NULL, default UTC now | Subscription creation time. |

### 8.9 JSON value structures

| Table.column | JSON structure | Required logical members |
|---|---|---|
| `scans.summary` | Object | `request`, `category_totals`, `metadata`, `threat_intel`, `providers`, `duration_ms`, `scanned_at`. |
| `scans.findings` | Array of objects | `label`, `points`, `severity`, `detail`, `category`. |
| `phishing_analyses.flags` | Array of objects | `label`, `points`, `severity`; `detail` when available. |
| `webhooks.events` | Array of strings | Event names such as `scan.dangerous` or `scan.*`. |

## 9. Finalized Database Schema

### 9.1 Entity relationships

```text
users (1) ──< auth_tokens          [CASCADE]
      (1) ──< watchlist_entries    [CASCADE]
      (1) ──< api_keys             [CASCADE]
      (1) ──< webhooks             [CASCADE]
      (0..1) ──< scans              [SET NULL]
      (0..1) ──< phishing_analyses [SET NULL]
      (0..1) ──< audit_log          [SET NULL]
```

The recommended retention rule is final: delete secrets and user-owned configuration, but retain operational history with the actor set to null. This supports reporting without retaining an account relationship. It requires removing the manual scan/analysis deletes from the administrative deletion route.

### 9.2 Final physical rules

| Table | Primary key | Candidate/unique keys | Required foreign-key and data rules |
|---|---|---|---|
| `users` | `id` | `username`, `email` | `is_admin` defaults false. |
| `auth_tokens` | `id` | `token` | `user_id` cascades; add index on `expires_at` for expired-token cleanup. |
| `scans` | `id` | - | `user_id` sets null; constrain `risk_score` to 0-100 and `verdict` to the four scan verdicts. |
| `phishing_analyses` | `id` | - | `user_id` sets null; constrain `content_type`, `phishing_score` 0-100 and its three verdicts. |
| `watchlist_entries` | `id` | `(user_id, kind, normalized_value)` | Cascade owner deletion. Store a lower-cased `normalized_value` rather than relying only on application duplicate checks. |
| `audit_log` | `id` | - | `user_id` sets null; `action` is required. |
| `api_keys` | `id` | `key_hash` | Cascade owner deletion; reject inactive or expired keys at authentication. |
| `webhooks` | `id` | - | Cascade owner deletion; restrict event names, use encrypted/managed secret material, validate HTTPS URL. |

### 9.3 Essential indexes

The current single-column indexes support basic lookup. Add the following composite or maintenance indexes for the release schema:

```sql
CREATE INDEX ix_auth_tokens_expires_at
    ON auth_tokens (expires_at);

CREATE INDEX ix_scans_user_created_at
    ON scans (user_id, created_at DESC);

CREATE INDEX ix_phishing_analyses_user_created_at
    ON phishing_analyses (user_id, created_at DESC);

CREATE INDEX ix_audit_log_created_at
    ON audit_log (created_at DESC);

CREATE UNIQUE INDEX uq_watchlist_entries_owner_kind_value
    ON watchlist_entries (user_id, kind, normalized_value);
```

For SQLite, enable foreign-key enforcement on every database connection. For production, prefer PostgreSQL with native `JSONB` for report payloads and a migration-managed schema. Retain JSON snapshots in `scans` because a scan report must stay reproducible even if detection rules change later.

### 9.4 Release-completion checklist

1. Introduce a versioned migration baseline containing the eight tables, all foreign keys, check constraints and the indexes above.
2. Enforce SQLite foreign keys in development and use PostgreSQL in shared or concurrent deployments.
3. Apply the selected anonymised-history deletion policy consistently in both ORM constraints and routes.
4. Either implement API-key authentication and webhook delivery with outbound-request safeguards, or remove their unused tables and endpoints from the release scope.
5. Add tests for token expiry, cascade/set-null behaviour, score ranges, enum values, duplicate watchlist items and bulk-scan rate limiting.
