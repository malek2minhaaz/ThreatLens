# 🧩 ThreatLens Scanner — Chrome Extension

A Manifest V3 extension that scans any URL against your **ThreatLens** backend
and shows the unified 0–100 risk score, verdict and itemized findings — right
from the browser.

## Features

- **Toolbar popup** — pre-fills the active tab's URL, scans it, shows the score
  ring, verdict and top findings.
- **Context menu** — right-click any page, link or selected text →
  *"Scan … with ThreatLens"* opens a full report tab.
- **Color-coded badge** — after a scan, the toolbar icon shows the score
  colored by verdict (green / lime / amber / red).
- **Deep links** — "Open full report" jumps to your dashboard's scanner page
  (loads the persisted scan from history when possible).
- **Configurable server** — point it at `http://localhost:8000` or any hosted
  ThreatLens instance.

## Install (unpacked, for development)

1. Start your ThreatLens server (`uvicorn app.main:app --reload`).
2. Open **chrome://extensions** in Chrome.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select this `extension/` folder.
5. Click the extension's puzzle icon → **⚙️ Settings**, enter your server URL
   and your ThreatLens username/password, then **Sign in & save**.
6. Pin the extension and click it to scan the current tab.

> Loading an unpacked extension works in Chrome / Edge / Brave / Opera.
> For a store release you'd package this folder as a ZIP.

## How it talks to the backend

- `POST {server}/api/auth/login` — one-time sign-in in the settings page.
- `POST {server}/api/scan-url` — every scan (Bearer token from storage).
- `GET {server}/api/health` — the "Test connection" button.

The session token is stored in `chrome.storage.local`; the password is **never**
persisted. Tokens expire after 30 days (dashboard-side) — just sign in again.
Signing out calls `/api/auth/logout` to revoke the token.

## Permissions

- `activeTab` / `tabs` — read the current tab's URL to pre-fill the popup.
- `storage` — persist the server URL and session token.
- `contextMenus` — the right-click scan actions.
- `host_permissions` — `http://localhost/*` and `http://127.0.0.1/*` by default.
  For a remote server, Chrome asks for permission when you sign in
  (via `optional_host_permissions`).

## Security notes

- Only scan URLs you trust to send to your own backend — the server performs
  live WHOIS/SSL/HTTP lookups and may forward URLs to threat-intel providers
  (VirusTotal / Safe Browsing / PhishTank) when keys are configured.
- Keep the extension's sign-in scoped to your own account; anyone with access
  to your browser can scan as you.

## Regenerating icons

```bash
cd extension/icons
python generate_icons.py     # requires Pillow
```
