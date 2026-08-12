/* ============================================================
   ThreatLens Scanner — shared helpers
   Loaded by popup/options/results pages and the service worker.
   ============================================================ */
"use strict";

const TL = (() => {
  const DEFAULTS = { server: "http://localhost:8000" };

  /** Normalize a user-provided server URL (add scheme, strip trailing slash). */
  function normalizeServer(s) {
    let v = String(s || "").trim().replace(/\/+$/, "");
    if (!v) v = DEFAULTS.server;
    if (!/^https?:\/\//i.test(v)) v = "http://" + v;
    return v;
  }

  async function getConfig() {
    const c = await chrome.storage.local.get(["server", "token", "username"]);
    return {
      server: normalizeServer(c.server),
      token: c.token || "",
      username: c.username || "",
      configured: Boolean(c.token),
    };
  }

  async function setConfig(partial) {
    await chrome.storage.local.set(partial);
  }

  async function clearConfig() {
    await chrome.storage.local.remove(["token", "username"]);
  }

  /** Small fetch wrapper that speaks the ThreatLens JSON API. */
  async function api(server, path, { method = "GET", body, token } = {}) {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (token) headers["Authorization"] = `Bearer ${token}`;

    let resp;
    try {
      resp = await fetch(server + path, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch {
      const err = new Error("Cannot reach the ThreatLens server.");
      err.status = 0;
      throw err;
    }

    let data = null;
    try {
      data = await resp.json();
    } catch {
      /* non-JSON body — fall through to the generic error */
    }
    if (!resp.ok) {
      const err = new Error((data && data.detail) || `HTTP ${resp.status}`);
      err.status = resp.status;
      throw err;
    }
    return data;
  }

  /** Risk-score color, mirroring the dashboard (100 = safe). */
  function scoreColor(score) {
    if (score >= 85) return "#34d399";
    if (score >= 70) return "#a3e635";
    if (score >= 40) return "#fbbf24";
    return "#f87171";
  }

  function verdictClass(v) {
    const s = String(v || "").toLowerCase();
    if (s.includes("danger") || s.includes("phish")) return "v-danger";
    if (s.includes("suspicious")) return "v-suspicious";
    if (s.includes("low")) return "v-low";
    return "v-safe";
  }

  function escapeHtml(str) {
    return String(str ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[c]));
  }

  function fmtDuration(ms) {
    if (!ms) return "—";
    return ms >= 1000 ? (ms / 1000).toFixed(1) + "s" : ms + "ms";
  }

  /** Run a full URL scan against the configured server. */
  async function scan(server, token, url) {
    return api(server, "/api/scan-url", { method: "POST", body: { url }, token });
  }

  return {
    DEFAULTS,
    normalizeServer,
    getConfig,
    setConfig,
    clearConfig,
    api,
    scoreColor,
    verdictClass,
    escapeHtml,
    fmtDuration,
    scan,
  };
})();
