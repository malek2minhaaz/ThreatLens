/* ============================================================
   ThreatLens — shared shell, API helpers & page bootstrap
   ------------------------------------------------------------
   Multi-page app: every section lives in its own HTML file and
   its own script under static/js/pages/. This file provides:

   · the shared header / footer / toast (injected on every page)
   · auth gating (redirects unauthenticated visitors to login)
   · the API client + tiny utilities used by all pages
   ============================================================ */
"use strict";

const App = (() => {
  const API = {
    health: "/api/health",
    auth: "/api/auth",
    scan: "/api/scan-url",
    phishing: "/api/analyze-phishing",
    inspect: "/api/phishing/inspect",
    headers: "/api/phishing/headers",
    senderCheck: "/api/phishing/sender-check",
    trends: "/api/phishing/trends",
    watchlist: "/api/watchlist",
    history: "/api/history",
    phishingHistory: "/api/phishing-history",
    stats: "/api/users/stats",
    report: "/api/users/report",
    intelStatus: "/api/intel/status",
    intelFeed: "/api/intel/feed",
    admin: "/api/admin",
  };

  const TOKEN_KEY = "threatlens_token";
  const ADMIN_FLAG_KEY = "threatlens_is_admin";
  const THEME_KEY = "threatlens_theme";
  const state = { user: null };

  /* ---------------- DOM helpers ---------------- */

  const $ = (id) => document.getElementById(id);
  const qs = (sel, root = document) => root.querySelector(sel);
  const qsa = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  /* ---------------- String / data helpers ---------------- */

  function escapeHtml(str) {
    return String(str ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  function getToken() {
    return localStorage.getItem(TOKEN_KEY) || "";
  }

  function setToken(token) {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(ADMIN_FLAG_KEY);
    }
  }

  /** Remember whether the logged-in user is an admin (used to route pre-login redirects). */
  function setAdminFlag(isAdmin) {
    if (isAdmin) localStorage.setItem(ADMIN_FLAG_KEY, "1");
    else localStorage.removeItem(ADMIN_FLAG_KEY);
  }

  function isAdminFlag() {
    return localStorage.getItem(ADMIN_FLAG_KEY) === "1";
  }

  function isAuthed() {
    return Boolean(getToken());
  }

  function verdictClass(verdict) {
    const v = (verdict || "").toLowerCase();
    if (v.includes("danger") || v.includes("phish")) return "v-danger";
    if (v.includes("suspicious")) return "v-suspicious";
    if (v.includes("low")) return "v-low";
    return "v-safe";
  }

  function severityClass(sev) {
    return "sev-" + (sev || "info");
  }

  function findingPointsClass(points) {
    if (points > 0) return "pos";
    if (points < 0) return "neg";
    return "zero";
  }

  function formatPoints(points) {
    return points > 0 ? `+${points}` : String(points);
  }

  function timeAgo(iso) {
    // Backend timestamps are naive UTC — interpret as UTC when no offset is present
    const tzHint = /(?:Z|[+-]\d\d:\d\d)$/.test(String(iso));
    const then = new Date(tzHint ? iso : iso + "Z");
    if (Number.isNaN(then.getTime())) return "—";
    const secs = Math.floor((Date.now() - then.getTime()) / 1000);
    if (secs < 60) return "just now";
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    return then.toLocaleDateString();
  }

  function initials(name) {
    const parts = String(name || "?").trim().split(/\s+/);
    return ((parts[0]?.[0] || "?") + (parts[1]?.[0] || "")).toUpperCase();
  }

  function animateValue(el, from, to, duration) {
    const start = performance.now();
    function tick(now) {
      const p = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(from + (to - from) * eased);
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  /* ---------------- Toast ---------------- */

  function toast(message, success = false) {
    const el = $("toast");
    if (!el) return;
    el.textContent = message;
    el.classList.toggle("t-success", success);
    el.hidden = false;
    requestAnimationFrame(() => el.classList.add("show"));
    clearTimeout(toast._t);
    toast._t = setTimeout(() => {
      el.classList.remove("show");
      setTimeout(() => (el.hidden = true), 300);
    }, 3200);
  }

  /* ---------------- API client ---------------- */

  async function apiFetch(url, options = {}) {
    const headers = { ...(options.headers || {}) };
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
    if (options.body) headers["Content-Type"] = "application/json";

    const resp = await fetch(url, { ...options, headers });
    if (resp.status === 401 && !url.includes("/api/auth/login") && !url.includes("/api/auth/register")) {
      handleSessionExpired();
    }
    if (!resp.ok) {
      let detail = `HTTP ${resp.status}`;
      try {
        const body = await resp.json();
        detail = body.detail || detail;
      } catch { /* ignore */ }
      throw new Error(detail);
    }
    return resp.json();
  }

  function handleSessionExpired() {
    setToken(null);
    state.user = null;
    if (!location.pathname.endsWith("login.html")) {
      toast("Your session has expired. Please sign in again.");
      setTimeout(() => location.replace("login.html"), 400);
    }
  }

  /* ---------------- Shared shell (header / footer / toast) ---------------- */

  const NAV = [
    { page: "scanner", href: "scanner.html", label: "URL Scanner" },
    { page: "phishing", href: "phishing.html", label: "Phishing Lab" },
    { page: "history", href: "history.html", label: "History" },
    { page: "intel", href: "intel.html", label: "Threat Intel" },
    { page: "learn", href: "learn.html", label: "Learn" },
    { page: "profile", href: "profile.html", label: "Profile" },
    { page: "admin", href: "admin.html", label: "Admin", adminOnly: true },
  ];

  let activePage = "";

  const SHIELD_SVG =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5l8-3z"/>' +
    '<path d="M9 12l2 2 4-4"/></svg>';

  const LOGOUT_SVG =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/></svg>';

  const SUN_SVG =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<circle cx="12" cy="12" r="4"/>' +
    '<path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';

  const MOON_SVG =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

  const CHEVRON_SVG =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M9 6l6 6-6 6"/></svg>';

  function renderShell(current) {
    if ($("appHeader")) return; // already injected

    const authed = isAuthed();

    const header = `
    <header class="site-header" id="appHeader">
      <div class="container header-inner">
        <a class="brand" href="index.html" aria-label="ThreatLens home">
          <span class="brand__shield" aria-hidden="true">${SHIELD_SVG}</span>
          <span class="brand__name">Threat<span class="brand__accent">Lens</span></span>
        </a>
        <nav class="site-nav" id="mainNav" aria-label="Primary"${authed ? "" : " hidden"}></nav>
        <div class="header-right">
          <span class="status-pill" id="apiStatus" title="API connectivity — click to re-check">
            <span class="status-pill__dot"></span>
            <span id="apiStatusText">Checking API…</span>
          </span>
          <button class="icon-btn" id="themeToggle" title="Switch to dark theme" aria-label="Switch between light and dark theme">${MOON_SVG}</button>
          <div class="user-chip" id="userChip" hidden title="Open your profile">
            <span class="avatar" id="userAvatar">?</span>
            <span class="user-chip__name" id="userName">—</span>
            <button class="icon-btn" id="logoutBtn" title="Sign out" aria-label="Sign out">${LOGOUT_SVG}</button>
          </div>
        </div>
      </div>
    </header>`;

    const footer = `
    <footer class="site-footer" id="appFooter">
      <div class="container footer-inner">
        <span class="mono muted">ThreatLens v1.2 — FastAPI · SQLite · HTML/CSS/JS</span>
        <span class="mono muted">Educational tool — always verify with official channels.</span>
      </div>
    </footer>`;

    document.body.insertAdjacentHTML("afterbegin", header);
    document.body.insertAdjacentHTML("beforeend", footer);
    document.body.insertAdjacentHTML("beforeend", '<div class="toast" id="toast" role="status" hidden></div>');

    renderNav();

    // Theme toggle — light is the default, choice persists in localStorage
    initTheme();
    $("themeToggle").addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      localStorage.setItem(THEME_KEY, next);
      document.documentElement.dataset.theme = next;
      const btn = $("themeToggle");
      btn.innerHTML = next === "dark" ? SUN_SVG : MOON_SVG;
      btn.title = next === "dark" ? "Switch to light theme" : "Switch to dark theme";
    });

    // Status pill — click to re-check connectivity
    $("apiStatus").addEventListener("click", checkApi);

    // User chip — click through to the profile page
    const chip = $("userChip");
    chip.addEventListener("click", () => {
      if (state.user) location.href = "profile.html";
    });

    // Logout
    $("logoutBtn").addEventListener("click", async (e) => {
      e.stopPropagation();
      try { await apiFetch(API.auth + "/logout", { method: "POST" }); } catch { /* ignore */ }
      setToken(null);
      state.user = null;
      toast("Signed out.", true);
      setTimeout(() => location.replace("index.html"), 300);
    });
  }

  function renderNav() {
    const nav = $("mainNav");
    if (!nav) return;
    const isAdmin = Boolean(state.user?.is_admin);
    nav.innerHTML = NAV
      .filter((n) => !n.adminOnly || isAdmin)
      .map((n) => `<a class="nav-link${n.page === activePage ? " is-active" : ""}" href="${n.href}">${n.label}</a>`)
      .join("");
  }

  function initTheme() {
    const stored = localStorage.getItem(THEME_KEY);
    const theme = stored === "dark" || stored === "light" ? stored : "light";
    document.documentElement.dataset.theme = theme;
    const btn = $("themeToggle");
    if (btn) {
      btn.innerHTML = theme === "dark" ? SUN_SVG : MOON_SVG;
      btn.title = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";
    }
    return theme;
  }

  function renderUserChip() {
    const chip = $("userChip");
    if (!chip) return;
    const u = state.user;
    chip.hidden = !u;
    if (u) {
      $("userAvatar").textContent = initials(u.public_name);
      $("userName").textContent = u.public_name;
    }
  }

  async function checkApi() {
    const pill = $("apiStatus");
    if (!pill) return;
    pill.classList.add("is-checking");
    pill.classList.remove("is-online", "is-offline");
    $("apiStatusText").textContent = "Checking API…";
    try {
      await apiFetch(API.health);
      pill.classList.add("is-online");
      $("apiStatusText").textContent = "API online";
    } catch {
      pill.classList.add("is-offline");
      $("apiStatusText").textContent = "API offline";
    } finally {
      pill.classList.remove("is-checking");
    }
  }

  async function loadUser() {
    if (!isAuthed()) return;
    try {
      state.user = await apiFetch(API.auth + "/me");
      renderUserChip();
      renderNav();
    } catch {
      setToken(null);
      state.user = null;
    }
  }

  /* ---------------- Bootstrap ---------------- */

  /**
   * Boot the current page: gate on auth, inject the shared shell,
   * then kick off the status check + user load.
   * Returns false when a redirect was issued (page scripts should bail).
   */
  function boot(currentPage, { authRequired = true } = {}) {
    if (authRequired && !isAuthed()) {
      location.replace("login.html");
      return false;
    }
    if (!authRequired && isAuthed()) {
      // Already signed in — send admins to the admin panel, everyone else to the scanner
      location.replace(isAdminFlag() ? "admin.html" : "scanner.html");
      return false;
    }
    activePage = currentPage;
    renderShell(currentPage);
    checkApi();
    loadUser();
    return true;
  }

  /**
   * Guard used by the admin page: resolves the current user and redirects
   * non-admins away. Returns the admin user or null when access is denied.
   */
  async function ensureAdmin() {
    const u = state.user || (state.user = await apiFetch(API.auth + "/me"));
    if (!u || !u.is_admin) {
      toast("Admin access required.");
      setTimeout(() => location.replace("scanner.html"), 400);
      return null;
    }
    return u;
  }

  return {
    API,
    TOKEN_KEY,
    state,
    $,
    qs,
    qsa,
    escapeHtml,
    getToken,
    setToken,
    setAdminFlag,
    isAdminFlag,
    isAuthed,
    verdictClass,
    severityClass,
    findingPointsClass,
    formatPoints,
    timeAgo,
    initials,
    animateValue,
    toast,
    apiFetch,
    renderShell,
    boot,
    ensureAdmin,
    CHEVRON_SVG,
  };
})();

/* ---------------- Boot: detect the current page & run ---------------- */

(function bootNow() {
  const file = (location.pathname.split("/").pop() || "index").replace(/\.html$/, "");
  const isAuthPage = file === "login" || file === "register";
  // Guard against double execution (only boot once per page load)
  if (!window.__appBooted) {
    window.__appBooted = true;
    App.boot(file, { authRequired: !isAuthPage });
  }
})();
