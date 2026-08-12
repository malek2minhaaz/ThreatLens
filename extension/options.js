/* ============================================================
   ThreatLens Scanner — options / settings
   Sign in once, store the session token, test connectivity.
   ============================================================ */
"use strict";

document.addEventListener("DOMContentLoaded", init);

async function init() {
  const $ = (id) => document.getElementById(id);
  const cfg = await TL.getConfig();

  $("server").value = cfg.server;
  $("username").value = cfg.username || "";
  setStatus(cfg.configured ? `Signed in as ${cfg.username}` : "Not configured yet.");

  $("saveBtn").addEventListener("click", async () => {
    const server = TL.normalizeServer($("server").value);
    const username = $("username").value.trim();
    const password = $("password").value;
    if (!username || !password) {
      setStatus("Enter your username/email and password.");
      return;
    }
    $("saveBtn").disabled = true;
    setStatus("Signing in…");
    try {
      const data = await TL.api(server, "/api/auth/login", {
        method: "POST",
        body: { identifier: username, password },
      });
      await TL.setConfig({
        server,
        token: data.token,
        username: data.user?.username || username,
      });
      await ensureHostAccess(server);
      $("password").value = "";
      setStatus(`Signed in as ${data.user?.username || username} ✓`, true);
    } catch (err) {
      setStatus(`Sign-in failed: ${err.message}`);
    } finally {
      $("saveBtn").disabled = false;
    }
  });

  $("testBtn").addEventListener("click", async () => {
    const server = TL.normalizeServer($("server").value);
    $("testBtn").disabled = true;
    setStatus("Testing connection…");
    try {
      const h = await TL.api(server, "/api/health");
      setStatus(`Connected — ${h.app || "ThreatLens"} v${h.version || "?"} ✓`, true);
    } catch (err) {
      setStatus(`Connection failed: ${err.message}`);
    } finally {
      $("testBtn").disabled = false;
    }
  });

  $("signOutBtn").addEventListener("click", async () => {
    const current = await TL.getConfig();
    try {
      if (current.token) {
        await TL.api(current.server, "/api/auth/logout", { method: "POST", token: current.token });
      }
    } catch { /* server may be offline — still clear locally */ }
    await TL.clearConfig();
    chrome.runtime.sendMessage({ type: "clear-badge" });
    setStatus("Signed out.");
  });

  /** Grant host permission for non-localhost servers (prompts Chrome's UI). */
  async function ensureHostAccess(server) {
    let origin;
    try {
      origin = new URL(server).origin + "/*";
    } catch {
      return;
    }
    if (origin === "http://localhost/*" || origin === "http://127.0.0.1/*") return; // already granted
    const has = await chrome.permissions.contains({ origins: [origin] });
    if (!has) await chrome.permissions.request({ origins: [origin] });
  }

  function setStatus(msg, ok = false) {
    const el = $("status");
    el.textContent = msg;
    el.classList.toggle("ok", ok);
  }
}
