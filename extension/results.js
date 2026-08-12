/* ============================================================
   ThreatLens Scanner — full report page (context-menu target)
   Reads ?url=…, scans it and renders the complete report.
   ============================================================ */
"use strict";

document.addEventListener("DOMContentLoaded", init);

async function init() {
  const $ = (id) => document.getElementById(id);
  const cfg = await TL.getConfig();

  if (!cfg.configured) {
    $("loading").hidden = true;
    $("error").hidden = false;
    $("error").textContent = "ThreatLens isn't configured. Open the extension settings and sign in first.";
    return;
  }

  const url = new URLSearchParams(location.search).get("url") || "";

  $("openDashboard").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: buildDashboardUrl() });
  });
  $("rescan").addEventListener("click", (e) => {
    e.preventDefault();
    runScan(url);
  });
  $("toggleRaw").addEventListener("click", (e) => {
    e.preventDefault();
    const raw = $("raw");
    raw.hidden = !raw.hidden;
    $("toggleRaw").textContent = raw.hidden ? "Show raw JSON" : "Hide raw JSON";
  });

  function buildDashboardUrl() {
    return `${cfg.server}/scanner.html${lastScanId ? `?report=${lastScanId}` : `?url=${encodeURIComponent(url)}`}`;
  }

  let lastScanId = null;

  async function runScan(target) {
    $("error").hidden = true;
    $("report").hidden = true;
    $("loading").hidden = false;
    $("loading").textContent = `Scanning ${target}…`;
    try {
      const data = await TL.scan(cfg.server, cfg.token, target);
      lastScanId = data.scan_id || null;
      render(data);
      chrome.runtime.sendMessage({ type: "set-badge", score: data.risk_score, verdict: data.verdict });
      $("loading").hidden = true;
      $("report").hidden = false;
    } catch (err) {
      $("loading").hidden = true;
      $("error").hidden = false;
      $("error").textContent = `Scan failed: ${err.message}`;
      if (err.status === 401) $("error").textContent += " — open the extension settings to re-sign in.";
      console.error(err);
    }
  }

  function render(data) {
    const score = data.risk_score;
    const ring = $("scoreRing");
    ring.style.background = `conic-gradient(${TL.scoreColor(score)} ${score * 3.6}deg, rgba(148,163,184,0.15) 0deg)`;
    $("scoreValue").textContent = score;
    $("verdict").textContent = data.verdict;
    $("verdict").className = "verdict " + TL.verdictClass(data.verdict);
    $("scanUrl").textContent = data.request.normalized_url;

    const whois = data.metadata.whois || {};
    const ssl = data.metadata.ssl || {};
    const http = data.metadata.http || {};
    $("scanMeta").textContent = [
      `WHOIS: ${whois.age_display || "unavailable"}`,
      `TLS: ${ssl.valid ? "valid" : ssl.available ? "invalid" : "none"}`,
      `HTTP: ${http.status_code || "—"}`,
      `Time: ${TL.fmtDuration(data.duration_ms)}`,
    ].join(" · ");

    const totals = data.category_totals || {};
    $("cats").innerHTML = ["Heuristics", "Metadata", "Threat Intelligence"]
      .filter((c) => c in totals)
      .map((c) => {
        const pts = totals[c];
        return `<div class="cat"><div class="cat__name">${c}</div><div class="cat__pts ${pts > 0 ? "pos" : pts < 0 ? "neg" : ""}">${pts > 0 ? "+" + pts : pts}</div></div>`;
      })
      .join("");

    $("findings").innerHTML = data.findings.length
      ? data.findings.map((f) => `
          <div class="finding f-${f.severity}">
            <span class="f-pts ${f.points > 0 ? "pos" : f.points < 0 ? "neg" : ""}">${f.points > 0 ? "+" + f.points : f.points}</span>
            <div>
              <div class="f-title">${TL.escapeHtml(f.label)} <span style="color:var(--mute);font-size:11px">· ${TL.escapeHtml(f.category)}</span></div>
              <div class="f-detail">${TL.escapeHtml(f.detail)}</div>
            </div>
          </div>`).join("")
      : '<div class="empty">No findings — clean scan.</div>';

    $("raw").textContent = JSON.stringify(data, null, 2);
    $("raw").hidden = true;
    $("toggleRaw").textContent = "Show raw JSON";
  }

  runScan(url);
}
