/* ============================================================
   ThreatLens Scanner — popup
   Pre-fills the active tab's URL and scans it on demand.
   ============================================================ */
"use strict";

document.addEventListener("DOMContentLoaded", init);

async function init() {
  const $ = (id) => document.getElementById(id);
  const cfg = await TL.getConfig();

  $("optionsBtn").addEventListener("click", () => chrome.runtime.openOptionsPage());
  $("openOptions").addEventListener("click", () => chrome.runtime.openOptionsPage());

  if (!cfg.configured) {
    $("unconfigured").hidden = false;
    $("scanArea").hidden = true;
    $("results").hidden = true;
    return;
  }

  // Pre-fill with the current tab's URL
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) $("urlInput").value = tab.url;
  } catch { /* ignore */ }

  const scanBtn = $("scanBtn");
  const doScan = () => {
    const url = $("urlInput").value.trim();
    if (!url) {
      setStatus("Enter a URL to scan.");
      $("urlInput").focus();
      return;
    }
    scanUrl(url);
  };

  scanBtn.addEventListener("click", doScan);
  $("urlInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") doScan();
  });
  $("reauthLink").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });

  async function scanUrl(url) {
    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning…";
    setStatus("");
    $("results").hidden = true;
    $("reauth").hidden = true;
    try {
      const data = await TL.scan(cfg.server, cfg.token, url);
      render(data);
      chrome.runtime.sendMessage({ type: "set-badge", score: data.risk_score, verdict: data.verdict });
    } catch (err) {
      setStatus(`Scan failed: ${err.message}`);
      if (err.status === 401) $("reauth").hidden = false;
      console.error(err);
    } finally {
      scanBtn.disabled = false;
      scanBtn.textContent = "Scan URL";
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
      whois.age_display || "no WHOIS",
      ssl.valid ? `TLS valid` : ssl.available ? "TLS invalid" : "no TLS",
      `HTTP ${http.status_code || "—"}`,
      TL.fmtDuration(data.duration_ms),
    ].join(" · ");

    const list = $("findings");
    list.innerHTML = data.findings
      .slice(0, 6)
      .map((f) => `
        <div class="finding f-${f.severity}">
          <span class="f-pts ${f.points > 0 ? "pos" : f.points < 0 ? "neg" : ""}">${f.points > 0 ? "+" + f.points : f.points}</span>
          <div>
            <div class="f-title">${TL.escapeHtml(f.label)}</div>
            <div class="f-detail">${TL.escapeHtml(f.detail)}</div>
          </div>
        </div>`)
      .join("");
    if (data.findings.length > 6) {
      list.insertAdjacentHTML("beforeend", `<div class="more">+ ${data.findings.length - 6} more findings</div>`);
    }

    const report = $("openReport");
    report.href = `${cfg.server}/scanner.html${data.scan_id ? `?report=${data.scan_id}` : ""}`;
    report.hidden = false;

    $("results").hidden = false;
  }

  function setStatus(msg) {
    $("status").textContent = msg;
  }
}
