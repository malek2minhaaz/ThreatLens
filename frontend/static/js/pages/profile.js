/* ============================================================
   ThreatLens — Profile page (profile.html)
   ============================================================ */
"use strict";

(function () {
  if (!App.isAuthed()) return; // app.js is already redirecting
  const { $ } = App;

  /* ---------------- Phishing trends ---------------- */

  function svgTrendChart(series) {
    if (!series || series.length < 2) {
      return '<div class="table-empty">Not enough data yet — run a few phishing analyses to see trends.</div>';
    }
    const W = 600, H = 150, PAD = 14;
    const maxX = series.length - 1;
    const x = (i) => PAD + (i * (W - PAD * 2)) / maxX;
    const y = (v) => H - PAD - (Math.min(100, v) / 100) * (H - PAD * 2 - 16);
    const pts = series.map((s, i) => [x(i), y(s.avg_score)]);
    const line = pts.map(([px, py], i) => `${i ? "L" : "M"}${px.toFixed(1)},${py.toFixed(1)}`).join(" ");
    const last = pts[pts.length - 1];
    const area = `${line} L${last[0].toFixed(1)},${H - PAD} L${pts[0][0].toFixed(1)},${H - PAD} Z`;
    const dots = pts.map(([px, py]) => `<circle cx="${px.toFixed(1)}" cy="${py.toFixed(1)}" r="3.5" class="trend-dot"/>`).join("");
    const labels =
      `<text x="${pts[0][0].toFixed(1)}" y="${H - 3}" class="trend-label">${series[0].date.slice(5)}</text>` +
      `<text x="${last[0].toFixed(1)}" y="${H - 3}" text-anchor="end" class="trend-label">${series[series.length - 1].date.slice(5)}</text>`;
    return `<svg viewBox="0 0 ${W} ${H}" class="trend-chart__svg" role="img" aria-label="Average phishing score over time">
      <defs><linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="var(--danger)" stop-opacity="0.35"/>
        <stop offset="100%" stop-color="var(--danger)" stop-opacity="0.02"/>
      </linearGradient></defs>
      <path d="${area}" fill="url(#trendFill)"/>
      <path d="${line}" fill="none" stroke="var(--danger)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
      ${dots}${labels}</svg>`;
  }

  async function loadPhishTrends() {
    try {
      const t = await App.apiFetch(App.API.trends);
      $("trendTotal").textContent = t.total_analyses ?? 0;
      $("trendAvg").textContent = t.avg_score ?? "—";
      $("trendPhish").textContent = (t.verdict_distribution || {}).PHISHING ?? 0;
      $("phishTrendChart").innerHTML = svgTrendChart(t.series || []);
      const flags = t.top_flags || [];
      const maxC = Math.max(1, ...flags.map((f) => f.count));
      $("phishTopFlags").innerHTML = flags.length
        ? flags.map((f) => `
          <div class="dist-row">
            <span class="dist-row__label">${App.escapeHtml(f.label)}</span>
            <div class="dist-row__bar"><div class="dist-row__fill" data-pct="${Math.round((f.count / maxC) * 100)}" style="width:0%;background:var(--danger)"></div></div>
            <span class="dist-row__pct mono">${f.count}</span>
          </div>`).join("")
        : '<p class="muted">No phishing analyses yet.</p>';
      requestAnimationFrame(() => {
        document.querySelectorAll("#phishTopFlags .dist-row").forEach((row, i) => {
          const fill = row.querySelector(".dist-row__fill");
          setTimeout(() => { fill.style.width = fill.dataset.pct + "%"; }, 120 + i * 90);
        });
      });
    } catch { /* trends are non-fatal */ }
  }

  async function loadProfile() {
    try {
      const u = App.state.user || (App.state.user = await App.apiFetch(App.API.auth + "/me"));
      $("profileAvatar").textContent = App.initials(u.public_name);
      $("profileName").textContent = u.public_name;
      $("profileUsername").textContent = "@" + u.username;
      $("profileAdminBadge").hidden = !u.is_admin;
      $("profileEmail").textContent = u.email;
      $("profileSince").textContent = new Date(u.created_at).toLocaleDateString();
      $("profileId").textContent = "#" + u.id;
      $("pfDisplayName").value = u.display_name || "";
      $("pfEmail").value = u.email;

      const stats = await App.apiFetch(App.API.stats);
      const tiles = [
        { label: "Total scans", value: stats.total_scans, cls: "" },
        { label: "Avg risk score", value: stats.avg_risk_score ?? "—", cls: (stats.avg_risk_score ?? 100) >= 70 ? "pos" : "warn" },
        { label: "Dangerous URLs", value: stats.dangerous_scans, cls: stats.dangerous_scans ? "neg" : "pos" },
        { label: "Phishing analyses", value: stats.total_phishing_analyses, cls: "" },
        { label: "Avg phish score", value: stats.avg_phishing_score ?? "—", cls: (stats.avg_phishing_score ?? 0) >= 55 ? "neg" : "pos" },
      ];
      $("profileStats").innerHTML = tiles.map((t) => `
        <div class="stat-tile panel">
          <span class="stat-tile__value ${t.cls}">${App.escapeHtml(t.value)}</span>
          <span class="stat-tile__label">${t.label}</span>
        </div>`).join("");

      const dist = stats.verdict_distribution || {};
      const total = Object.values(dist).reduce((a, b) => a + b, 0) || 1;
      const order = ["SAFE", "LOW RISK", "SUSPICIOUS", "DANGEROUS"];
      $("profileDist").innerHTML = order.filter((v) => dist[v] > 0).map((v) => {
        const pct = Math.round((dist[v] / total) * 100);
        const color = v === "SAFE" ? "var(--safe)" : v === "LOW RISK" ? "var(--low)" : v === "SUSPICIOUS" ? "var(--amber)" : "var(--danger)";
        return `
        <div class="dist-row">
          <span class="dist-row__label">${v}</span>
          <div class="dist-row__bar"><div class="dist-row__fill" data-pct="${pct}" style="width:0%;background:${color}"></div></div>
          <span class="dist-row__pct mono">${pct}%</span>
        </div>`;
      }).join("") || '<p class="muted">No scans yet.</p>';

      // Animate distribution bars
      requestAnimationFrame(() => {
        $("profileDist").querySelectorAll(".dist-row").forEach((row, i) => {
          const fill = row.querySelector(".dist-row__fill");
          const target = fill.dataset.pct;
          setTimeout(() => { fill.style.width = target + "%"; }, 120 + i * 90);
        });
      });
    } catch (err) {
      App.toast(`Could not load profile: ${err.message}`);
    }
  }

  $("profileLogoutBtn").addEventListener("click", () => $("logoutBtn")?.click());

  $("profileForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("pfSaveBtn");
    btn.classList.add("is-loading");
    btn.disabled = true;
    try {
      const data = await App.apiFetch(App.API.auth + "/me", {
        method: "PUT",
        body: JSON.stringify({
          display_name: $("pfDisplayName").value.trim() || null,
          email: $("pfEmail").value.trim(),
        }),
      });
      App.state.user = data;
      loadProfile();
      App.toast("Profile updated.", true);
    } catch (err) {
      App.toast(err.message);
    } finally {
      btn.classList.remove("is-loading");
      btn.disabled = false;
    }
  });

  $("passwordForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const current = $("pwCurrent").value;
    const next = $("pwNew").value;
    if (next !== $("pwNew2").value) return App.toast("New passwords do not match.");
    const btn = $("pwSaveBtn");
    btn.classList.add("is-loading");
    btn.disabled = true;
    try {
      await App.apiFetch(App.API.auth + "/change-password", {
        method: "POST",
        body: JSON.stringify({ current_password: current, new_password: next }),
      });
      // All sessions are invalidated — force a re-login
      App.setToken(null);
      App.state.user = null;
      App.toast("Password changed — please sign in again.", true);
      setTimeout(() => location.replace("login.html"), 350);
    } catch (err) {
      App.toast(err.message);
    } finally {
      btn.classList.remove("is-loading");
      btn.disabled = false;
    }
  });

  /* ---------------- Download report ---------------- */

  let reportData = null;

  async function ensureReport() {
    if (reportData) return reportData;
    reportData = await App.apiFetch(App.API.report);
    return reportData;
  }

  function reportFilename(data, ext) {
    const d = new Date();
    const date = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
    return `threatlens_report_${(data.user?.username || "user")}_${date}.${ext}`;
  }

  function downloadFile(filename, content, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  function setReportStatus(msg) {
    const el = $("reportStatus");
    if (el) el.textContent = msg;
  }

  function withReportButton(btn, fn) {
    btn.classList.add("is-loading");
    btn.disabled = true;
    return Promise.resolve()
      .then(fn)
      .catch((err) => App.toast(`Report failed: ${err.message}`))
      .finally(() => {
        btn.classList.remove("is-loading");
        btn.disabled = false;
      });
  }

  /* __REPORT_BUILDERS_START__ */
  function csvCell(v) {
    let s = String(v ?? "");
    // Neutralize spreadsheet formula injection when opened in Excel/Sheets.
    if (/^[=+\-@]/.test(s)) s = "'" + s;
    return /[",\r\n]/.test(s) ? '"' + s.replaceAll('"', '""') + '"' : s;
  }

  function buildReportCSV(data) {
    const rows = [
      ["Type", "ID", "URL / Preview", "Content type", "Score (/100)", "Verdict", "Date"],
    ];
    (data.scans || []).forEach((r) => {
      rows.push(["Scan", r.id, r.url, "", r.risk_score, r.verdict, r.created_at]);
    });
    (data.phishing || []).forEach((r) => {
      const preview = (r.preview || "").replace(/\s+/g, " ").slice(0, 120);
      rows.push(["Phishing", r.id, preview, r.content_type, r.phishing_score, r.verdict, r.created_at]);
    });
    return rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
  }

  function buildReportHTML(data) {
    const esc = App.escapeHtml;
    const s = data.summary || {};
    const dist = s.verdict_distribution || {};
    const distTotal = Object.values(dist).reduce((a, b) => a + b, 0) || 1;
    const fmtDate = (iso) => {
      const tz = /(?:Z|[+-]\d\d:\d\d)$/.test(String(iso)) ? "" : "Z";
      const d = new Date((iso || "") + tz);
      return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
    };
    const badge = (verdict) => {
      const v = (verdict || "").toLowerCase();
      const cls = v.includes("danger") || v.includes("phish") ? "b-danger"
        : v.includes("suspicious") ? "b-suspicious"
        : v.includes("low") ? "b-low" : "b-safe";
      return `<span class="badge ${cls}">${esc(verdict)}</span>`;
    };

    const u = data.user || {};
    const username = u.username || "user";
    // Username is user-controlled — keep it out of the inline <script> and
    // file names by restricting it to safe characters.
    const fileBase = `threatlens_report_${String(username).replace(/[^A-Za-z0-9_-]/g, "_") || "user"}`;

    const distRows = ["SAFE", "LOW RISK", "SUSPICIOUS", "DANGEROUS"]
      .filter((v) => dist[v] > 0)
      .map((v) => {
        const pct = Math.round((dist[v] / distTotal) * 100);
        const color = v === "SAFE" ? "#059669" : v === "LOW RISK" ? "#65a30d" : v === "SUSPICIOUS" ? "#d97706" : "#dc2626";
        return `<div class="dist-row"><span class="dist-lbl">${v}</span><div class="dist-bar"><div style="width:${pct}%;background:${color}"></div></div><span class="dist-pct">${pct}%</span></div>`;
      }).join("") || '<p class="empty">No scans yet.</p>';

    const tiles = [
      ["Total URL scans", s.total_scans ?? 0],
      ["Dangerous URLs", s.dangerous_scans ?? 0],
      ["Detection rate", `${Math.round((s.detection_rate ?? 0) * 100)}%`],
      ["Phishing analyses", s.total_phishing ?? 0],
      ["Avg risk score", s.avg_risk_score ?? "—"],
      ["Avg phish score", s.avg_phishing_score ?? "—"],
    ].map(([lbl, val]) => `<div class="tile"><span class="tile-lbl">${lbl}</span><b>${esc(val)}</b></div>`).join("");

    const scans = data.scans || [];
    const phish = data.phishing || [];

    const scanTable = scans.length
      ? `<table><thead><tr><th>#</th><th>URL</th><th>Score</th><th>Verdict</th><th>Findings</th><th>Date</th></tr></thead>
         <tbody>${scans.map((r) => `<tr><td class="mono">#${r.id}</td><td class="mono url">${esc(r.url)}</td><td><b>${r.risk_score}</b>/100</td><td>${badge(r.verdict)}</td><td>${r.findings_count}</td><td class="muted">${fmtDate(r.created_at)}</td></tr>`).join("")}</tbody></table>`
      : '<p class="empty">No URL scans yet.</p>';

    const phishTable = phish.length
      ? `<table><thead><tr><th>#</th><th>Type</th><th>Preview</th><th>Score</th><th>Verdict</th><th>Date</th></tr></thead>
         <tbody>${phish.map((r) => `<tr><td class="mono">#${r.id}</td><td>${esc(r.content_type)}</td><td class="preview">${esc((r.preview || "—").slice(0, 120))}</td><td><b>${r.phishing_score}</b>/100</td><td>${badge(r.verdict)}</td><td class="muted">${fmtDate(r.created_at)}</td></tr>`).join("")}</tbody></table>`
      : '<p class="empty">No phishing analyses yet.</p>';

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>ThreatLens Activity Report — ${esc(u.public_name || username)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, -apple-system, Arial, sans-serif; background: #fff; color: #1f2d3d; margin: 0; padding: 34px; line-height: 1.5; }
  .toolbar { display: flex; justify-content: flex-end; gap: 10px; margin-bottom: 20px; }
  .toolbar button { font: 600 13px/1 'Segoe UI', sans-serif; padding: 9px 16px; border-radius: 9px; border: 1px solid #bcd3ea; background: #f0f6fd; color: #15609f; cursor: pointer; }
  .toolbar button:hover { background: #e2eefb; }
  header { border-bottom: 3px solid #1a6db5; padding-bottom: 14px; margin-bottom: 22px; }
  header h1 { margin: 0 0 6px; font-size: 26px; color: #1a6db5; }
  header p { margin: 2px 0; color: #5b7fa6; font-size: 13px; }
  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 8px; }
  .tile { border: 1px solid #dbe7f5; border-radius: 10px; background: #f5f9fe; padding: 12px 14px; }
  .tile .tile-lbl { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: #6d8db0; margin-bottom: 4px; }
  .tile b { font-size: 22px; color: #15609f; }
  section h2 { color: #1a6db5; font-size: 17px; border-bottom: 2px solid #dbe7f5; padding-bottom: 6px; margin: 30px 0 12px; }
  .dist-row { display: grid; grid-template-columns: 120px 1fr 54px; align-items: center; gap: 12px; margin-bottom: 9px; font-size: 13px; }
  .dist-lbl { font-weight: 600; }
  .dist-bar { height: 10px; border-radius: 999px; background: #eef3f9; overflow: hidden; }
  .dist-bar div { height: 100%; border-radius: 999px; }
  .dist-pct { text-align: right; color: #6d8db0; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-top: 6px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e3ecf6; vertical-align: top; }
  th { text-transform: uppercase; font-size: 10.5px; letter-spacing: .06em; color: #6d8db0; }
  .mono { font-family: Consolas, 'Courier New', monospace; font-size: 11.5px; }
  .url { max-width: 380px; word-break: break-all; }
  .preview { max-width: 340px; word-break: break-word; }
  .muted { color: #7d97b2; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 10.5px; font-weight: 700; letter-spacing: .04em; }
  .b-safe { color: #047857; background: #d9f3e9; }
  .b-low { color: #4d7c0f; background: #ecf5d3; }
  .b-suspicious { color: #b45309; background: #fdeed3; }
  .b-danger { color: #b91c1c; background: #fbdcdc; }
  .empty { color: #8aa3bd; font-size: 13px; }
  footer { margin-top: 34px; padding-top: 14px; border-top: 1px solid #e3ecf6; color: #8aa3bd; font-size: 11px; text-align: center; }
  @media print { .toolbar { display: none; } body { padding: 10px; } }
</style>
</head>
<body>
  <div class="toolbar">
    <button onclick="window.print()">🖨️ Print / Save as PDF</button>
    <button onclick="downloadHtml()">💾 Download .html</button>
  </div>

  <header>
    <h1>🛡️ ThreatLens — Activity Report</h1>
    <p><b>${esc(u.public_name || username)}</b> (@${esc(username)}) · ${esc(u.email || "")} · Member since ${fmtDate(u.created_at)}</p>
    <p>Generated ${fmtDate(data.generated_at)} · ${scans.length} scans · ${phish.length} phishing analyses</p>
  </header>

  <div class="tiles">${tiles}</div>

  <section>
    <h2>Verdict distribution</h2>
    ${distRows}
  </section>

  <section>
    <h2>URL scans (${scans.length})</h2>
    ${scanTable}
  </section>

  <section>
    <h2>Phishing analyses (${phish.length})</h2>
    ${phishTable}
  </section>

  <footer>
    Generated by ThreatLens v1.2 — Threat Detection &amp; URL Scanner.<br />
    Educational tool — always verify suspicious links through official channels.
  </footer>

  <script>
    function downloadHtml() {
      var html = '<!DOCTYPE html>\n' + document.documentElement.outerHTML;
      var blob = new Blob([html], { type: 'text/html' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = '${fileBase}_' + new Date().toISOString().slice(0, 10) + '.html';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    }
  <\/script>
</body>
</html>`;
  }
  /* __REPORT_BUILDERS_END__ */

  $("reportCsvBtn").addEventListener("click", () => withReportButton($("reportCsvBtn"), async () => {
    const data = await ensureReport();
    downloadFile(reportFilename(data, "csv"), "\uFEFF" + buildReportCSV(data), "text/csv;charset=utf-8");
    setReportStatus(`CSV downloaded — ${data.summary.total_scans} scans, ${data.summary.total_phishing} phishing analyses.`);
    App.toast("CSV report downloaded.", true);
  }));

  $("reportJsonBtn").addEventListener("click", () => withReportButton($("reportJsonBtn"), async () => {
    const data = await ensureReport();
    downloadFile(reportFilename(data, "json"), JSON.stringify(data, null, 2), "application/json");
    setReportStatus("JSON report downloaded.");
    App.toast("JSON report downloaded.", true);
  }));

  $("reportHtmlBtn").addEventListener("click", () => {
    // Open the report window synchronously (within the user gesture) so the
    // popup isn't blocked; content is written once the data arrives.
    const win = window.open("", "_blank");
    withReportButton($("reportHtmlBtn"), async () => {
      const data = await ensureReport();
      const html = buildReportHTML(data);
      const kb = (new Blob([html]).size / 1024).toFixed(1);
      if (win) {
        win.document.open();
        win.document.write(html);
        win.document.close();
        setReportStatus(`HTML report opened (${kb} KB) — use Print → Save as PDF.`);
      } else {
        downloadFile(reportFilename(data, "html"), html, "text/html");
        setReportStatus(`Popup blocked — HTML report downloaded instead (${kb} KB).`);
      }
      App.toast("HTML report ready.", true);
    });
  });

  loadProfile();
  loadPhishTrends();
})();
