/* ============================================================
   ThreatLens — URL Scanner page (scanner.html)
   Scan flow, animated gauge, findings, tabs, raw JSON export.
   Supports deep links:  scanner.html?report=ID  and  ?url=…
   ============================================================ */
"use strict";

(function () {
  if (!App.isAuthed()) return; // app.js is already redirecting
  const { $, qsa } = App;

  let stagger = 0;

  /* ---------------- Scan flow ---------------- */

  $("scanForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const input = $("urlInput").value.trim();
    if (!input) {
      App.toast("Please enter a URL to scan.");
      $("urlInput").focus();
      return;
    }
    runScan(input);
  });

  qsa(".chip[data-sample]").forEach((chip) => {
    chip.addEventListener("click", () => {
      $("urlInput").value = chip.dataset.sample;
      runScan(chip.dataset.sample);
    });
  });

  // Keyboard shortcut: press "/" to focus the URL field (from anywhere)
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "")) {
      e.preventDefault();
      $("urlInput").focus();
      $("urlInput").select();
    }
  });

  async function runScan(url) {
    const btn = $("scanBtn");
    const placeholder = $("scanPlaceholder");
    const loading = $("scanLoading");
    const report = $("scanReport");

    placeholder.hidden = true;
    report.hidden = true;
    loading.hidden = false;
    btn.classList.add("is-loading");
    btn.disabled = true;
    $("loadingUrl").textContent = url;

    const steps = ["pipe-heuristics", "pipe-metadata", "pipe-intel", "pipe-score"];
    steps.forEach((s) => $(s).classList.remove("is-active", "is-done"));
    const timers = steps.map((s, i) =>
      setTimeout(() => {
        $(s).classList.add("is-active");
        if (i > 0) {
          $(steps[i - 1]).classList.remove("is-active");
          $(steps[i - 1]).classList.add("is-done");
        }
      }, 500 + i * 700)
    );

    try {
      const data = await App.apiFetch(App.API.scan, { method: "POST", body: JSON.stringify({ url }) });
      timers.forEach(clearTimeout);
      steps.forEach((s) => $(s).classList.add("is-done"));
      renderReport(data);
      loading.hidden = true;
      report.hidden = false;
    } catch (err) {
      timers.forEach(clearTimeout);
      loading.hidden = true;
      placeholder.hidden = false;
      App.toast(`Scan failed: ${err.message}`);
      console.error(err);
    } finally {
      btn.classList.remove("is-loading");
      btn.disabled = false;
    }
  }

  /* ---------------- Mode switch (single / bulk) ---------------- */

  qsa(".mode-switch__btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const mode = btn.dataset.mode;
      qsa(".mode-switch__btn").forEach((b) => {
        b.classList.toggle("is-active", b === btn);
        b.setAttribute("aria-selected", b === btn ? "true" : "false");
      });
      $("scanForm").hidden = mode !== "single";
      $("bulkForm").hidden = mode !== "bulk";
    });
  });

  /* ---------------- Bulk scan ---------------- */

  $("bulkForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const urls = $("bulkUrls").value
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (!urls.length) {
      App.toast("Paste at least one URL to scan.");
      $("bulkUrls").focus();
      return;
    }
    runBulkScan(urls);
  });

  async function runBulkScan(urls) {
    const unique = Array.from(new Set(urls)).slice(0, 25);
    if (unique.length < urls.length) App.toast(`Deduplicated to ${unique.length} unique URLs.`, true);

    const btn = $("bulkScanBtn");
    const loading = $("bulkLoading");
    const results = $("bulkResults");

    results.hidden = true;
    loading.hidden = false;
    $("bulkProgress").textContent = String(unique.length);
    btn.classList.add("is-loading");
    btn.disabled = true;

    try {
      const data = await App.apiFetch(App.API.scanBulk, { method: "POST", body: JSON.stringify({ urls: unique }) });
      renderBulkResults(data);
      loading.hidden = true;
      results.hidden = false;
      results.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      loading.hidden = true;
      App.toast(`Bulk scan failed: ${err.message}`);
      console.error(err);
    } finally {
      btn.classList.remove("is-loading");
      btn.disabled = false;
    }
  }

  function scoreColor(score) {
    if (score >= 85) return "var(--safe)";
    if (score >= 70) return "var(--low)";
    if (score >= 40) return "var(--suspicious)";
    return "var(--danger)";
  }

  function renderBulkResults(data) {
    const summary = data.summary || {};
    const tiles = [
      ["Safe", summary.safe || 0, "safe"],
      ["Low risk", summary.low_risk || 0, "low"],
      ["Suspicious", summary.suspicious || 0, "susp"],
      ["Dangerous", summary.dangerous || 0, "danger"],
      ["Failed", summary.failed || 0, "fail"],
    ];
    $("bulkSummary").innerHTML = tiles
      .map(([label, n, cls]) =>
        `<div class="stat-tile bulk-tile bulk-tile--${cls}"><span class="stat-tile__value">${n}</span><span class="stat-tile__label">${label}</span></div>`
      )
      .join("");

    const rows = [];
    data.results.forEach((r, i) => {
      if (r.error) {
        rows.push(`
          <tr class="bulk-row" data-i="${i}">
            <td class="mono">${i + 1}</td>
            <td class="url-cell">${App.escapeHtml(r.url)}</td>
            <td class="score-cell" style="color:var(--danger)">—</td>
            <td><span class="verdict-badge verdict-badge--sm v-danger">Error</span></td>
            <td colspan="2" class="muted">${App.escapeHtml(r.error)}</td>
            <td></td>
          </tr>`);
        return;
      }
      rows.push(`
        <tr class="bulk-row" data-i="${i}" tabindex="0" aria-expanded="false">
          <td class="mono">${i + 1}</td>
          <td class="url-cell" title="${App.escapeHtml(r.url)}">${App.escapeHtml(r.url)}</td>
          <td><span class="bulk-score" style="color:${scoreColor(r.risk_score)}">${r.risk_score}</span><span class="bulk-score__unit">/100</span></td>
          <td><span class="verdict-badge verdict-badge--sm ${App.verdictClass(r.verdict)}">${App.escapeHtml(r.verdict)}</span></td>
          <td class="mono">${r.findings.length}</td>
          <td class="mono">${(r.duration_ms / 1000).toFixed(1)}s</td>
          <td><span class="bulk-chevron" aria-hidden="true">▸</span></td>
        </tr>
        <tr class="bulk-details" data-for="${i}" hidden>
          <td colspan="7">
            <div class="bulk-findings">${r.findings.length
              ? r.findings.map((f) => findingHTML(f)).join("")
              : '<div class="table-empty">No findings — clean scan.</div>'}
            </div>
          </td>
        </tr>`);
    });
    $("bulkTableBody").innerHTML = rows.join("");

    // Expand / collapse a row's findings
    qsa(".bulk-row").forEach((row) => {
      const toggle = () => {
        const detail = qs(`.bulk-details[data-for="${row.dataset.i}"]`);
        if (!detail) return;
        detail.hidden = !detail.hidden;
        row.classList.toggle("is-open", !detail.hidden);
        row.setAttribute("aria-expanded", String(!detail.hidden));
      };
      row.addEventListener("click", toggle);
      row.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          toggle();
        }
      });
    });

    // CSV export
    const csvBtn = $("bulkCsvBtn");
    csvBtn.hidden = data.results.length === 0;
    csvBtn.onclick = () => {
      const head = "url,risk_score,verdict,risk_level,findings_count,duration_ms";
      const lines = data.results.map((r) =>
        [r.url, r.risk_score ?? "", r.verdict ?? "", r.risk_level ?? "", r.findings?.length ?? "", r.duration_ms ?? ""]
          .map((v) => `"${String(v ?? "").replaceAll('"', '""')}"`)
          .join(",")
      );
      const csv = [head, ...lines].join("\n");
      const a = document.createElement("a");
      a.href = "data:text/csv;charset=utf-8," + encodeURIComponent(csv);
      a.download = `threatlens-bulk-scan-${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
    };
  }

  /* ---------------- Report rendering ---------------- */

  function renderReport(data, opts = {}) {
    const score = data.risk_score;
    const circumference = 540.35;
    const offset = circumference * (1 - score / 100);
    const bar = $("gaugeBar");
    const color =
      score >= 85 ? "var(--safe)" :
      score >= 70 ? "var(--low)" :
      score >= 40 ? "var(--amber)" : "var(--danger)";

    $("gaugeValue").textContent = score;
    $("verdictBadge").textContent = data.verdict;
    $("verdictBadge").className = "verdict-badge " + App.verdictClass(data.verdict);
    $("riskLevelText").textContent = `Risk level: ${data.risk_level}`;
    $("reportUrl").textContent = data.request.normalized_url;

    bar.style.stroke = color;
    bar.style.transition = "none";
    bar.style.strokeDashoffset = circumference;
    void bar.getBoundingClientRect();
    requestAnimationFrame(() => {
      bar.style.transition = "stroke-dashoffset 1.1s cubic-bezier(0.22,1,0.36,1)";
      bar.style.strokeDashoffset = offset;
    });
    App.animateValue($("gaugeValue"), 0, score, 900);

    renderStats(data);
    renderFindings(data);
    renderHeuristicsTab(data);
    renderMetadataTab(data);

    const rawEl = $("rawJson");
    rawEl.textContent = JSON.stringify(data, null, 2);
    $("downloadJson").href = "data:application/json;charset=utf-8," + encodeURIComponent(rawEl.textContent);

    $("tabCountBreakdown").textContent = data.findings.length;
    $("tabCountHeuristics").textContent = data.findings.filter((f) => f.category === "Heuristics").length;

    if (!opts.keepVisible) {
      $("scanReport").hidden = false;
      $("scanPlaceholder").hidden = true;
      $("scanReport").scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function renderStats(data) {
    const whois = data.metadata.whois || {};
    const ssl = data.metadata.ssl || {};
    const http = data.metadata.http || {};
    const vt = data.threat_intel.virustotal || {};

    $("statAge").textContent = whois.age_display || "unavailable";
    $("statAge").className = "stat__value " + (whois.available ? "pos" : "warn");

    const sslTxt = ssl.available ? (ssl.valid ? `Valid (${ssl.days_remaining}d)` : "Invalid") : "No TLS";
    $("statSsl").textContent = sslTxt;
    $("statSsl").className = "stat__value " + (ssl.valid ? "pos" : ssl.available ? "neg" : "warn");

    $("statHttp").textContent = http.status_code || http.error || "—";
    $("statHttp").className = "stat__value " + (http.status_code >= 400 ? "neg" : "pos");

    const av = vt.status === "ok" ? `${vt.malicious}/${vt.total_engines} flagged` : vt.status === "skipped" ? "not configured" : "unavailable";
    $("statAv").textContent = av;
    $("statAv").className = "stat__value " + (vt.malicious ? "neg" : "pos");

    $("statRedirects").textContent = http.redirect_count ?? "—";
    $("statRedirects").className = "stat__value " + (http.final_domain_changed ? "neg" : "pos");

    $("statTime").textContent = data.duration_ms ? `${(data.duration_ms / 1000).toFixed(1)}s` : "—";
  }

  function findingHTML(f) {
    const delay = Math.min(0.3, 0.03 * stagger);
    return `
    <div class="finding f-sev-${f.severity}" style="animation-delay:${delay}s">
      <div class="finding__points ${App.findingPointsClass(f.points)}">${App.formatPoints(f.points)}</div>
      <div class="finding__body">
        <div class="finding__title">${App.escapeHtml(f.label)}
          <span class="sev-chip ${App.severityClass(f.severity)}">${App.escapeHtml(f.severity)}</span>
        </div>
        <div class="finding__detail">${App.escapeHtml(f.detail)}</div>
      </div>
      <div class="finding__meta"><span class="cat-tag">${App.escapeHtml(f.category)}</span></div>
    </div>`;
  }

  function renderFindings(data) {
    stagger = 0;
    const totals = data.category_totals || {};
    const catNames = ["Heuristics", "Metadata", "Threat Intelligence"];
    $("breakdownCats").innerHTML = catNames
      .filter((c) => c in totals)
      .map((c) => {
        const pts = totals[c];
        return `<div class="cat-card">
          <span class="cat-card__name">${c}</span>
          <span class="cat-card__points ${App.findingPointsClass(pts)}">${App.formatPoints(pts)}</span>
        </div>`;
      })
      .join("");

    $("findingsList").innerHTML = data.findings.map((f) => { const h = findingHTML(f); stagger++; return h; }).join("");
  }

  function renderHeuristicsTab(data) {
    stagger = 0;
    const list = data.findings.filter((f) => f.category === "Heuristics");
    $("heuristicsList").innerHTML = list.length
      ? list.map((f) => { const h = findingHTML(f); stagger++; return h; }).join("")
      : '<div class="table-empty">No heuristic findings.</div>';
  }

  function renderMetadataTab(data) {
    const whois = data.metadata.whois || {};
    const ssl = data.metadata.ssl || {};
    const http = data.metadata.http || {};

    $("metadataPanel").innerHTML = `
    <div class="detail-grid">
      <div class="detail-card">
        <h4>WHOIS <span class="status-dot ${whois.available ? "ok" : "warn"}"></span></h4>
        ${whois.error ? `<p class="error-note">⚠ ${App.escapeHtml(whois.error)}</p>` : ""}
        <dl>
          <dt>Registered</dt><dd>${App.escapeHtml(whois.creation_date || "—")}</dd>
          <dt>Age</dt><dd>${App.escapeHtml(whois.age_display || "—")}</dd>
          <dt>Expires</dt><dd>${App.escapeHtml(whois.expiration_date || "—")}</dd>
          <dt>Registrar</dt><dd>${App.escapeHtml(whois.registrar || "—")}</dd>
          <dt>Name servers</dt><dd>${App.escapeHtml((whois.name_servers || []).slice(0, 3).join(", ") || "—")}</dd>
        </dl>
      </div>
      <div class="detail-card">
        <h4>TLS Certificate <span class="status-dot ${ssl.available ? (ssl.valid ? "ok" : "bad") : "warn"}"></span></h4>
        ${ssl.error && !ssl.available ? `<p class="error-note">⚠ ${App.escapeHtml(ssl.error)}</p>` : ""}
        <dl>
          <dt>Issuer</dt><dd>${App.escapeHtml(ssl.issuer || "—")}</dd>
          <dt>Subject</dt><dd>${App.escapeHtml(ssl.subject || "—")}</dd>
          <dt>Valid from</dt><dd>${App.escapeHtml((ssl.valid_from || "—").replace("T", " ").slice(0, 16))}</dd>
          <dt>Valid to</dt><dd>${App.escapeHtml((ssl.valid_to || "—").replace("T", " ").slice(0, 16))}</dd>
          <dt>Days remaining</dt><dd>${ssl.days_remaining !== undefined ? ssl.days_remaining : "—"}</dd>
        </dl>
      </div>
      <div class="detail-card">
        <h4>HTTP & Redirects <span class="status-dot ${http.available ? "ok" : "warn"}"></span></h4>
        ${http.error && !http.available ? `<p class="error-note">⚠ ${App.escapeHtml(http.error)}</p>` : ""}
        <dl>
          <dt>Status</dt><dd>${App.escapeHtml(http.status_code ?? "—")}</dd>
          <dt>Server</dt><dd>${App.escapeHtml(http.server_header || "—")}</dd>
          <dt>Content-Type</dt><dd>${App.escapeHtml(http.content_type || "—")}</dd>
          <dt>Final host</dt><dd>${App.escapeHtml(http.final_host || "—")}</dd>
          <dt>Redirects</dt><dd>${http.redirect_count ?? "—"}</dd>
        </dl>
        ${http.redirect_chain && http.redirect_chain.length > 1 ? `
          <div class="redirect-chain">
            ${http.redirect_chain.slice(0, 6).map((u) => `<span class="mono">↳ ${App.escapeHtml(u)}</span>`).join("")}
          </div>` : ""}
      </div>
    </div>`;
  }

  /* ---------------- Report tabs ---------------- */

  qsa(".tab[data-tab]").forEach((tab) => {
    tab.addEventListener("click", () => {
      qsa(".tab[data-tab]").forEach((t) => {
        t.classList.remove("is-active");
        t.setAttribute("aria-selected", "false");
      });
      qsa(".tab-panel").forEach((p) => {
        p.classList.remove("is-active");
        p.hidden = true;
      });
      tab.classList.add("is-active");
      tab.setAttribute("aria-selected", "true");
      const panel = $("tab-" + tab.dataset.tab);
      if (panel) {
        panel.classList.add("is-active");
        panel.hidden = false;
      }
    });
  });

  $("copyJson").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("rawJson").textContent);
      App.toast("Report JSON copied to clipboard.", true);
    } catch {
      App.toast("Could not copy — select the JSON manually.");
    }
  });

  /* ---------------- Deep links ---------------- */

  const params = new URLSearchParams(location.search);

  if (params.get("url")) {
    $("urlInput").value = params.get("url");
  }

  if (params.get("report")) {
    openReport(params.get("report"));
  }

  async function openReport(id) {
    try {
      const data = await App.apiFetch(`${App.API.history}/${id}`);
      renderReport(data);
      App.toast(`Loaded historical scan #${id}`, true);
    } catch (err) {
      App.toast(`Failed to load scan: ${err.message}`);
    }
  }
})();
