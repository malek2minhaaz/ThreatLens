/* ============================================================
   ThreatLens — Threat Intel page (intel.html)
   Provider status cards, detection summary banner and a
   card-based feed of per-scan provider verdicts. Auto-refreshes
   every 60s and offers a manual refresh button.
   ============================================================ */
"use strict";

(function () {
  if (!App.isAuthed()) return; // app.js is already redirecting
  const { $ } = App;

  const INTEL_PROVIDERS = [
    { key: "virustotal", name: "VirusTotal", desc: "Multi-engine AV consensus" },
    { key: "google_safe_browsing", name: "Google Safe Browsing", desc: "Google's malware & phishing list" },
    { key: "phishtank", name: "PhishTank", desc: "Community phishing database" },
  ];

  let feedData = { total: 0, detections: 0, feed: [] };
  let detectionFilter = "all";
  let lastFetch = null;
  let renderedOnce = false;

  /* ---------------- Provider status cards ---------------- */

  async function loadProviders() {
    try {
      const status = await App.apiFetch(App.API.intelStatus);
      $("intelProviders").innerHTML = INTEL_PROVIDERS.map((p) => {
        const on = Boolean(status[p.key]);
        return `
        <div class="panel intel-provider ${on ? "is-on" : "is-off"}">
          <div class="intel-provider__head">
            <span class="status-dot ${on ? "ok" : "skip"}"></span>
            <h4>${p.name}</h4>
          </div>
          <p class="muted">${p.desc}</p>
          <span class="sev-chip ${on ? "sev-positive" : "sev-info"}">${on ? "CONFIGURED" : "NOT CONFIGURED"}</span>
        </div>`;
      }).join("");
    } catch (err) {
      $("intelProviders").innerHTML = `<div class="panel"><p class="muted">Could not load provider status: ${App.escapeHtml(err.message)}</p></div>`;
    }
  }

  /* ---------------- Feed ---------------- */

  function isDetected(r) {
    return r.virustotal.malicious > 0 || r.google_safe_browsing.threatened || r.phishtank.in_database;
  }

  function provChip(label, state) {
    const cls = state === "bad" ? "prov-chip--bad" : state === "ok" ? "prov-chip--ok" : "prov-chip--off";
    return `<span class="prov-chip ${cls}"><span class="prov-chip__dot"></span>${label}</span>`;
  }

  function vtChip(vt) {
    if (vt.status === "ok") {
      if (vt.malicious > 0) return provChip(`${vt.malicious}/${vt.total_engines} flagged`, "bad");
      return provChip("VT clean", "ok");
    }
    return provChip(vt.status === "skipped" ? "VT —" : "VT n/a", "off");
  }

  function gsbChip(gsb) {
    if (gsb.threatened) return provChip(App.escapeHtml(gsb.threat_types?.[0] || "threat"), "bad");
    if (gsb.status === "ok") return provChip("GSB clear", "ok");
    return provChip("GSB —", "off");
  }

  function ptChip(pt) {
    if (pt.in_database) return provChip("PhishTank listed", "bad");
    if (pt.status === "ok") return provChip("PhishTank clear", "ok");
    return provChip("PT —", "off");
  }

  function feedCard(r, idx) {
    const scoreCls = r.risk_score >= 70 ? "safe" : r.risk_score >= 40 ? "warn" : "danger";
    return `
    <article class="record-card" data-id="${r.scan_id}" tabindex="0"
      title="${App.escapeHtml(r.url)} — open full report" style="animation-delay:${Math.min(0.3, 0.035 * idx)}s">
      <div class="record-card__top">
        <span class="score-pill score-pill--${scoreCls}">${r.risk_score}<span class="score-pill__unit">SAFE</span></span>
        <div class="record-card__body">
          <span class="record-card__url">${App.escapeHtml(r.url)}</span>
          <span class="record-card__meta">
            <span>#${r.scan_id}</span><span class="meta-sep">·</span>
            <span>${App.timeAgo(r.created_at)}</span>
          </span>
        </div>
        <span class="chevron" aria-hidden="true">${App.CHEVRON_SVG}</span>
      </div>
      <div class="provider-verdicts">
        ${vtChip(r.virustotal)}
        ${gsbChip(r.google_safe_browsing)}
        ${ptChip(r.phishtank)}
      </div>
    </article>`;
  }

  function renderSummary() {
    const { total, detections, feed } = feedData;
    const pct = total ? Math.round((detections / total) * 100) : 0;
    $("intelSummary").innerHTML = `
      <span class="summary-banner__pct" style="color:${pct >= 40 ? "var(--danger)" : pct >= 15 ? "var(--amber)" : "var(--safe)"}">${pct}%</span>
      <div class="summary-banner__text">
        <strong>${detections}</strong> of <strong>${total}</strong> recent scans produced a threat-intel detection${total === 0 ? " — scan a URL to populate this feed." : "."}
      </div>
      <div class="summary-banner__bar">
        <div class="summary-banner__fill" style="width:0%"></div>
      </div>`;
    const fill = $("intelSummary")?.querySelector(".summary-banner__fill");
    if (fill) {
      requestAnimationFrame(() => {
        fill.style.width = pct + "%";
      });
    }
  }

  function renderDetectionChips() {
    const { total, detections, feed } = feedData;
    const clear = total - detections;
    const chips = [
      { key: "all", label: "All", count: total },
      { key: "detected", label: "Detected", count: detections },
      { key: "clear", label: "Clear", count: clear },
    ];
    $("detectionChips").innerHTML = chips.map((c) => `
      <button class="filter-chip${detectionFilter === c.key ? " is-active" : ""}" data-filter="${c.key}">
        ${c.label}<span class="filter-chip__count">${c.count}</span>
      </button>`).join("");
  }

  function renderFeed() {
    const { feed } = feedData;
    const visible = detectionFilter === "all"
      ? feed
      : feed.filter((r) => (detectionFilter === "detected" ? isDetected(r) : !isDetected(r)));

    const grid = $("intelFeed");
    const empty = $("intelEmpty");

    if (!visible.length) {
      grid.innerHTML = "";
      empty.hidden = false;
    } else {
      empty.hidden = true;
      grid.innerHTML = visible.map((r, i) => feedCard(r, i)).join("");
      if (renderedOnce) grid.querySelectorAll(".record-card").forEach((c) => c.classList.add("no-anim"));
      renderedOnce = true;

      grid.querySelectorAll(".record-card[data-id]").forEach((card) => {
        card.addEventListener("click", () => location.href = `scanner.html?report=${card.dataset.id}`);
        card.addEventListener("keydown", (e) => {
          if (e.key === "Enter" || e.key === " ") { e.preventDefault(); location.href = `scanner.html?report=${card.dataset.id}`; }
        });
      });
    }

    lastFetch = Date.now();
    $("intelUpdated").textContent = `Feed auto-refreshes every 60s · last updated ${App.timeAgo(new Date(lastFetch).toISOString())}`;
  }

  async function loadFeed({ silent = false } = {}) {
    try {
      const data = await App.apiFetch(App.API.intelFeed + "?limit=50");
      feedData = data;
      renderSummary();
      renderDetectionChips();
      renderFeed();
    } catch (err) {
      if (!silent) App.toast(`Could not load intel feed: ${err.message}`);
    }
  }

  /* ---------------- Actions ---------------- */

  $("intelRefresh").addEventListener("click", async () => {
    const icon = $("refreshIcon");
    icon.classList.add("is-spinning");
    try {
      await loadFeed();
      App.toast("Threat intel feed refreshed.", true);
    } finally {
      icon.classList.remove("is-spinning");
    }
  });

  $("detectionChips").addEventListener("click", (e) => {
    const chip = e.target.closest(".filter-chip");
    if (!chip) return;
    detectionFilter = chip.dataset.filter;
    renderDetectionChips();
    renderFeed();
  });

  /* ---------------- Init ---------------- */

  loadProviders();
  loadFeed();
  setInterval(() => loadFeed({ silent: true }), 60000);
})();
