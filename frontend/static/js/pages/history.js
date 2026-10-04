/* ============================================================
   ThreatLens — History page (history.html)
   Card-based history with live search, verdict filter chips,
   sorting, stat tiles and tabbed URL-scan / phishing views.
   ============================================================ */
"use strict";

(function () {
  if (!App.isAuthed()) return; // app.js is already redirecting
  const { $, qsa } = App;

  const TAB = {
    scans: { api: App.API.history + "?limit=50", label: "scans" },
    phishing: { api: App.API.phishingHistory + "?limit=50", label: "analyses" },
  };

  let scans = null;   // { total, items: [...] }
  let phish = null;   // { total, items: [...] }
  let activeTab = "scans";
  let query = "";
  let filter = "all";
  let sort = "newest";
  let renderedOnce = false;

  /* ---------------- Loading ---------------- */

  async function loadTab(tab, force = false) {
    const cache = tab === "scans" ? scans : phish;
    if (cache && !force) return cache;
    try {
      const data = await App.apiFetch(TAB[tab].api);
      if (tab === "scans") scans = data;
      else phish = data;
      return data;
    } catch (err) {
      App.toast(`Could not load ${TAB[tab].label}: ${err.message}`);
      return { total: 0, items: [] };
    }
  }

  /* ---------------- Card templates ---------------- */

  function scorePill(score, kind) {
    let cls = "safe";
    if (kind === "scan") cls = score >= 70 ? "safe" : score >= 40 ? "warn" : "danger";
    else cls = score >= 55 ? "danger" : score >= 25 ? "warn" : "safe";
    const unit = kind === "scan" ? "SAFE" : "/100";
    return `<span class="score-pill score-pill--${cls}">${score}<span class="score-pill__unit">${unit}</span></span>`;
  }

  function scanCard(r, idx) {
    return `
    <article class="record-card" data-id="${r.id}" tabindex="0"
      title="${App.escapeHtml(r.url)} — open full report" style="animation-delay:${Math.min(0.3, 0.035 * idx)}s">
      <div class="record-card__top">
        ${scorePill(r.risk_score, "scan")}
        <div class="record-card__body">
          <span class="record-card__url">${App.escapeHtml(r.url)}</span>
          <span class="record-card__meta">
            <span>#${r.id}</span><span class="meta-sep">·</span>
            <span>${r.findings_count} findings</span><span class="meta-sep">·</span>
            <span>${App.timeAgo(r.created_at)}</span>
          </span>
        </div>
        <span class="record-card__verdict"><span class="verdict-badge verdict-badge--sm ${App.verdictClass(r.verdict)}">${App.escapeHtml(r.verdict)}</span></span>
      </div>
      <div class="record-card__foot">
        <div class="mini-chips">
          <span class="mini-chip">Risk ${r.risk_score}/100</span>
          <span class="mini-chip">${new Date(r.created_at).toLocaleDateString()}</span>
        </div>
        <span class="chevron" aria-hidden="true">${App.CHEVRON_SVG}</span>
      </div>
    </article>`;
  }

  function phishCard(r, idx) {
    const preview = (r.preview || "No preview stored").slice(0, 90);
    return `
    <article class="record-card is-static" title="Phishing analyses are viewable in the Phishing Lab">
      <div class="record-card__top">
        ${scorePill(r.phishing_score, "phish")}
        <div class="record-card__body">
          <span class="record-card__url">${App.escapeHtml(preview)}${(r.preview || "").length > 90 ? "…" : ""}</span>
          <span class="record-card__meta">
            <span>#${r.id}</span><span class="meta-sep">·</span>
            <span>${App.escapeHtml(r.content_type)}</span><span class="meta-sep">·</span>
            <span>${App.timeAgo(r.created_at)}</span>
          </span>
        </div>
        <span class="record-card__verdict"><span class="verdict-badge verdict-badge--sm ${App.verdictClass(r.verdict)}">${App.escapeHtml(r.verdict)}</span></span>
      </div>
      <div class="record-card__foot">
        <div class="mini-chips">
          <span class="mini-chip">${new Date(r.created_at).toLocaleDateString()}</span>
        </div>
        <span class="mini-chip">${r.content_type}</span>
      </div>
    </article>`;
  }

  /* ---------------- Filtering / sorting ---------------- */

  function searchable(item) {
    return `${item.url || ""} ${item.verdict || ""} ${item.content_type || ""} ${item.id || ""}`.toLowerCase();
  }

  function visibleItems() {
    let items = activeTab === "scans" ? scans.items : phish.items;
    if (query) items = items.filter((it) => searchable(it).includes(query));
    if (filter !== "all") items = items.filter((it) => String(it.verdict).toLowerCase() === filter);

    const field = activeTab === "scans" ? "risk_score" : "phishing_score";
    const dir = sort === "oldest" || sort === "risk-low" ? 1 : -1;
    return [...items].sort((a, b) => {
      if (sort === "newest" || sort === "oldest") return (new Date(a.created_at) - new Date(b.created_at)) * dir;
      return (a[field] - b[field]) * dir;
    });
  }

  /* ---------------- Rendering ---------------- */

  function buildVerdictChips(items) {
    const counts = { all: items.length };
    items.forEach((it) => {
      const v = String(it.verdict).toLowerCase();
      counts[v] = (counts[v] || 0) + 1;
    });
    const order = ["all", ...Object.keys(counts).filter((k) => k !== "all")];
    $("verdictChips").innerHTML = order.map((v) => `
      <button class="filter-chip${filter === v ? " is-active" : ""}" data-filter="${v}">
        ${v === "all" ? "All" : App.escapeHtml(v.toUpperCase())}<span class="filter-chip__count">${counts[v]}</span>
      </button>`).join("");
  }

  function renderCards() {
    const items = visibleItems();
    const grid = $("historyCards");
    const empty = $("historyEmpty");
    const meta = $("resultMeta");
    const total = activeTab === "scans" ? scans.total : phish.total;

    if (!items.length) {
      grid.innerHTML = "";
      empty.hidden = false;
      if (query || filter !== "all") {
        $("emptyTitle").textContent = "No matching records";
        $("emptyBody").textContent = `Nothing matches your search / filter${activeTab === "scans" ? " — try clearing it." : "."}`;
      } else {
        $("emptyTitle").textContent = activeTab === "scans" ? "No scans yet" : "No phishing analyses yet";
        $("emptyBody").textContent = activeTab === "scans"
          ? "Run your first scan in the URL Scanner."
          : "Analyze some content in the Phishing Lab.";
      }
    } else {
      empty.hidden = true;
      grid.innerHTML = items.map((r, i) =>
        (activeTab === "scans" ? scanCard(r, i) : phishCard(r, i))
      ).join("");
      if (renderedOnce) qsa(".record-card", grid).forEach((c) => c.classList.add("no-anim"));
      renderedOnce = true;

      grid.querySelectorAll(".record-card[data-id]").forEach((card) => {
        card.addEventListener("click", () => openReport(card.dataset.id));
        card.addEventListener("keydown", (e) => {
          if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openReport(card.dataset.id); }
        });
      });
    }

    const noun = activeTab === "scans" ? "scans" : "analyses";
    meta.textContent = `Showing ${items.length} of ${total} ${noun}${query ? ` · filter: “${query}”` : ""}`;
  }

  function renderStats() {
    const data = activeTab === "scans" ? scans : phish;
    const items = data.items;
    const field = activeTab === "scans" ? "risk_score" : "phishing_score";
    const avg = items.length ? Math.round(items.reduce((a, b) => a + b[field], 0) / items.length) : 0;
    const bad = activeTab === "scans"
      ? items.filter((r) => String(r.verdict).toLowerCase() === "dangerous").length
      : items.filter((r) => String(r.verdict).toLowerCase() === "phishing").length;

    const avgCls = activeTab === "scans"
      ? (avg >= 70 ? "pos" : avg >= 40 ? "warn" : "neg")
      : (avg >= 55 ? "neg" : avg >= 25 ? "warn" : "pos");

    const tiles = [
      { label: activeTab === "scans" ? "Total scans" : "Total analyses", value: data.total, cls: "" },
      { label: "Filtered", value: visibleItems().length, cls: "" },
      { label: activeTab === "scans" ? "Dangerous URLs" : "Phishing hits", value: bad, cls: bad ? "neg" : "pos" },
      { label: activeTab === "scans" ? "Avg risk score" : "Avg phish score", value: avg, cls: avgCls },
    ];

    $("historyStats").innerHTML = tiles.map((t) => `
      <div class="stat-tile panel">
        <span class="stat-tile__value ${t.cls}">${App.escapeHtml(t.value)}</span>
        <span class="stat-tile__label">${t.label}</span>
      </div>`).join("");
  }

  async function renderAll() {
    const tab = activeTab;
    const data = await loadTab(tab);
    if (tab !== activeTab) return; // user switched tabs while this was loading
    buildVerdictChips(data.items);
    renderStats();
    renderCards();
  }

  /* ---------------- Actions ---------------- */

  function openReport(id) {
    location.href = `scanner.html?report=${id}`;
  }

  // Tab switching
  qsa(".tab[data-history-tab]").forEach((tab) => {
    tab.addEventListener("click", () => {
      qsa(".tab[data-history-tab]").forEach((t) => t.classList.remove("is-active"));
      tab.classList.add("is-active");
      activeTab = tab.dataset.historyTab;
      filter = "all";
      query = "";
      $("historySearch").value = "";
      renderAll();
    });
  });

  // Live search
  $("historySearch").addEventListener("input", (e) => {
    query = e.target.value.trim().toLowerCase();
    renderCards();
  });
  $("historySearch").addEventListener("keydown", (e) => {
    if (e.key === "Escape") { $("historySearch").value = ""; query = ""; renderCards(); }
  });

  // Verdict chips (delegated)
  $("verdictChips").addEventListener("click", (e) => {
    const chip = e.target.closest(".filter-chip");
    if (!chip) return;
    filter = chip.dataset.filter;
    buildVerdictChips(activeTab === "scans" ? scans.items : phish.items);
    renderCards();
  });

  // Sort
  $("historySort").addEventListener("change", (e) => {
    sort = e.target.value;
    renderCards();
  });

  /* ---------------- Init ---------------- */

  // Show skeleton loaders while data loads
  App.showSkeleton("#historyCards");
  renderAll();
})();
