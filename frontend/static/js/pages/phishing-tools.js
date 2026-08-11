/* ============================================================
   ThreatLens — Phishing tools (phishing.html)
   Link Inspector · Email Headers · Sender Check · Watchlist
   ============================================================ */
"use strict";

(function () {
  if (!App.isAuthed()) return;
  const { $, API } = App;

  function animateFill(el, pct) {
    el.style.transition = "none";
    el.style.width = "0%";
    void el.getBoundingClientRect();
    requestAnimationFrame(() => {
      el.style.transition = "width 0.9s cubic-bezier(0.22,1,0.36,1)";
      el.style.width = pct + "%";
    });
  }

  function findingsHtml(flags) {
    return flags.length
      ? flags.map((f, idx) => `
        <div class="finding f-sev-${f.severity}" style="animation-delay:${Math.min(0.25, 0.03 * idx)}s">
          <div class="finding__points pos">+${f.points}</div>
          <div class="finding__body">
            <div class="finding__title">${App.escapeHtml(f.label)}
              <span class="sev-chip ${App.severityClass(f.severity)}">${App.escapeHtml(f.severity)}</span>
            </div>
            <div class="finding__detail">${App.escapeHtml(f.detail)}</div>
          </div>
        </div>`).join("")
      : '<div class="table-empty">No suspicious indicators detected.</div>';
  }

  /* ============================================================
     Link Inspector
     ============================================================ */

  $("inspectForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const content = $("inspectInput").value.trim();
    if (content.length < 3) return App.toast("Paste a message to inspect first.");
    const btn = $("inspectBtn");
    btn.classList.add("is-loading");
    btn.disabled = true;
    try {
      const data = await App.apiFetch(API.inspect, { method: "POST", body: JSON.stringify({ content }) });
      $("inspectPlaceholder").hidden = true;
      $("inspectResult").hidden = false;

      $("inspectVerdict").textContent = data.message.verdict;
      $("inspectVerdict").className = "verdict-badge " + App.verdictClass(data.message.verdict);
      $("inspectScore").textContent = `${data.message.phishing_score} / 100`;
      $("inspectScanned").textContent = `${data.scanned_count} scanned · ${data.failed_count} failed`;
      animateFill($("inspectMeterFill"), data.message.phishing_score);
      App.renderWatchMatches($("inspectWatchMatches"), data.watchlist_matches);

      $("inspectLinks").innerHTML = data.links.length
        ? data.links.map((r) => {
            if (r.error) {
              return `
              <div class="link-card link-card--error">
                <div class="link-card__head"><span class="mono link-card__url">${App.escapeHtml(r.url)}</span></div>
                <div class="link-card__verdict err">⚠ failed to scan</div>
                <div class="muted">${App.escapeHtml(r.error)}</div>
              </div>`;
            }
            return `
            <a class="link-card ${App.verdictClass(r.verdict)}" href="scanner.html?report=${r.scan_id}" title="Open the full scan report">
              <div class="link-card__head">
                <span class="mono link-card__url">${App.escapeHtml(r.normalized_url)}</span>
                <span class="link-card__open">open →</span>
              </div>
              <div class="link-card__meta">
                <span class="verdict-badge ${App.verdictClass(r.verdict)}">${App.escapeHtml(r.verdict)}</span>
                <span class="mono">${r.risk_score}/100</span>
                <span class="muted">${r.findings_count} findings · ${(r.duration_ms / 1000).toFixed(1)}s</span>
              </div>
            </a>`;
          }).join("")
        : '<div class="table-empty">No links found in the message.</div>';
      App.toast("Inspection complete — every link was scanned.", true);
    } catch (err) {
      App.toast(`Inspection failed: ${err.message}`);
    } finally {
      btn.classList.remove("is-loading");
      btn.disabled = false;
    }
  });

  /* ============================================================
     Email Header Analyzer
     ============================================================ */

  $("headersForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const content = $("headersInput").value.trim();
    if (content.length < 3) return App.toast("Paste the raw headers first.");
    const btn = $("headersBtn");
    btn.classList.add("is-loading");
    btn.disabled = true;
    try {
      const data = await App.apiFetch(API.headers, { method: "POST", body: JSON.stringify({ content }) });
      $("headersPlaceholder").hidden = true;
      $("headersResult").hidden = false;

      $("headersVerdict").textContent = data.verdict;
      $("headersVerdict").className = "verdict-badge " + App.verdictClass(data.verdict);
      $("headersScore").textContent = `${data.score} / 100`;
      $("headersConfidence").textContent = `confidence: ${data.confidence}`;
      animateFill($("headersMeterFill"), data.score);

      const p = data.parsed || {};
      const auth = p.auth || {};
      const row = (label, value) =>
        `<div class="header-row"><span class="header-row__label">${label}</span><span class="mono header-row__value">${App.escapeHtml(value ?? "—")}</span></div>`;
      $("headersParsed").innerHTML = [
        row("From", p.from),
        row("From domain", p.from_domain),
        row("Reply-To", p.reply_to),
        row("Return-Path", p.return_path),
        row("Sender", p.sender),
        row("Subject", p.subject),
        row("Received hops", p.received_count),
        row("SPF", auth.spf),
        row("DKIM", auth.dkim),
        row("DMARC", auth.dmarc),
      ].join("");
      $("headersFlags").innerHTML = findingsHtml(data.flags);
      App.toast("Header analysis complete.", true);
    } catch (err) {
      App.toast(`Header analysis failed: ${err.message}`);
    } finally {
      btn.classList.remove("is-loading");
      btn.disabled = false;
    }
  });

  /* ============================================================
     Sender Check
     ============================================================ */

  $("senderForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const sender = $("senderInput").value.trim();
    if (sender.length < 3) return App.toast("Enter a sender email or domain.");
    const btn = $("senderBtn");
    btn.classList.add("is-loading");
    btn.disabled = true;
    try {
      const data = await App.apiFetch(API.senderCheck, { method: "POST", body: JSON.stringify({ sender }) });
      $("senderPlaceholder").hidden = true;
      $("senderResult").hidden = false;

      $("senderDomain").textContent = data.domain;
      $("senderVerdict").textContent = data.verdict;
      $("senderVerdict").className = "verdict-badge " + App.verdictClass(data.verdict);
      $("senderScore").textContent = `${data.risk_score} / 100`;
      animateFill($("senderMeterFill"), data.risk_score);
      const w = data.whois;
      $("senderWhois").textContent = w && w.registered_days_ago != null
        ? `domain age: ~${w.registered_days_ago} days`
        : w && w.registration_date ? `registered: ${String(w.registration_date).slice(0, 10)}` : "whois: unavailable";
      App.renderWatchMatches($("senderWatchMatches"), data.watchlist_matches);
      $("senderFindings").innerHTML = findingsHtml(data.findings);
      App.toast("Sender domain checked.", true);
    } catch (err) {
      App.toast(`Sender check failed: ${err.message}`);
    } finally {
      btn.classList.remove("is-loading");
      btn.disabled = false;
    }
  });

  /* ============================================================
     Watchlist
     ============================================================ */

  async function loadWatchlist() {
    const wrap = $("watchList");
    try {
      const data = await App.apiFetch(API.watchlist);
      if (!data.items.length) {
        wrap.innerHTML = '<div class="table-empty">Your watchlist is empty — add a domain, sender or URL above.</div>';
        return;
      }
      wrap.innerHTML = data.items.map((it) => `
        <div class="watch-row">
          <span class="watch-row__kind">${App.escapeHtml(it.kind)}</span>
          <span class="mono watch-row__value">${App.escapeHtml(it.value)}</span>
          <span class="muted watch-row__note">${App.escapeHtml(it.note || "")}</span>
          <span class="muted watch-row__seen">${it.last_seen_at ? "seen again " + App.timeAgo(it.last_seen_at) : "added " + App.timeAgo(it.created_at)}</span>
          <button class="btn btn--ghost btn--sm" data-remove="${it.id}">Remove</button>
        </div>`).join("");

      wrap.querySelectorAll("[data-remove]").forEach((btn) =>
        btn.addEventListener("click", async () => {
          try {
            await App.apiFetch(`${API.watchlist}/${btn.dataset.remove}`, { method: "DELETE" });
            App.toast("Removed from watchlist.", true);
            loadWatchlist();
          } catch (err) {
            App.toast(err.message);
          }
        })
      );
    } catch (err) {
      wrap.innerHTML = `<div class="table-empty">Could not load watchlist: ${App.escapeHtml(err.message)}</div>`;
    }
  }

  $("watchForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      kind: $("watchKind").value,
      value: $("watchValue").value.trim(),
      note: $("watchNote").value.trim() || null,
    };
    if (payload.value.length < 2) return App.toast("Enter a value to add.");
    const btn = $("watchAddBtn");
    btn.classList.add("is-loading");
    btn.disabled = true;
    try {
      await App.apiFetch(API.watchlist, { method: "POST", body: JSON.stringify(payload) });
      $("watchValue").value = "";
      $("watchNote").value = "";
      App.toast("Added to your watchlist.", true);
      loadWatchlist();
    } catch (err) {
      App.toast(err.message);
    } finally {
      btn.classList.remove("is-loading");
      btn.disabled = false;
    }
  });

  // Load the watchlist the first time its tab is opened
  document.querySelector('[data-tab="watchlist"]').addEventListener("click", loadWatchlist);
})();
