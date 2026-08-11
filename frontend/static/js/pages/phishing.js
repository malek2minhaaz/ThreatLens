/* ============================================================
   ThreatLens — Phishing Lab page (phishing.html)
   Tabs + Content Analyzer. Other tools live in phishing-tools.js
   ============================================================ */
"use strict";

(function () {
  if (!App.isAuthed()) return; // app.js is already redirecting
  const { $ } = App;

  /* ---------------- Tab switching ---------------- */

  const tabs = Array.from(document.querySelectorAll(".tool-tab"));
  tabs.forEach((tab) =>
    tab.addEventListener("click", () => {
      tabs.forEach((t) => {
        const active = t === tab;
        t.classList.toggle("is-active", active);
        t.setAttribute("aria-selected", String(active));
      });
      document.querySelectorAll(".tool-panel").forEach((p) => {
        p.hidden = p.id !== "panel-" + tab.dataset.tab;
      });
    })
  );

  /* ---------------- Shared: watchlist matches ---------------- */

  function renderWatchMatches(el, matches) {
    if (!el) return;
    if (!matches || !matches.length) {
      el.hidden = true;
      el.innerHTML = "";
      return;
    }
    el.hidden = false;
    el.innerHTML =
      '<div class="watch-match__title">⚠ Matches your watchlist</div>' +
      matches
        .map(
          (m) =>
            `<span class="watch-match__chip"><span class="watch-match__kind">${App.escapeHtml(m.kind)}</span> ${App.escapeHtml(m.value)}</span>`
        )
        .join("");
  }
  App.renderWatchMatches = renderWatchMatches;

  /* ---------------- Content Analyzer ---------------- */

  const SAMPLE_PHISH = `From: "PayPal Security Center" <security-alert@paypal-verify-account.tk>
Reply-To: scammer1337@gmail.com
Subject: URGENT: Your account has been suspended

Dear valued customer,

We detected unusual activity on your account. Your account will be
permanently CLOSED within 24 hours if you do not act immediately.

Click here to verify your account: https://paypal-account-verify.tk/login

Failure to respond will result in legal action against you.
Please confirm your password and billing information right away.`;

  $("loadSample").addEventListener("click", () => {
    $("phishInput").value = SAMPLE_PHISH;
    $("contentType").value = "email";
    App.toast("Sample phishing email loaded — analyze it to see the engine in action.", true);
  });

  $("phishForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const content = $("phishInput").value.trim();
    if (content.length < 3) {
      App.toast("Paste some content to analyze first.");
      return;
    }
    const btn = $("phishBtn");
    btn.classList.add("is-loading");
    btn.disabled = true;
    try {
      const data = await App.apiFetch(App.API.phishing, {
        method: "POST",
        body: JSON.stringify({ content, content_type: $("contentType").value }),
      });
      renderPhishResult(data);
    } catch (err) {
      App.toast(`Analysis failed: ${err.message}`);
    } finally {
      btn.classList.remove("is-loading");
      btn.disabled = false;
    }
  });

  function renderPhishResult(data) {
    $("phishPlaceholder").hidden = true;
    $("phishResult").hidden = false;

    const score = data.phishing_score;
    $("phishVerdict").textContent = data.verdict;
    $("phishVerdict").className = "verdict-badge " + App.verdictClass(data.verdict);
    $("phishScore").textContent = `${score} / 100`;
    $("phishConfidence").textContent = `confidence: ${data.confidence}`;

    const fill = $("phishMeterFill");
    fill.style.transition = "none";
    fill.style.width = "0%";
    void fill.getBoundingClientRect();
    requestAnimationFrame(() => {
      fill.style.transition = "width 0.9s cubic-bezier(0.22,1,0.36,1)";
      fill.style.width = score + "%";
    });

    $("phishFlags").innerHTML = data.flags.length
      ? data.flags.map((f, idx) => `
        <div class="finding f-sev-${f.severity}" style="animation-delay:${Math.min(0.25, 0.03 * idx)}s">
          <div class="finding__points pos">+${f.points}</div>
          <div class="finding__body">
            <div class="finding__title">${App.escapeHtml(f.label)}
              <span class="sev-chip ${App.severityClass(f.severity)}">${App.escapeHtml(f.severity)}</span>
            </div>
            <div class="finding__detail">${App.escapeHtml(f.detail)}</div>
          </div>
          <div class="finding__meta"><span class="cat-tag">Phishing</span></div>
        </div>`).join("")
      : '<div class="table-empty">No phishing indicators detected.</div>';

    renderWatchMatches($("phishWatchMatches"), data.watchlist_matches);

    const kw = data.matched_keywords || {};
    $("phishDetails").innerHTML = `
    <p><strong>Stats:</strong> ${data.stats.word_count} words · ${data.stats.link_count} link(s) · greeting: ${data.stats.greeting_detected ? "yes" : "no"}</p>
    ${Object.entries(kw).filter(([, v]) => v.length).map(([group, words]) => `
      <p><strong>${group}:</strong> ${words.slice(0, 5).map((w) => `<span class="mono">${App.escapeHtml(w)}</span>`).join(", ")}</p>`).join("") || "<p>No keywords matched.</p>"}
    ${data.stats.links.length ? `<p><strong>Links found:</strong><br>${data.stats.links.map((l) => `<span class="mono">${App.escapeHtml(l)}</span><br>`).join("")}</p>` : ""}`;
  }
})();
