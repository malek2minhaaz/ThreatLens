/* ============================================================
   ThreatLens — Admin Panel page (admin.html)
   Admin-only: global stats, verdict distribution, provider
   status, user management (promote/demote/delete) and an
   all-users scan feed.
   ============================================================ */
"use strict";

(function () {
  if (!App.isAuthed()) return; // app.js is already redirecting
  const { $ } = App;

  let usersCache = [];

  /* ---------------- Stats + distribution + providers ---------------- */

  async function loadStats() {
    const stats = await App.apiFetch(App.API.admin + "/stats");
    const total = Object.values(stats.verdict_distribution || {}).reduce((a, b) => a + b, 0) || 1;

    const tiles = [
      { label: "Users", value: stats.users, cls: "" },
      { label: "Admins", value: stats.admins, cls: "" },
      { label: "Total scans", value: stats.total_scans, cls: "" },
      { label: "Scans today", value: stats.scans_today, cls: "" },
      { label: "Dangerous", value: stats.dangerous_scans, cls: stats.dangerous_scans ? "neg" : "pos" },
      { label: "Detection rate", value: `${Math.round(stats.detection_rate * 100)}%`, cls: stats.detection_rate >= 0.2 ? "neg" : stats.detection_rate > 0 ? "warn" : "pos" },
      { label: "Avg risk score", value: stats.avg_risk_score ?? "—", cls: (stats.avg_risk_score ?? 100) >= 70 ? "pos" : "warn" },
      { label: "Phishing analyses", value: stats.total_phishing, cls: "" },
    ];
    $("adminStats").innerHTML = tiles.map((t) => `
      <div class="stat-tile panel">
        <span class="stat-tile__value ${t.cls}">${App.escapeHtml(t.value)}</span>
        <span class="stat-tile__label">${t.label}</span>
      </div>`).join("");

    const order = ["SAFE", "LOW RISK", "SUSPICIOUS", "DANGEROUS"];
    $("adminDist").innerHTML = order.filter((v) => stats.verdict_distribution[v] > 0).map((v) => {
      const pct = Math.round((stats.verdict_distribution[v] / total) * 100);
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
      $("adminDist").querySelectorAll(".dist-row").forEach((row, i) => {
        const fill = row.querySelector(".dist-row__fill");
        setTimeout(() => { fill.style.width = fill.dataset.pct + "%"; }, 120 + i * 90);
      });
    });

    const providers = [
      { key: "virustotal", name: "VirusTotal", desc: "Multi-engine AV consensus" },
      { key: "google_safe_browsing", name: "Google Safe Browsing", desc: "Google's malware & phishing list" },
      { key: "phishtank", name: "PhishTank", desc: "Community phishing database" },
    ];
    $("adminProviders").innerHTML = providers.map((p) => {
      const on = Boolean(stats.providers[p.key]);
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
  }

  /* ---------------- Users ---------------- */

  async function loadUsers() {
    try {
      const data = await App.apiFetch(App.API.admin + "/users");
      usersCache = data.items;
      renderUsers();
    } catch (err) {
      $("adminUsersBody").innerHTML = `<tr><td colspan="8" class="table-empty">Could not load users: ${App.escapeHtml(err.message)}</td></tr>`;
    }
  }

  function renderUsers() {
    const q = ($("adminUserSearch").value || "").trim().toLowerCase();
    const items = q
      ? usersCache.filter((u) =>
          `${u.username} ${u.email} ${u.display_name || ""}`.toLowerCase().includes(q)
        )
      : usersCache;

    $("adminUsersMeta").textContent = usersCache.length
      ? `Showing ${items.length} of ${usersCache.length} users${q ? ` · filter: “${q}”` : ""}`
      : "No users registered yet";
    $("adminUsersBody").innerHTML = items.length
      ? items.map((u, i) => `
        <tr data-id="${u.id}" style="animation-delay:${Math.min(0.25, 0.02 * i)}s">
          <td>
            <div class="user-cell">
              <span class="avatar" aria-hidden="true">${App.escapeHtml(App.initials(u.public_name))}</span>
              <div>
                <div>${App.escapeHtml(u.public_name)}</div>
                <div class="mono muted" style="font-size:0.72rem">@${App.escapeHtml(u.username)}</div>
              </div>
            </div>
          </td>
          <td class="mono muted">${App.escapeHtml(u.email)}</td>
          <td><span class="score-cell">${u.scan_count}</span></td>
          <td class="mono muted">${u.phishing_count}</td>
          <td class="mono muted">${new Date(u.created_at).toLocaleDateString()}</td>
          <td class="mono muted">${u.last_scan_at ? App.timeAgo(u.last_scan_at) : "—"}</td>
          <td>${u.is_admin ? '<span class="admin-chip">👑 Admin</span>' : '<span class="mini-chip">User</span>'}</td>
          <td>
            <div class="admin-actions">
              <button class="btn btn--ghost btn--sm" data-action="role" data-id="${u.id}" data-admin="${u.is_admin ? 1 : 0}">
                ${u.is_admin ? "Demote" : "Promote"}
              </button>
              <button class="btn btn--ghost btn--sm btn--danger" data-action="delete" data-id="${u.id}" data-name="${u.username.replaceAll('\"', '&quot;')}">Delete</button>
            </div>
          </td>
        </tr>`).join("")
      : `<tr><td colspan="8" class="table-empty">${usersCache.length ? "No users match your search." : "No users registered yet."}</td></tr>`;

    $("adminUsersBody").querySelectorAll("button[data-action]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        if (btn.dataset.action === "role") toggleRole(btn);
        else deleteUser(btn);
      });
    });
  }

  async function toggleRole(btn) {
    const id = Number(btn.dataset.id);
    const isAdmin = btn.dataset.admin === "1";
    btn.classList.add("is-loading");
    btn.disabled = true;
    try {
      await App.apiFetch(`${App.API.admin}/users/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ is_admin: !isAdmin }),
      });
      App.toast(`User ${isAdmin ? "demoted" : "promoted to admin"}.`, true);
      await loadUsers();
    } catch (err) {
      App.toast(err.message);
      btn.classList.remove("is-loading");
      btn.disabled = false;
    }
  }

  async function deleteUser(btn) {
    const name = btn.dataset.name;
    if (!window.confirm(`Delete user "${name}" and ALL of their scans and analyses? This cannot be undone.`)) return;
    btn.classList.add("is-loading");
    btn.disabled = true;
    try {
      const res = await App.apiFetch(`${App.API.admin}/users/${btn.dataset.id}`, { method: "DELETE" });
      App.toast(res.detail || "User deleted.", true);
      loadUsers();
    } catch (err) {
      App.toast(err.message);
      btn.classList.remove("is-loading");
      btn.disabled = false;
    }
  }

  /* ---------------- Recent scans (all users) ---------------- */

  async function loadScans() {
    try {
      const data = await App.apiFetch(App.API.admin + "/scans?limit=50");
      $("adminScansMeta").textContent = `${data.total} most recent scans across all users`;
      $("adminScansBody").innerHTML = data.items.length
        ? data.items.map((r) => `
          <tr>
            <td class="mono muted">#${r.id}</td>
            <td><span class="mono">${App.escapeHtml(r.username)}</span></td>
            <td class="url-cell" title="${App.escapeHtml(r.url)}">${App.escapeHtml(r.url)}</td>
            <td class="score-cell ${r.risk_score >= 70 ? "pos" : r.risk_score >= 40 ? "warn" : "neg"}">${r.risk_score}</td>
            <td><span class="verdict-badge verdict-badge--sm ${App.verdictClass(r.verdict)}">${App.escapeHtml(r.verdict)}</span></td>
            <td class="mono muted">${App.timeAgo(r.created_at)}</td>
          </tr>`).join("")
        : '<tr><td colspan="6" class="table-empty">No scans yet.</td></tr>';
    } catch (err) {
      $("adminScansBody").innerHTML = `<tr><td colspan="6" class="table-empty">Could not load scans: ${App.escapeHtml(err.message)}</td></tr>`;
    }
  }

  /* ---------------- Actions ---------------- */

  $("adminUserSearch").addEventListener("input", renderUsers);
  $("adminUserSearch").addEventListener("keydown", (e) => {
    if (e.key === "Escape") { $("adminUserSearch").value = ""; renderUsers(); }
  });

  $("adminRefresh").addEventListener("click", async () => {
    const icon = $("adminRefreshIcon");
    icon.classList.add("is-spinning");
    try {
      await Promise.all([loadStats(), loadUsers(), loadScans()]);
      App.toast("Admin panel refreshed.", true);
    } finally {
      icon.classList.remove("is-spinning");
    }
  });

  /* ---------------- Audit log ---------------- */

  async function loadAudit() {
    try {
      const data = await App.apiFetch("/api/audit/log?limit=30");
      $("auditMeta").textContent = data.total + " total entries";
      $("auditLog").innerHTML = data.items.length
        ? data.items.map(function(r) {
            var det = r.detail ? " — " + App.escapeHtml(r.detail) : "";
            var ip = r.ip_address ? " <span class=\"mono muted\">(" + App.escapeHtml(r.ip_address) + ")</span>" : "";
            return '<div class="audit-entry">' +
              '<span class="audit-entry__time">' + App.timeAgo(r.created_at) + '</span>' +
              '<span class="audit-entry__action">' +
                '<span class="audit-entry__user">' + App.escapeHtml(r.action) + '</span>' +
                det + ip +
              '</span>' +
            '</div>';
          }).join("")
        : '<div class="table-empty">No audit entries yet.</div>';
    } catch (err) {
      $("auditLog").innerHTML = '<div class="table-empty">Could not load audit log: ' + App.escapeHtml(err.message) + '</div>';
    }
  }

  /* ---------------- Init ---------------- */

  App.ensureAdmin().then((admin) => {
    if (!admin) return;
    loadStats().catch((err) => App.toast(`Stats failed: ${err.message}`));
    loadUsers();
    loadScans();
    loadAudit();
  });
})();
