/* ============================================================
   ThreatLens — auth pages (login.html / register.html)
   ============================================================ */
"use strict";

(function () {
  const { $, API } = App;

  async function submitAuth(url, payload, btn, successMsg) {
    btn.classList.add("is-loading");
    btn.disabled = true;
    try {
      const data = await App.apiFetch(url, { method: "POST", body: JSON.stringify(payload) });
      App.setToken(data.token);
      App.setAdminFlag(Boolean(data.user?.is_admin));
      App.state.user = data.user;
      App.toast(successMsg, true);
      // Admins land on the admin panel; regular users on the scanner
      setTimeout(() => location.replace(data.user?.is_admin ? "admin.html" : "scanner.html"), 350);
    } catch (err) {
      App.toast(err.message);
    } finally {
      btn.classList.remove("is-loading");
      btn.disabled = false;
    }
  }

  if ($("loginForm")) {
    $("loginForm").addEventListener("submit", (e) => {
      e.preventDefault();
      const identifier = $("loginIdentifier").value.trim();
      const password = $("loginPassword").value;
      if (!identifier || !password) return App.toast("Enter your credentials.");
      submitAuth(API.auth + "/login", { identifier, password }, $("loginBtn"), "Welcome back!");
    });
  }

  if ($("registerForm")) {
    $("registerForm").addEventListener("submit", (e) => {
      e.preventDefault();
      const username = $("regUsername").value.trim();
      const email = $("regEmail").value.trim();
      const password = $("regPassword").value;
      const confirm = $("regPassword2").value;
      if (password !== confirm) return App.toast("Passwords do not match.");
      submitAuth(API.auth + "/register", { username, email, password }, $("registerBtn"), "Account created — welcome!");
    });
  }
})();
