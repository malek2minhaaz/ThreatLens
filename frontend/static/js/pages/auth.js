/* ============================================================
   ThreatLens — auth pages (login.html / register.html)
   ============================================================ */
"use strict";

(function () {
  const { $, API } = App;

  /* Explain why the user was sent here (auth-gated redirect / expired session). */
  const redirectReason = sessionStorage.getItem("threatlens_redirect_reason");
  if (redirectReason) {
    sessionStorage.removeItem("threatlens_redirect_reason");
    if (redirectReason === "auth_required") {
      App.toast("Please sign in to access that page.");
    } else if (redirectReason === "expired") {
      App.toast("Your session has expired. Please sign in again.");
    }
  }

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
      /* Client-side checks mirror the backend schema so the user gets
         a clear message instead of a raw 422 from the server. */
      if (password.length < 8) return App.toast("Password must be at least 8 characters.");
      if (!/[A-Z]/.test(password)) return App.toast("Password must contain at least one uppercase letter.");
      if (!/[a-z]/.test(password)) return App.toast("Password must contain at least one lowercase letter.");
      if (!/\d/.test(password)) return App.toast("Password must contain at least one digit.");
      if (!/^[A-Za-z0-9_]+$/.test(username)) return App.toast("Username may only contain letters, numbers and underscores.");
      submitAuth(API.auth + "/register", { username, email, password }, $("registerBtn"), "Account created — welcome!");
    });
  }
})();
