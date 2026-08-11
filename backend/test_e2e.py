"""End-to-end smoke test for the ThreatLens API (requires running server)."""
import json
import sys
import urllib.error
import urllib.request
import uuid

BASE = "http://127.0.0.1:8000"


class ApiError(Exception):
    def __init__(self, status, detail):
        self.status = status
        self.detail = detail
        super().__init__(f"{status}: {detail}")


def request(method, path, payload=None, token=None, timeout=150):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
    else:
        data = None
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        try:
            detail = json.load(exc.read()).get("detail", str(exc))
        except Exception:
            detail = str(exc)
        raise ApiError(exc.code, detail) from exc


def check(name, cond, extra=""):
    if not cond:
        raise AssertionError(f"{name} FAILED {extra}")
    print(f"  OK — {name}")


def main():
    username = f"tester_{uuid.uuid4().hex[:8]}"
    email = f"{username}@example.com"
    password = "ThreatLens!2026"

    # ---- Auth ----
    print("== auth: register ==")
    r = request("POST", "/api/auth/register", {"username": username, "email": email, "password": password})
    token = r["token"]
    check("register returns token + user", bool(token) and r["user"]["username"] == username)
    check("user id present", isinstance(r["user"]["id"], int))

    print("== auth: duplicate register rejected ==")
    try:
        request("POST", "/api/auth/register", {"username": username, "email": email, "password": password})
        raise AssertionError("duplicate register should 409")
    except ApiError as exc:
        check("409 on duplicate", exc.status == 409)

    print("== auth: login with email ==")
    r = request("POST", "/api/auth/login", {"identifier": email, "password": password})
    check("login by email works", bool(r["token"]))
    token = r["token"]

    print("== auth: wrong password rejected ==")
    try:
        request("POST", "/api/auth/login", {"identifier": username, "password": "wrongpass1"})
        raise AssertionError("bad password should 401")
    except ApiError as exc:
        check("401 on bad password", exc.status == 401)

    print("== auth: me ==")
    me = request("GET", "/api/auth/me", token=token)
    check("me returns profile", me["email"] == email and me["username"] == username)

    print("== auth: protected endpoint without token ==")
    try:
        request("GET", "/api/history", token=None, timeout=10)
        raise AssertionError("no-token request should 401")
    except ApiError as exc:
        check("401 without token", exc.status == 401)

    # ---- Scanner ----
    print("== scan example.com ==")
    r = request("POST", "/api/scan-url", {"url": "https://example.com"}, token=token)
    check("example.com safe", r["risk_score"] >= 85, f"score={r['risk_score']}")
    check("whois resolved", r["metadata"]["whois"]["available"] is True)
    check("ssl valid", r["metadata"]["ssl"]["valid"] is True)
    check("http 200", r["metadata"]["http"]["status_code"] == 200)
    check("scan persisted with user", isinstance(r["scan_id"], int))

    print("== scan typosquat .tk ==")
    r = request("POST", "/api/scan-url", {"url": "http://paypal-account-verify.tk/login"}, token=token)
    check("typosquat dangerous", r["risk_score"] < 40, f"score={r['risk_score']}")
    labels = [f["label"] for f in r["findings"]]
    check("typosquat finding", any("Typosquat" in l for l in labels))
    check("suspicious TLD finding", any("Suspicious TLD" in l for l in labels))

    print("== scan SSRF blocked ==")
    r = request("POST", "/api/scan-url", {"url": "http://127.0.0.1:8000/api/health"}, token=token)
    details = " ".join(f.get("detail", "") for f in r["findings"])
    check("loopback refused", "internal" in details.lower() or "loopback" in details.lower())

    # ---- Phishing ----
    print("== phishing analysis ==")
    scam = (
        "From: PayPal Security <security@paypal-verify.tk>\nReply-To: scammer42@gmail.com\n"
        "Subject: URGENT: account suspended\n\nDear valued customer, your account will be closed "
        "within 24 hours if you do not verify. Click here: https://paypal-verify.tk/login "
        "and confirm your password. Failure to respond results in legal action."
    )
    r = request("POST", "/api/analyze-phishing", {"content": scam, "content_type": "email"}, token=token)
    check("scam flagged", r["verdict"] == "PHISHING", f"score={r['phishing_score']}")

    benign = "Hi Alex, thanks for your order #4821. Track it here: https://shop.example.com/track/4821."
    r = request("POST", "/api/analyze-phishing", {"content": benign, "content_type": "sms"}, token=token)
    check("benign safe", r["verdict"] == "SAFE", f"score={r['phishing_score']}")

    # ---- History / stats / intel ----
    print("== history & stats & intel ==")
    h = request("GET", "/api/history?limit=10", token=token)
    check("history has user scans", h["total"] >= 2, f"total={h['total']}")
    check("history rows scoped", all(isinstance(i["id"], int) for i in h["items"]))

    stats = request("GET", "/api/users/stats", token=token)
    check("stats computed", stats["total_scans"] >= 2 and stats["total_phishing_analyses"] >= 2)

    status = request("GET", "/api/intel/status", token=token)
    check("intel status", set(status) == {"virustotal", "google_safe_browsing", "phishtank"})
    feed = request("GET", "/api/intel/feed?limit=10", token=token)
    check("intel feed", feed["total"] >= 2 and "feed" in feed)

    # ---- Profile update + password ----
    print("== profile update ==")
    r = request("PUT", "/api/auth/me", {"display_name": "Test User"}, token=token)
    check("display name updated", r["public_name"] == "Test User")
    me = request("GET", "/api/auth/me", token=token)
    check("persisted", me["display_name"] == "Test User")

    print("== change password (invalidates sessions) ==")
    r = request("POST", "/api/auth/change-password",
                {"current_password": password, "new_password": "NewPass!2026"}, token=token)
    try:
        request("GET", "/api/auth/me", token=token, timeout=10)
        raise AssertionError("old token should be invalidated")
    except ApiError as exc:
        check("old token rejected after password change", exc.status == 401)

    r = request("POST", "/api/auth/login", {"identifier": username, "password": "NewPass!2026"})
    check("login with new password", bool(r["token"]))

    # ---- Logout ----
    print("== logout ==")
    token2 = r["token"]
    request("POST", "/api/auth/logout", token=token2)
    try:
        request("GET", "/api/auth/me", token=token2, timeout=10)
        raise AssertionError("logged-out token should be invalid")
    except ApiError as exc:
        check("logout invalidates token", exc.status == 401)

    print("\nALL TESTS PASSED")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(f"\nFAILED: {exc}")
        sys.exit(1)
    except ApiError as exc:
        print(f"\nAPI ERROR: {exc}")
        sys.exit(1)
