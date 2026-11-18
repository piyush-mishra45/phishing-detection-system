"""REST API + database tests (Flask test client, temporary SQLite DB)."""
import json

import pytest

PHISH = {"sender_email": "PayPal <help@paypa1-secure.tk>", "subject": "URGENT verify", "email_content": "Dear customer your account is suspended. Verify your account immediately http://192.0.2.9/login"}


def test_health(client):
    assert client.get("/api/health").get_json()["database"] == "ok"


def test_auth_required(client):
    for path in ("/api/history", "/api/dashboard/stats", "/api/model/metrics", "/api/reports/export"):
        assert client.get(path).status_code == 401
    assert client.post("/api/scan/website", json={"url": "http://example.com"}).status_code == 401


def test_register_login_logout(client):
    r = client.post("/api/auth/register", json={"username": "bob", "email": "bob@example.com", "password": "Str0ngPassw0rd!"})
    assert r.status_code == 201 and "password" not in json.dumps(r.get_json())
    assert client.post("/api/auth/register", json={"username": "bob", "email": "bob@example.com", "password": "Str0ngPassw0rd!"}).status_code == 409
    assert client.post("/api/auth/register", json={"username": "x", "email": "bad", "password": "weak"}).status_code == 400
    assert client.post("/api/auth/login", json={"identifier": "bob", "password": "wrong"}).status_code == 401
    tok = client.post("/api/auth/login", json={"identifier": "bob@example.com", "password": "Str0ngPassw0rd!"}).get_json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert client.get("/api/auth/me", headers=h).status_code == 200
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401  # token revoked


def test_password_is_hashed(app, auth):
    from app.database.db import db
    from app.models.models import User
    u = db().query(User).filter_by(username="alice").one()
    assert "Str0ng" not in u.password_hash and u.password_hash.startswith(("scrypt:", "pbkdf2:"))


def test_email_scan_roundtrip_and_privacy(client, auth, app):
    r = client.post("/api/scan/email", json=PHISH, headers=auth)
    assert r.status_code == 201
    rep = r.get_json()["report"]
    assert rep["prediction"] == "PHISHING" and rep["risk_level"] in ("High Risk", "Critical Risk") and rep["malicious_links"]
    from app.database.db import db
    from app.models.models import EmailScan
    row = db().query(EmailScan).one()
    assert len(row.email_content) <= 500
    detail = client.get(f"/api/history/{r.get_json()['scan_id']}", headers=auth).get_json()
    assert detail["report"]["prediction"] == "PHISHING" and detail["features"]


def test_eml_upload(client, auth):
    import io
    eml = b"From: a@evil.tk\nSubject: Verify\nContent-Type: text/plain\n\nVerify your account immediately or it will be suspended http://evil.tk/login"
    r = client.post("/api/scan/email", data={"file": (io.BytesIO(eml), "m.eml")}, headers=auth, content_type="multipart/form-data")
    assert r.status_code == 201
    r = client.post("/api/scan/email", data={"file": (io.BytesIO(b"x"), "m.exe")}, headers=auth, content_type="multipart/form-data")
    assert r.status_code == 400


def test_website_scan_validation_and_ssrf(client, auth):
    assert client.post("/api/scan/website", json={"url": ""}, headers=auth).status_code == 400
    assert client.post("/api/scan/website", json={"url": "ftp://x.com"}, headers=auth).status_code == 400
    r = client.post("/api/scan/website", json={"url": "http://169.254.169.254/latest/meta-data/"}, headers=auth)
    assert r.status_code == 201 and r.get_json()["report"]["prediction"] == "UNKNOWN" and r.get_json()["report"]["fetch"]["reachable"] is False


def test_history_filters_search_export_and_idor(client, auth, make_user):
    client.post("/api/scan/email", json=PHISH, headers=auth)
    client.post("/api/scan/email", json={"sender_email": "bob@corp.example", "subject": "Lunch", "email_content": "Hi team, lunch tomorrow at noon? Thanks"}, headers=auth)
    all_ = client.get("/api/history", headers=auth).get_json()
    assert all_["total"] == 2
    assert client.get("/api/history?q=lunch", headers=auth).get_json()["total"] == 1
    assert client.get("/api/history?category=critical", headers=auth).get_json()["total"] >= 1
    assert client.get("/api/history?category=low", headers=auth).get_json()["total"] == 1
    assert client.get("/api/history?date_from=2999-01-01", headers=auth).get_json()["total"] == 0
    assert client.get("/api/history?date_from=garbage", headers=auth).status_code == 400
    csv_text = client.get("/api/reports/export", headers=auth).data.decode()
    assert csv_text.splitlines()[0].startswith("id,type") and len(csv_text.splitlines()) == 3
    other = make_user("mallory", "mallory@example.com")
    sid = all_["items"][0]["id"]
    assert client.get(f"/api/history/{sid}", headers=other).status_code == 404  # no cross-user access
    assert client.get("/api/history", headers=other).get_json()["total"] == 0


def test_csv_export_neutralises_formulas(client, auth):
    client.post("/api/scan/email", json={"subject": "=cmd|' /C calc'!A0", "email_content": "Hello there, this is a normal long enough message."}, headers=auth)
    assert "'=cmd" in client.get("/api/reports/export", headers=auth).data.decode()


def test_dashboard_stats(client, auth):
    client.post("/api/scan/email", json=PHISH, headers=auth)
    s = client.get("/api/dashboard/stats", headers=auth).get_json()
    assert s["totals"]["emails_scanned"] == 1 and s["totals"]["phishing_emails"] == 1 and len(s["weekly"]) == 7 and s["recent_scans"]


def test_rbac(client, auth):
    assert client.get("/api/admin/users", headers=auth).status_code == 403
    admin = client.post("/api/auth/register", json={"username": "root", "email": "admin@example.com", "password": "Str0ngPassw0rd!"}).get_json()
    h = {"Authorization": "Bearer " + admin["token"]}
    assert admin["user"]["role"] == "admin" and client.get("/api/admin/users", headers=h).status_code == 200


def test_rate_limit(app, client, auth):
    from app.security import ratelimit
    ratelimit.reset()
    app.config["RATE_LIMIT_SCAN_PER_MIN"] = 2
    codes = [client.post("/api/scan/website", json={"url": "http://127.0.0.1/"}, headers=auth).status_code for _ in range(4)]
    assert codes[:2] == [201, 201] and 429 in codes[2:]


def test_cascade_delete(app, client, auth):
    from app.database.db import db
    from app.models.models import ScanFeature, ScanHistory
    sid = client.post("/api/scan/email", json=PHISH, headers=auth).get_json()["scan_id"]
    assert db().query(ScanFeature).count() > 0
    assert client.delete(f"/api/history/{sid}", headers=auth).status_code == 200
    assert db().query(ScanHistory).count() == 0 and db().query(ScanFeature).count() == 0
