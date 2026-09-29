"""Needs a Postgres at TEST_DATABASE_URL; skipped otherwise."""
import datetime as dt
import os

import pytest

DB = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB, reason="TEST_DATABASE_URL not set")


@pytest.fixture
def client(monkeypatch):
    from auditor import config as cfg
    from auditor import db
    from auditor.config import Settings, Tenant
    from auditor.rules.engine import Finding, save_findings
    from auditor.web.app import create_app
    from fastapi.testclient import TestClient

    from cryptography.fernet import Fernet
    monkeypatch.setenv("AUDITOR_ENC_KEY", Fernet.generate_key().decode())
    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    conn.commit()
    db.migrate(conn)

    cfg.save_tenant(conn, id="webtest", base_url="https://webtest.thereforeonline.com",
                    username="svc", password="pw", tenant_name_override=None, log_category_no=1,
                    log_tz="UTC", display_tz="UTC", schedule_cron="30 3 * * *", llm_enabled=True,
                    llm_redact=True, digest_email_to=[], known={"users": ["svc.logaudit"]},
                    enabled=True)
    tenant = cfg.get_tenant(conn, "webtest")
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    f = Finding(rule_id="new_entity", dedupe_key="user:mallory", title="New user: mallory",
                severity="medium", first_ts=now, last_ts=now, subject_users=["mallory"])
    save_findings(conn, tenant, [f])
    conn.close()

    monkeypatch.setenv("AUDITOR_WEB_USER", "tester")
    monkeypatch.setenv("AUDITOR_WEB_PASSWORD", "s3cret")
    monkeypatch.setenv("AUDITOR_WEB_SECRET", "test-secret")
    settings = Settings(DB, [], {}, "", "", "", {}, None)
    app = create_app(settings)
    return TestClient(app)


def _login(client):
    return client.post("/login", data={"username": "tester", "password": "s3cret", "next": "/"},
                        follow_redirects=False)


def test_unauthenticated_redirects_to_login(client):
    r = client.get("/t/webtest/findings", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login")


def test_login_then_findings_list(client):
    r = _login(client)
    assert r.status_code == 303
    r = client.get("/t/webtest/findings?min_severity=info")
    assert r.status_code == 200
    assert "New user: mallory" in r.text


def test_review_persists_and_shows_reviewer(client):
    _login(client)
    findings_id = 1
    r = client.post(f"/t/webtest/findings/{findings_id}/review",
                     data={"status": "acknowledged", "note": "looks fine"}, follow_redirects=False)
    assert r.status_code == 303
    r = client.get(f"/t/webtest/findings/{findings_id}")
    assert "tester" in r.text and "looks fine" in r.text


def test_bad_login_rejected(client):
    r = client.post("/login", data={"username": "tester", "password": "wrong", "next": "/"})
    assert r.status_code == 401


def test_admin_create_edit_delete_tenant(client):
    _login(client)
    r = client.post("/admin/tenants/new", data={
        "id": "newtenant", "base_url": "https://newtenant.thereforeonline.com",
        "username": "svc", "password": "secret123", "log_category_no": "1",
        "log_tz": "UTC", "display_tz": "UTC", "schedule_cron": "0 4 * * *",
        "llm_enabled": "true", "llm_redact": "true", "digest_email_to": "a@example.com",
        "enabled": "true"}, follow_redirects=False)
    assert r.status_code == 303
    r = client.get("/admin/tenants")
    assert "newtenant" in r.text

    # editing without a password keeps the existing (encrypted) one
    r = client.post("/admin/tenants/newtenant/edit", data={
        "base_url": "https://newtenant.thereforeonline.com", "username": "svc", "password": "",
        "log_category_no": "1", "log_tz": "UTC", "display_tz": "UTC",
        "schedule_cron": "0 5 * * *", "llm_enabled": "true", "llm_redact": "true",
        "digest_email_to": "", "enabled": "true"}, follow_redirects=False)
    assert r.status_code == 303
    r = client.get("/admin/tenants")
    assert "0 5 * * *" in r.text

    r = client.post("/admin/tenants/newtenant/delete", data={"confirm": "newtenant"},
                     follow_redirects=False)
    assert r.status_code == 303
    r = client.get("/admin/tenants")
    assert "newtenant" not in r.text


def test_admin_rule_toggle_persists(client):
    from auditor import config as cfg
    from auditor import db
    _login(client)
    r = client.get("/admin/tenants/webtest/rules")
    assert r.status_code == 200
    assert "mass_delete" in r.text
    r = client.post("/admin/tenants/webtest/rules",
                     data={"enabled__mass_delete": "off", "config__mass_delete": ""},
                     follow_redirects=False)
    assert r.status_code == 303
    conn = db.connect(DB)
    overrides = cfg.rule_settings_for(conn, "webtest")
    conn.close()
    assert overrides["mass_delete"]["enabled"] is False


def test_admin_smtp_save_and_reload(client):
    from auditor import config as cfg
    from auditor import db
    _login(client)
    r = client.post("/admin/smtp", data={"host": "smtp.example.com", "port": "587",
                     "user": "bot", "password": "hunter2", "from_addr": "bot@example.com",
                     "starttls": "true"})
    assert r.status_code == 200
    conn = db.connect(DB)
    smtp = cfg.load_smtp(conn)
    conn.close()
    assert smtp["host"] == "smtp.example.com"
    assert smtp["password"] == "hunter2"   # round-trips through Fernet encryption


def test_admin_create_user_and_login_as_them(client):
    r = _login(client)
    assert r.status_code == 303
    r = client.post("/admin/users/new", data={"username": "newperson", "password": "newpass123"},
                     follow_redirects=False)
    assert r.status_code == 303
    r = client.post("/login", data={"username": "newperson", "password": "newpass123", "next": "/"},
                     follow_redirects=False)
    assert r.status_code == 303
