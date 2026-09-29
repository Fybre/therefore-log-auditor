"""Needs a Postgres at TEST_DATABASE_URL; skipped otherwise."""
import datetime as dt
import os

import pytest

DB = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB, reason="TEST_DATABASE_URL not set")


@pytest.fixture
def client(monkeypatch):
    from auditor import db
    from auditor.config import Settings, Tenant
    from auditor.rules.engine import Finding, save_findings
    from auditor.web.app import create_app
    from fastapi.testclient import TestClient

    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    conn.commit()
    db.migrate(conn)

    tenant = Tenant(id="webtest", base_url="https://webtest.thereforeonline.com", display_tz="UTC",
                    known={"users": ["svc.logaudit"]})
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    f = Finding(rule_id="new_entity", dedupe_key="user:mallory", title="New user: mallory",
                severity="medium", first_ts=now, last_ts=now, subject_users=["mallory"])
    save_findings(conn, tenant, [f])
    conn.close()

    monkeypatch.setenv("AUDITOR_WEB_USER", "tester")
    monkeypatch.setenv("AUDITOR_WEB_PASSWORD", "s3cret")
    monkeypatch.setenv("AUDITOR_WEB_SECRET", "test-secret")
    settings = Settings(DB, [tenant], {}, "", "", "", {}, None)
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
