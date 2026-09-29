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
    from auditor import config as cfg
    from auditor import db
    _login(client)
    r = client.post("/admin/tenants/new", data={
        "id": "newtenant", "base_url": "https://newtenant.thereforeonline.com",
        "username": "svc", "password": "secret123", "log_category_no": "1",
        "log_tz": "UTC", "display_tz": "UTC", "schedule_hour": "4", "schedule_minute": "0",
        "llm_enabled": "true", "llm_redact": "true", "digest_email_to": "a@example.com",
        "enabled": "true"}, follow_redirects=False)
    assert r.status_code == 303
    r = client.get("/admin/tenants")
    assert "newtenant" in r.text
    assert "04:00 daily" in r.text

    # editing without a password keeps the existing (encrypted) one
    r = client.post("/admin/tenants/newtenant/edit", data={
        "base_url": "https://newtenant.thereforeonline.com", "username": "svc", "password": "",
        "log_category_no": "1", "log_tz": "UTC", "display_tz": "UTC",
        "schedule_hour": "5", "schedule_minute": "0", "llm_enabled": "true", "llm_redact": "true",
        "digest_email_to": "", "enabled": "true"}, follow_redirects=False)
    assert r.status_code == 303
    r = client.get("/admin/tenants")
    assert "05:00 daily" in r.text

    conn = db.connect(DB)
    tenant = cfg.get_tenant(conn, "newtenant")
    conn.close()
    assert tenant.schedule["daily"] == "0 5 * * *"

    r = client.post("/admin/tenants/newtenant/delete", data={"confirm": "newtenant"},
                     follow_redirects=False)
    assert r.status_code == 303
    r = client.get("/admin/tenants")
    assert "newtenant" not in r.text


def test_admin_tenant_advanced_schedule(client):
    from auditor import config as cfg
    from auditor import db
    _login(client)
    r = client.post("/admin/tenants/new", data={
        "id": "weekdaytenant", "base_url": "https://weekdaytenant.thereforeonline.com",
        "username": "svc", "password": "secret123", "log_category_no": "1",
        "log_tz": "UTC", "display_tz": "UTC", "use_advanced_schedule": "true",
        "schedule_cron_advanced": "30 3 * * 1-5", "llm_enabled": "true", "llm_redact": "true",
        "digest_email_to": "", "enabled": "true"}, follow_redirects=False)
    assert r.status_code == 303
    conn = db.connect(DB)
    tenant = cfg.get_tenant(conn, "weekdaytenant")
    conn.close()
    assert tenant.schedule["daily"] == "30 3 * * 1-5"

    r = client.get("/admin/tenants/weekdaytenant/edit")
    assert r.status_code == 200
    assert 'name="use_advanced_schedule" value="true" checked' in r.text
    assert "30 3 * * 1-5" in r.text


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


def test_admin_smtp_test_email_requires_address(client):
    _login(client)
    r = client.post("/admin/smtp/test", data={"host": "smtp.example.com", "port": "587"})
    assert r.status_code == 200
    assert "Enter an address" in r.text


def test_admin_smtp_test_email_sends_with_unsaved_form_values(client, monkeypatch):
    calls = []
    monkeypatch.setattr("auditor.digest.send_email",
                        lambda smtp, to, subject, text, html=None: calls.append((smtp, to)))
    _login(client)
    r = client.post("/admin/smtp/test", data={
        "host": "smtp.example.com", "port": "587", "user": "bot", "password": "hunter2",
        "from_addr": "bot@example.com", "starttls": "true", "test_to": "craig@example.com"})
    assert r.status_code == 200
    assert "Test email sent to craig@example.com" in r.text
    assert len(calls) == 1
    smtp, to = calls[0]
    assert smtp["host"] == "smtp.example.com" and smtp["password"] == "hunter2"
    assert to == ["craig@example.com"]


def test_admin_smtp_test_email_falls_back_to_saved_password(client, monkeypatch):
    from auditor import config as cfg
    from auditor import db
    conn = db.connect(DB)
    cfg.save_smtp(conn, host="smtp.example.com", port=587, user="bot", password="savedpw",
                  from_addr="bot@example.com", starttls=True)
    conn.close()

    calls = []
    monkeypatch.setattr("auditor.digest.send_email",
                        lambda smtp, to, subject, text, html=None: calls.append(smtp))
    _login(client)
    r = client.post("/admin/smtp/test", data={
        "host": "smtp.example.com", "port": "587", "user": "bot", "password": "",
        "from_addr": "bot@example.com", "starttls": "true", "test_to": "craig@example.com"})
    assert r.status_code == 200
    assert calls[0]["password"] == "savedpw"


def test_admin_run_now_triggers_pipeline(client, monkeypatch):
    calls = []

    def fake_run_tenant(settings, tenant, **kwargs):
        calls.append(tenant.id)
        return {"tenant": tenant.id, "files_new": 0, "events": 0, "findings": 0, "findings_changed": 0}

    monkeypatch.setattr("auditor.pipeline.run_tenant", fake_run_tenant)
    _login(client)
    r = client.post("/admin/tenants/webtest/run")
    assert r.status_code == 200
    assert calls == ["webtest"]
    assert "run complete" in r.text


def test_detect_category_uniquely(client, monkeypatch):
    monkeypatch.setattr(
        "auditor.therefore.ThereforeClient.list_categories",
        lambda self: [{"CategoryNo": 1, "Name": "Logfiles"}, {"CategoryNo": 50, "Name": "Invoices"}])
    _login(client)
    r = client.post("/admin/tenants/detect-category", data={
        "base_url": "https://x.thereforeonline.com", "username": "u", "password": "p"})
    assert r.status_code == 200
    assert "Detected: category 1" in r.text


def test_detect_category_ambiguous_lists_candidates(client, monkeypatch):
    monkeypatch.setattr(
        "auditor.therefore.ThereforeClient.list_categories",
        lambda self: [{"CategoryNo": 1, "Name": "Logfiles"}, {"CategoryNo": 324, "Name": "Logfiles2"}])
    _login(client)
    r = client.post("/admin/tenants/detect-category", data={
        "base_url": "https://x.thereforeonline.com", "username": "u", "password": "p"})
    assert r.status_code == 200
    assert "pick the right one" in r.text
    assert "Logfiles2" in r.text and ">1<" in r.text


def test_bulk_review_updates_only_selected(client):
    from auditor import config as cfg
    from auditor import db
    from auditor.rules.engine import Finding, save_findings
    _login(client)

    conn = db.connect(DB)
    tenant = cfg.get_tenant(conn, "webtest")
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    f2 = Finding(rule_id="new_entity", dedupe_key="user:trent", title="New user: trent",
                severity="medium", first_ts=now, last_ts=now, subject_users=["trent"])
    ids = save_findings(conn, tenant, [f2])
    other_id = ids[0]
    conn.close()

    r = client.post("/t/webtest/findings/bulk-review",
                     data={"ids": ["1"], "status": "acknowledged", "note": "bulk test",
                           "return_qs": "min_severity=info&status=&days=30"},
                     follow_redirects=False)
    assert r.status_code == 303
    assert "min_severity=info" in r.headers["location"]

    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("SELECT id, status, reviewed_note FROM findings WHERE tenant_id='webtest' ORDER BY id")
        rows = cur.fetchall()
    conn.close()
    assert rows[0]["status"] == "acknowledged" and rows[0]["reviewed_note"] == "bulk test"
    other = next(r for r in rows if r["id"] == other_id)
    assert other["status"] == "open"   # untouched - wasn't in `ids`


def test_known_activity_edit_persists_and_suppresses(client):
    from auditor import config as cfg
    from auditor import db
    _login(client)
    r = client.get("/t/webtest/known")
    assert r.status_code == 200
    assert "downgraded to" in r.text   # the purpose paragraph is present

    r = client.post("/t/webtest/known/add", data={"kind": "users", "value": "alice"}, follow_redirects=False)
    assert r.status_code == 303
    client.post("/t/webtest/known/add", data={"kind": "users", "value": "bob"})
    client.post("/t/webtest/known/add", data={"kind": "ips", "value": "10.0.0.5"})

    r = client.post("/t/webtest/known", data={
        "windows": "2026-01-01T00:00:00+00:00 to 2026-01-02T00:00:00+00:00: planned change",
        "notes": "alice is the new admin",
    }, follow_redirects=False)
    assert r.status_code == 200
    assert "Saved." in r.text
    assert "alice" in r.text and "bob" in r.text and "10.0.0.5" in r.text

    conn = db.connect(DB)
    tenant = cfg.get_tenant(conn, "webtest")
    conn.close()
    assert set(tenant.known["users"]) == {"alice", "bob", "svc.logaudit"}
    assert tenant.known["ips"] == ["10.0.0.5"]
    assert tenant.known["windows"] == [{"start": "2026-01-01T00:00:00+00:00",
                                        "end": "2026-01-02T00:00:00+00:00", "note": "planned change"}]
    assert tenant.known["notes"] == ["alice is the new admin"]


def test_known_add_remove_updates_suppression_immediately(client):
    """Adding a known user via the quick add-row should immediately downgrade any matching
    open finding, not wait for the next scheduled run."""
    from auditor import config as cfg
    from auditor import db
    _login(client)
    r = client.post("/t/webtest/known/add", data={"kind": "users", "value": "mallory"},
                     follow_redirects=False)
    assert r.status_code == 303
    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("SELECT severity, suppressed_by FROM findings WHERE tenant_id='webtest' AND id=1")
        row = cur.fetchone()
    conn.close()
    assert row["severity"] == "info"
    assert row["suppressed_by"] == "known user"

    r = client.post("/t/webtest/known/remove", data={"kind": "users", "value": "mallory"},
                     follow_redirects=False)
    assert r.status_code == 303
    conn = db.connect(DB)
    tenant = cfg.get_tenant(conn, "webtest")
    conn.close()
    assert "mallory" not in tenant.known.get("users", [])


def test_suppress_from_finding_marks_user_known(client):
    from auditor import config as cfg
    from auditor import db
    _login(client)
    r = client.post("/t/webtest/findings/1/suppress", data={"action": "know_user"}, follow_redirects=False)
    assert r.status_code == 303
    conn = db.connect(DB)
    tenant = cfg.get_tenant(conn, "webtest")
    with conn.cursor() as cur:
        cur.execute("SELECT severity FROM findings WHERE tenant_id='webtest' AND id=1")
        row = cur.fetchone()
    conn.close()
    assert "mallory" in tenant.known.get("users", [])
    assert row["severity"] == "info"


def test_group_for_display_rolls_up_three_or_more():
    from auditor.web.app import _group_for_display
    now = dt.datetime(2026, 1, 1, 10, tzinfo=dt.timezone.utc)
    rows = [{"id": i, "rule_id": "new_entity", "severity": "medium", "last_ts": now,
             "title": f"New user: u{i}", "status": "open", "llm_verdict": None,
             "incident_key": None, "suppressed_by": None, "incident_size": 1} for i in range(3)]
    items = _group_for_display(rows, "UTC")
    assert len(items) == 1
    assert items[0]["kind"] == "group"
    assert len(items[0]["members"]) == 3


def test_group_for_display_leaves_pairs_ungrouped():
    from auditor.web.app import _group_for_display
    now = dt.datetime(2026, 1, 1, 10, tzinfo=dt.timezone.utc)
    rows = [{"id": i, "rule_id": "new_entity", "severity": "medium", "last_ts": now,
             "title": f"New user: u{i}", "status": "open", "llm_verdict": None,
             "incident_key": None, "suppressed_by": None, "incident_size": 1} for i in range(2)]
    items = _group_for_display(rows, "UTC")
    assert len(items) == 2
    assert all(i["kind"] == "row" for i in items)


def test_findings_page_shows_summary_and_rollup(client):
    from auditor import config as cfg
    from auditor import db
    from auditor.rules.engine import Finding, save_findings
    conn = db.connect(DB)
    tenant = cfg.get_tenant(conn, "webtest")
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
    extra = [Finding(rule_id="new_entity", dedupe_key=f"user:u{i}", title=f"New user: u{i}",
                     severity="medium", first_ts=now, last_ts=now, subject_users=[f"u{i}"])
             for i in range(4)]
    save_findings(conn, tenant, extra)
    conn.close()

    _login(client)
    r = client.get("/t/webtest/findings?min_severity=info")
    assert r.status_code == 200
    assert "new_entity" in r.text
    assert "findings on" in r.text   # the rollup summary text


def test_decode_log_settings():
    from auditor.web.app import _decode_log_settings
    settings = {
        "700": "<Server><LogMask><V>3</V><V>1</V><V>1</V><V>0</V></LogMask></Server>",
        "701": 1, "702": 0, "703": 1020, "704": 10,
    }
    taken_at = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.timezone.utc)
    out = _decode_log_settings(settings, taken_at, "Australia/Sydney")
    assert out["archive_mode"] == "Every day"
    assert out["archive_time_utc"] == "17:00 UTC"
    assert out["split_size_mb"] == 10
    assert out["logmask_positions"] == [3, 1, 1, 0]
    counts = {c["value"]: c["count"] for c in out["logmask_counts"]}
    assert counts == {3: 1, 1: 2, 0: 1}


def test_tenant_edit_page_shows_log_settings(client):
    from auditor import db
    _login(client)
    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO settings_snapshots (tenant_id, settings) VALUES
                       ('webtest', %s)""",
                    ['{"700": "<Server><LogMask><V>3</V><V>0</V></LogMask></Server>", '
                     '"701": 1, "703": 1020, "704": 10}'])
    conn.commit()
    conn.close()
    r = client.get("/admin/tenants/webtest/edit")
    assert r.status_code == 200
    assert "Every day" in r.text
    assert "17:00 UTC" in r.text


def test_admin_create_user_and_login_as_them(client):
    r = _login(client)
    assert r.status_code == 303
    r = client.post("/admin/users/new", data={"username": "newperson", "password": "newpass123"},
                     follow_redirects=False)
    assert r.status_code == 303
    r = client.post("/login", data={"username": "newperson", "password": "newpass123", "next": "/"},
                     follow_redirects=False)
    assert r.status_code == 303
