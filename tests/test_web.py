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
                    llm_redact=True, digest_email_to=[], digest_only_on_new=False,
                    known={"users": ["svc.logaudit"]}, enabled=True)
    tenant = cfg.get_tenant(conn, "webtest")
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    f = Finding(rule_id="new_entity", dedupe_key="user:mallory", title="New user: mallory",
                severity="medium", first_ts=now, last_ts=now, subject_users=["mallory"])
    save_findings(conn, tenant, [f])
    conn.close()

    monkeypatch.setenv("AUDITOR_WEB_USER", "tester")
    monkeypatch.setenv("AUDITOR_WEB_PASSWORD", "s3cret")
    monkeypatch.setenv("AUDITOR_WEB_SECRET", "test-secret")
    settings = Settings(DB, [], {}, "", "", "", {}, None, review_link_secret="test-secret")
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
    assert "AUDITOR_ENC_KEY" not in r.text   # client fixture sets both secrets - no warning banner


def test_missing_secrets_show_a_dashboard_warning(monkeypatch):
    """Regression: a missing AUDITOR_ENC_KEY on a real deployment silently generated a fresh
    random key every restart, permanently breaking every previously-stored password with no
    visible error until something downstream (Therefore auth) failed confusingly. This must be
    surfaced in the dashboard itself, not just logged."""
    from auditor import config as cfg
    from auditor import db
    from auditor.config import Settings
    from auditor.web.app import create_app
    from fastapi.testclient import TestClient

    monkeypatch.delenv("AUDITOR_ENC_KEY", raising=False)
    monkeypatch.delenv("AUDITOR_WEB_SECRET", raising=False)
    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    conn.commit()
    db.migrate(conn)
    conn.close()

    monkeypatch.setenv("AUDITOR_WEB_USER", "tester")
    monkeypatch.setenv("AUDITOR_WEB_PASSWORD", "s3cret")
    settings = Settings(DB, [], {}, "", "", "", {}, None)
    app = create_app(settings)
    client = TestClient(app)
    client.post("/login", data={"username": "tester", "password": "s3cret", "next": "/"})

    r = client.get("/admin/tenants")
    assert r.status_code == 200
    assert "AUDITOR_ENC_KEY is not set" in r.text
    assert "AUDITOR_WEB_SECRET is not set" in r.text


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


def test_admin_tenant_create_rejects_invalid_timezone(client):
    """A timezone abbreviation like "AEST" isn't a valid IANA zone - if it were saved, every
    page rendering that tenant's timestamps (including the shared tenant list) would 500. Must
    be rejected with a form error instead, and not saved to the DB."""
    from auditor import config as cfg
    from auditor import db
    _login(client)
    r = client.post("/admin/tenants/new", data={
        "id": "badtz", "base_url": "https://badtz.thereforeonline.com",
        "username": "svc", "password": "secret123", "log_category_no": "1",
        "log_tz": "UTC", "display_tz": "AEST", "schedule_hour": "3", "schedule_minute": "30",
        "digest_email_to": "", "enabled": "true"})
    assert r.status_code == 400
    assert "a valid time zone" in r.text
    assert "AEST" in r.text

    conn = db.connect(DB)
    assert cfg.get_tenant_row(conn, "badtz") is None
    conn.close()


def test_admin_tenant_update_rejects_invalid_timezone(client):
    from auditor import config as cfg
    from auditor import db
    _login(client)
    r = client.post("/admin/tenants/webtest/edit", data={
        "base_url": "https://webtest.thereforeonline.com", "username": "svc",
        "log_tz": "AEST", "display_tz": "UTC", "schedule_hour": "3", "schedule_minute": "30",
        "digest_email_to": "", "enabled": "true"})
    assert r.status_code == 400
    assert "a valid time zone" in r.text

    conn = db.connect(DB)
    tenant = cfg.get_tenant(conn, "webtest")
    conn.close()
    assert tenant.log_tz == "UTC"   # unchanged - the bad value was rejected before saving


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


def test_admin_general_dashboard_url_save_and_reload(client):
    from auditor import config as cfg
    from auditor import db
    _login(client)
    r = client.post("/admin/general", data={"dashboard_url": "https://audit.example.com/"})
    assert r.status_code == 200
    assert "https://audit.example.com" in r.text
    conn = db.connect(DB)
    general = cfg.load_general(conn)
    conn.close()
    assert general["dashboard_url"] == "https://audit.example.com"   # trailing slash stripped


def test_admin_actions_are_audited(client):
    """SMTP save, general save, and dashboard-account changes should all leave a trace of who
    did what - separate from the findings this app raises about tenants' own activity."""
    from auditor import db

    _login(client)
    client.post("/admin/smtp", data={"host": "smtp.example.com", "port": "587", "user": "bot",
                "password": "hunter2", "from_addr": "bot@example.com", "starttls": "true"})
    client.post("/admin/general", data={"dashboard_url": "https://audit.example.com"})
    client.post("/admin/users/new", data={"username": "newbie", "password": "s3cret-pw"})

    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("SELECT action, actor, detail FROM admin_audit_log ORDER BY id")
        rows = cur.fetchall()
    conn.close()

    actions = [r["action"] for r in rows]
    assert "smtp.save" in actions
    assert "general.save" in actions
    assert "user.create" in actions
    smtp_row = next(r for r in rows if r["action"] == "smtp.save")
    assert smtp_row["actor"] == "tester"
    assert "hunter2" not in str(smtp_row["detail"])   # never logs the actual password
    assert smtp_row["detail"]["password_changed"] is True

    r = client.get("/admin/audit")
    assert r.status_code == 200
    assert "smtp.save" in r.text
    assert "hunter2" not in r.text


def test_tenant_crud_is_audited(client):
    from auditor import db

    _login(client)
    client.post("/admin/tenants/new", data={
        "id": "audited", "base_url": "https://audited.thereforeonline.com",
        "username": "svc", "password": "pw", "schedule_hour": "3", "schedule_minute": "30"})
    client.post(f"/admin/tenants/audited/edit", data={
        "base_url": "https://audited.thereforeonline.com", "username": "svc2",
        "schedule_hour": "3", "schedule_minute": "30"})
    client.post("/admin/tenants/audited/delete", data={"confirm": "audited"})

    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("SELECT action, tenant_id FROM admin_audit_log WHERE tenant_id='audited' ORDER BY id")
        rows = cur.fetchall()
    conn.close()
    assert [r["action"] for r in rows] == ["tenant.create", "tenant.update", "tenant.delete"]


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
    # Regression: a password typed just to test it must survive the re-render, or a Save
    # right after testing silently discards it instead of persisting what was just verified.
    assert 'name="password" value="hunter2"' in r.text


def test_admin_smtp_test_then_save_persists_the_tested_password(client, monkeypatch):
    """The exact bug scenario: type a new password, test it, then Save without retyping -
    relying on the password field having been re-filled by the test response."""
    from auditor import config as cfg
    from auditor import db
    monkeypatch.setattr("auditor.digest.send_email", lambda *a, **k: None)
    _login(client)
    r = client.post("/admin/smtp/test", data={
        "host": "smtp.example.com", "port": "587", "user": "bot", "password": "brandnewpw",
        "from_addr": "bot@example.com", "starttls": "true", "test_to": "craig@example.com"})
    assert 'value="brandnewpw"' in r.text   # what the browser would now resubmit on Save

    client.post("/admin/smtp", data={"host": "smtp.example.com", "port": "587", "user": "bot",
                "password": "brandnewpw", "from_addr": "bot@example.com", "starttls": "true"})
    conn = db.connect(DB)
    smtp = cfg.load_smtp(conn)
    conn.close()
    assert smtp["password"] == "brandnewpw"


def test_admin_smtp_test_without_typing_password_does_not_echo_saved_one(client, monkeypatch):
    """Testing the already-saved config (Password left blank) must not leak the real saved
    password into the HTML - only what was actually typed gets echoed."""
    from auditor import config as cfg
    from auditor import db
    conn = db.connect(DB)
    cfg.save_smtp(conn, host="smtp.example.com", port=587, user="bot", password="supersecret",
                  from_addr="bot@example.com", starttls=True)
    conn.close()
    monkeypatch.setattr("auditor.digest.send_email", lambda *a, **k: None)
    _login(client)
    r = client.post("/admin/smtp/test", data={
        "host": "smtp.example.com", "port": "587", "user": "bot", "password": "",
        "from_addr": "bot@example.com", "starttls": "true", "test_to": "craig@example.com"})
    assert "supersecret" not in r.text
    assert 'name="password" value=""' in r.text


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


def _fake_run_tenant_factory(db, DB, on_call=None):
    """A stand-in for pipeline.run_tenant() that mimics just enough of the real thing for the
    "Run now" web flow to work end to end in tests: insert a `runs` row (the real function's
    job, normally), call on_started with its id (the whole point of the async flow being
    tested), and return a minimal stats dict."""
    def fake_run_tenant(settings, tenant, on_started=None, **kwargs):
        if on_call:
            on_call(settings, tenant)
        conn = db.connect(DB)
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO runs (tenant_id, kind, finished_at, files, events, findings,
                               findings_changed) VALUES (%s, 'daily', now(), 0, 0, 0, 0) RETURNING id""",
                        (tenant.id,))
            run_id = cur.fetchone()["id"]
        conn.commit()
        conn.close()
        if on_started:
            on_started(run_id)
        return {"tenant": tenant.id, "files_new": 0, "events": 0, "findings": 0, "findings_changed": 0}
    return fake_run_tenant


def test_admin_run_now_redirects_to_a_polling_status_page(client, monkeypatch):
    """"Run now" must not block the HTTP request for the run's whole duration - a slow run can
    exceed a reverse proxy/tunnel's timeout (e.g. Cloudflare's ~100s) even though the run itself
    is still working fine. It should return almost immediately with a redirect to a status page
    that reflects the real run's outcome once finished."""
    from auditor import db
    calls = []
    monkeypatch.setattr("auditor.pipeline.run_tenant",
                        _fake_run_tenant_factory(db, DB, on_call=lambda s, t: calls.append(t.id)))
    _login(client)
    r = client.post("/admin/tenants/webtest/run", follow_redirects=False)
    assert r.status_code == 303
    assert "/admin/tenants/webtest/run/" in r.headers["location"]

    r2 = client.get(r.headers["location"])
    assert r2.status_code == 200
    assert "run complete" in r2.text
    assert calls == ["webtest"]


def test_run_now_refreshes_smtp_before_running(client, monkeypatch):
    """Regression: app.state.settings.smtp used to be frozen at load_settings()'s empty
    defaults for the whole life of the web process - SMTP saved via /admin/smtp after startup
    was silently never picked up by "Run now", so write_and_send()'s `if smtp.get("host")`
    check always failed and no digest email was ever sent, with no error anywhere."""
    from auditor import config as cfg
    from auditor import db
    conn = db.connect(DB)
    cfg.save_smtp(conn, host="smtp.example.com", port=587, user="bot", password="pw",
                  from_addr="bot@example.com", starttls=True)
    conn.close()

    seen_smtp = {}
    monkeypatch.setattr("auditor.pipeline.run_tenant",
                        _fake_run_tenant_factory(db, DB, on_call=lambda s, t: seen_smtp.update(s.smtp)))
    _login(client)
    r = client.post("/admin/tenants/webtest/run", follow_redirects=False)
    assert r.status_code == 303
    assert seen_smtp.get("host") == "smtp.example.com"


def test_run_status_shows_pending_page_while_still_running(client):
    from auditor import db
    _login(client)
    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("INSERT INTO runs (tenant_id, kind) VALUES ('webtest', 'daily') RETURNING id")
        run_id = cur.fetchone()["id"]
    conn.commit()
    conn.close()

    r = client.get(f"/admin/tenants/webtest/run/{run_id}")
    assert r.status_code == 200
    assert "run in progress" in r.text
    assert 'http-equiv="refresh"' in r.text


def test_run_status_404s_for_unknown_run_id(client):
    _login(client)
    r = client.get("/admin/tenants/webtest/run/999999")
    assert r.status_code == 404


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


def test_review_link_confirm_then_apply_without_login(client):
    """The whole point of these links is that the recipient isn't logged in - no _login() call
    here on purpose."""
    from auditor import db
    from auditor import link_tokens

    token = link_tokens.make_token("test-secret", "webtest", 1, "acknowledged")

    r = client.get(f"/review/{token}")
    assert r.status_code == 200
    assert "Mark as reviewed?" in r.text
    assert "New user: mallory" in r.text

    r = client.post(f"/review/{token}")
    assert r.status_code == 200
    assert "Done" in r.text

    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("SELECT status, reviewed_by FROM findings WHERE tenant_id='webtest' AND id=1")
        row = cur.fetchone()
        cur.execute("SELECT action, actor, tenant_id FROM admin_audit_log WHERE action='finding.acknowledged'")
        audit_row = cur.fetchone()
    conn.close()
    assert row["status"] == "acknowledged"
    assert row["reviewed_by"] == "review link (email)"
    assert audit_row["tenant_id"] == "webtest"


def test_review_link_rejects_bad_token(client):
    r = client.get("/review/not-a-real-token")
    assert r.status_code == 200
    assert "invalid or has expired" in r.text
    r = client.post("/review/not-a-real-token")
    assert r.status_code == 200
    assert "invalid or has expired" in r.text


def test_review_link_confirm_twice_shows_already_done(client):
    from auditor import link_tokens

    token = link_tokens.make_token("test-secret", "webtest", 1, "false_positive")
    client.post(f"/review/{token}")
    r = client.get(f"/review/{token}")
    assert r.status_code == 200
    assert "Already marked as" in r.text


def test_known_snooze_add_and_remove(client):
    """A snooze is forward-looking (since=now), so it deliberately does NOT retroactively
    suppress the seeded finding (dated an hour ago) - that's covered at the unit level in
    test_engine.py. This just checks the route stores/removes it correctly."""
    from auditor import config as cfg
    from auditor import db
    _login(client)
    r = client.post("/t/webtest/known/snooze", data={
        "rule_id": "new_entity", "scope_type": "user", "scope_value": "Contractor.Jane",
        "days": "14", "note": "onboarding"}, follow_redirects=False)
    assert r.status_code == 303

    conn = db.connect(DB)
    tenant = cfg.get_tenant(conn, "webtest")
    conn.close()
    snoozes = tenant.known["snoozes"]
    assert len(snoozes) == 1
    s = snoozes[0]
    assert s["rule_id"] == "new_entity"
    assert s["user"] == "contractor.jane"   # lowercased
    assert s["note"] == "onboarding"
    assert "id" in s and "since" in s and "until" in s

    r = client.get("/t/webtest/known")
    assert "new_entity" in r.text and "contractor.jane" in r.text

    r = client.post("/t/webtest/known/unsnooze", data={"id": s["id"]}, follow_redirects=False)
    assert r.status_code == 303
    conn = db.connect(DB)
    tenant = cfg.get_tenant(conn, "webtest")
    conn.close()
    assert tenant.known.get("snoozes", []) == []


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
