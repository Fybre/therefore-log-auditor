"""Needs a Postgres at TEST_DATABASE_URL; skipped otherwise."""
import datetime as dt
import os

import pytest

DB = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB, reason="TEST_DATABASE_URL not set")


@pytest.fixture
def conn_and_settings(monkeypatch):
    from auditor import config as cfg
    from auditor import db
    from auditor.config import Settings

    from cryptography.fernet import Fernet
    monkeypatch.setenv("AUDITOR_ENC_KEY", Fernet.generate_key().decode())
    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    conn.commit()
    db.migrate(conn)

    cfg.save_tenant(conn, id="healthtest", base_url="https://healthtest.thereforeonline.com",
                    username="svc", password="pw", tenant_name_override=None, log_category_no=1,
                    log_tz="UTC", display_tz="UTC", schedule_cron="30 3 * * *", llm_enabled=True,
                    llm_redact=True, digest_email_to=["ops@acme.test"], digest_only_on_new=False,
                    known={}, enabled=True)
    settings = Settings(DB, [], {}, "", "", "", {"host": "smtp.example.com", "port": 587}, None)
    cfg.refresh_from_db(settings, conn)
    try:
        yield conn, settings
    finally:
        conn.close()   # must not leave an open transaction - it would lock-block the next
                        # test's DROP SCHEMA CASCADE and hang the whole suite


def _insert_run(conn, tenant_id, *, kind="daily", started_at, finished_at=None, error=None):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO runs (tenant_id, kind, started_at, finished_at, error)
                       VALUES (%s, %s, %s, %s, %s)""", (tenant_id, kind, started_at, finished_at, error))
    conn.commit()


def test_check_tenant_healthy_when_recent_successful_run(conn_and_settings):
    from auditor.health import check_tenant

    conn, settings = conn_and_settings
    tenant = settings.tenant("healthtest")
    now = dt.datetime.now(dt.timezone.utc)
    _insert_run(conn, "healthtest", started_at=now - dt.timedelta(hours=2), finished_at=now - dt.timedelta(hours=1, minutes=55))
    assert check_tenant(conn, tenant, now) is None


def test_check_tenant_flags_stale_run(conn_and_settings):
    from auditor.health import check_tenant

    conn, settings = conn_and_settings
    tenant = settings.tenant("healthtest")
    now = dt.datetime.now(dt.timezone.utc)
    _insert_run(conn, "healthtest", started_at=now - dt.timedelta(hours=40), finished_at=now - dt.timedelta(hours=39))
    reason = check_tenant(conn, tenant, now)
    assert reason and "no completed run" in reason


def test_check_tenant_flags_failed_run(conn_and_settings):
    from auditor.health import check_tenant

    conn, settings = conn_and_settings
    tenant = settings.tenant("healthtest")
    now = dt.datetime.now(dt.timezone.utc)
    _insert_run(conn, "healthtest", started_at=now - dt.timedelta(minutes=10),
                finished_at=now - dt.timedelta(minutes=9), error="boom")
    reason = check_tenant(conn, tenant, now)
    assert reason and "boom" in reason


def test_check_tenant_flags_stuck_run(conn_and_settings):
    from auditor.health import check_tenant

    conn, settings = conn_and_settings
    tenant = settings.tenant("healthtest")
    now = dt.datetime.now(dt.timezone.utc)
    _insert_run(conn, "healthtest", started_at=now - dt.timedelta(hours=5), finished_at=None)
    reason = check_tenant(conn, tenant, now)
    assert reason and "not finished" in reason


def test_check_tenant_ignores_backfill_only_history(conn_and_settings):
    """A tenant with only a backfill run (no daily runs yet) shouldn't be flagged - there's no
    baseline for what a normal run looks like yet."""
    from auditor.health import check_tenant

    conn, settings = conn_and_settings
    tenant = settings.tenant("healthtest")
    now = dt.datetime.now(dt.timezone.utc)
    _insert_run(conn, "healthtest", kind="backfill", started_at=now - dt.timedelta(hours=100),
                finished_at=now - dt.timedelta(hours=99))
    assert check_tenant(conn, tenant, now) is None


def test_run_health_check_emails_once_then_dedupes(conn_and_settings, monkeypatch):
    from auditor import health

    conn, settings = conn_and_settings
    now = dt.datetime.now(dt.timezone.utc)
    _insert_run(conn, "healthtest", started_at=now - dt.timedelta(minutes=10),
                finished_at=now - dt.timedelta(minutes=9), error="boom")
    conn.close()

    sent = []
    monkeypatch.setattr("auditor.digest.send_email", lambda *a, **k: sent.append(a))

    health.run_health_check(settings)
    assert len(sent) == 1

    health.run_health_check(settings)   # same problem, no reminder due yet
    assert len(sent) == 1

    with health.connect(settings.database_url) as c, c.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM run_health_alerts WHERE tenant_id='healthtest'")
        assert cur.fetchone()["n"] == 1


def test_run_health_check_sends_recovery_email(conn_and_settings, monkeypatch):
    from auditor import health

    conn, settings = conn_and_settings
    now = dt.datetime.now(dt.timezone.utc)
    _insert_run(conn, "healthtest", started_at=now - dt.timedelta(minutes=10),
                finished_at=now - dt.timedelta(minutes=9), error="boom")
    conn.close()

    sent = []
    monkeypatch.setattr("auditor.digest.send_email", lambda *a, **k: sent.append(a))
    health.run_health_check(settings)
    assert len(sent) == 1

    with health.connect(settings.database_url) as c:
        _insert_run(c, "healthtest", started_at=now, finished_at=now + dt.timedelta(minutes=1))
    health.run_health_check(settings)
    assert len(sent) == 2
    assert "recovered" in sent[1][2]   # (smtp, to, subject, body)

    with health.connect(settings.database_url) as c, c.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM run_health_alerts WHERE tenant_id='healthtest'")
        assert cur.fetchone()["n"] == 0
