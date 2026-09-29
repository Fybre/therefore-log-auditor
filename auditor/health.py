"""Scheduler self-health check: the `log_gap` rule notices when a tenant's *Therefore* logs go
stale, but nothing previously noticed if the auditor's own scheduled runs for a tenant just
stopped happening (container crash-looping, a cron misconfiguration, expired credentials making
every run fail). This periodically checks each enabled tenant's recent `runs` history and emails
an alert (deduped so a persistent problem doesn't re-email every tick) if something looks wrong.
"""
from __future__ import annotations

import datetime as dt
import logging

import psycopg

from . import config, digest
from .config import Settings, Tenant
from .db import connect

log = logging.getLogger(__name__)

STUCK_AFTER = dt.timedelta(hours=3)
STALE_AFTER_DAILY = dt.timedelta(hours=36)     # covers the normal daily cron + its 6h catch-up window
STALE_AFTER_RESTRICTED = dt.timedelta(days=5)  # cron with a restricted weekday field (e.g. weekdays only)
REMIND_EVERY = dt.timedelta(hours=24)


def _is_restricted_schedule(cron: str) -> bool:
    fields = cron.split()
    return len(fields) == 5 and fields[4] != "*"


def check_tenant(conn: psycopg.Connection, tenant: Tenant, now: dt.datetime) -> str | None:
    """Returns a human-readable problem description, or None if the tenant looks healthy.
    Only considers non-backfill runs, since a manual backfill happening (or not) says nothing
    about whether the tenant's regular schedule is working."""
    with conn.cursor() as cur:
        cur.execute("""SELECT started_at, finished_at, error FROM runs
                       WHERE tenant_id=%s AND kind <> 'backfill'
                       ORDER BY started_at DESC LIMIT 1""", (tenant.id,))
        latest = cur.fetchone()
    if not latest:
        return None   # no baseline yet (e.g. a brand-new tenant) - nothing to flag
    if latest["error"]:
        return f"latest run failed: {latest['error'][:300]}"
    if latest["finished_at"] is None and now - latest["started_at"] > STUCK_AFTER:
        return f"latest run started {latest['started_at'].isoformat()} and has not finished"
    cron = (tenant.schedule or {}).get("daily", "30 3 * * *")
    threshold = STALE_AFTER_RESTRICTED if _is_restricted_schedule(cron) else STALE_AFTER_DAILY
    last_success = latest["finished_at"] or latest["started_at"]
    if now - last_success > threshold:
        return (f"no completed run in over {threshold} (last: {last_success.isoformat()}) - "
                f"schedule is '{cron}' ({tenant.display_tz})")
    return None


def _get_alert(conn: psycopg.Connection, tenant_id: str) -> dict | None:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM run_health_alerts WHERE tenant_id=%s", (tenant_id,))
        return cur.fetchone()


def _upsert_alert(conn: psycopg.Connection, tenant_id: str, reason: str, first_seen_at: dt.datetime,
                   last_alert_at: dt.datetime) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO run_health_alerts (tenant_id, reason, first_seen_at, last_alert_at)
               VALUES (%s, %s, %s, %s)
               ON CONFLICT (tenant_id) DO UPDATE SET reason=EXCLUDED.reason,
                   last_alert_at=EXCLUDED.last_alert_at""",
            (tenant_id, reason, first_seen_at, last_alert_at))
    conn.commit()


def _clear_alert(conn: psycopg.Connection, tenant_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM run_health_alerts WHERE tenant_id=%s", (tenant_id,))
    conn.commit()


def _recipients(settings: Settings, tenant: Tenant) -> list[str]:
    return settings.alert_email_to or (tenant.digest or {}).get("email_to") or []


def _send(settings: Settings, tenant: Tenant, subject: str, body: str) -> None:
    to = _recipients(settings, tenant)
    if not to or not settings.smtp.get("host"):
        log.warning("Health alert for %s not emailed (no recipients/SMTP configured): %s",
                    tenant.id, subject)
        return
    try:
        digest.send_email(settings.smtp, to, subject, body)
        log.info("Health alert emailed to %s: %s", to, subject)
    except Exception:
        log.exception("Failed to send health alert email for %s", tenant.id)


def run_health_check(settings: Settings) -> None:
    conn = connect(settings.database_url)
    try:
        config.refresh_from_db(settings, conn)
        now = dt.datetime.now(dt.timezone.utc)
        for t in settings.tenants:
            if not t.enabled:
                _clear_alert(conn, t.id)
                continue
            reason = check_tenant(conn, t, now)
            existing = _get_alert(conn, t.id)
            if reason:
                is_new = existing is None or existing["reason"] != reason
                due_reminder = existing and now - existing["last_alert_at"] > REMIND_EVERY
                if is_new or due_reminder:
                    first_seen = existing["first_seen_at"] if (existing and not is_new) else now
                    _upsert_alert(conn, t.id, reason, first_seen, now)
                    _send(settings, t, f"[Therefore audit] {t.id}: scheduler health problem",
                          f"Tenant {t.id} looks unhealthy:\n\n{reason}\n\n"
                          f"First seen: {first_seen.isoformat()}\n\n"
                          f"This is an automated check of the auditor's own run history, not "
                          f"of {t.id}'s Therefore logs (that's the separate log_gap finding).")
            elif existing:
                _clear_alert(conn, t.id)
                _send(settings, t, f"[Therefore audit] {t.id}: scheduler health recovered",
                      f"Tenant {t.id} is healthy again. Previous problem "
                      f"(first seen {existing['first_seen_at'].isoformat()}): {existing['reason']}")
    finally:
        conn.close()
