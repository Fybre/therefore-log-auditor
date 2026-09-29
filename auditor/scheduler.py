"""Long-running scheduler for the container: runs each tenant on its cron (in its display_tz),
plus hourly catch-up retries until the day's Server log has arrived. Tenants come from the
database (managed via the dashboard), so a `reconcile` job periodically re-reads them and
adds/removes/reschedules jobs - no restart needed after adding, editing or deleting a tenant."""
from __future__ import annotations

import datetime as dt
import logging
from zoneinfo import ZoneInfo

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from . import config
from .config import Settings, Tenant
from .db import connect, migrate
from .health import run_health_check
from .pipeline import run_tenant

log = logging.getLogger(__name__)
RECONCILE_MINUTES = 5
HEALTH_CHECK_MINUTES = 30


def _has_todays_log(settings: Settings, tenant: Tenant) -> bool:
    """True if a Server log generated for the most recent rotation (UTC date) is stored."""
    with connect(settings.database_url) as conn, conn.cursor() as cur:
        cur.execute("""SELECT max(generated) AS g FROM log_files
                       WHERE tenant_id=%s AND application='Therefore Server' AND status='parsed'""", (tenant.id,))
        g = cur.fetchone()["g"]
    return g is not None and g >= dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=1)


def _schedule_tenant(sched: BlockingScheduler, settings: Settings, t: Tenant) -> None:
    tz = ZoneInfo(t.display_tz)
    cron = (t.schedule or {}).get("daily", "30 3 * * *")
    sched.add_job(run_tenant, CronTrigger.from_crontab(cron, timezone=tz), args=[settings, t],
                  id=f"daily-{t.id}", misfire_grace_time=3600, coalesce=True, max_instances=1,
                  replace_existing=True)

    def catch_up(tenant=t):
        if not _has_todays_log(settings, tenant):
            log.info("%s: today's Server log not seen yet, re-running", tenant.id)
            run_tenant(settings, tenant, send_digest=False)

    minute, hour = cron.split()[:2]
    if hour.isdigit():
        hours = ",".join(str((int(hour) + i) % 24) for i in range(1, 7))
        sched.add_job(catch_up, CronTrigger.from_crontab(f"{minute} {hours} * * *", timezone=tz),
                      id=f"catchup-{t.id}", coalesce=True, max_instances=1, replace_existing=True)
    log.info("Scheduled %s: '%s' (%s)", t.id, cron, t.display_tz)


def _reconcile(sched: BlockingScheduler, settings: Settings) -> None:
    with connect(settings.database_url) as conn:
        config.refresh_from_db(settings, conn)
    current_ids = {t.id for t in settings.tenants}
    scheduled_ids = {j.id.split("-", 1)[1] for j in sched.get_jobs() if j.id.startswith("daily-")}
    for tid in scheduled_ids - current_ids:
        for prefix in ("daily-", "catchup-"):
            job = sched.get_job(f"{prefix}{tid}")
            if job:
                job.remove()
        log.info("Unscheduled %s (removed or disabled)", tid)
    for t in settings.tenants:
        _schedule_tenant(sched, settings, t)   # replace_existing covers both new tenants and cron edits


def serve(settings: Settings) -> None:
    with connect(settings.database_url) as conn:
        migrate(conn)
    sched = BlockingScheduler()
    _reconcile(sched, settings)
    sched.add_job(_reconcile, "interval", args=[sched, settings], minutes=RECONCILE_MINUTES,
                  id="reconcile", coalesce=True, max_instances=1)
    sched.add_job(run_health_check, "interval", args=[settings], minutes=HEALTH_CHECK_MINUTES,
                  id="health-check", coalesce=True, max_instances=1)
    log.info("Scheduler started; re-checking tenants every %s minutes, health check every %s minutes",
             RECONCILE_MINUTES, HEALTH_CHECK_MINUTES)
    sched.start()
