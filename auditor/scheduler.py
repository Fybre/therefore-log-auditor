"""Long-running scheduler for the container: runs each tenant on its cron (in its display_tz),
plus hourly catch-up retries until the day's Server log has arrived."""
from __future__ import annotations

import datetime as dt
import logging
from zoneinfo import ZoneInfo

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from .config import Settings, Tenant
from .db import connect, migrate
from .pipeline import run_tenant

log = logging.getLogger(__name__)


def _has_todays_log(settings: Settings, tenant: Tenant) -> bool:
    """True if a Server log generated for the most recent rotation (UTC date) is stored."""
    with connect(settings.database_url) as conn, conn.cursor() as cur:
        cur.execute("""SELECT max(generated) AS g FROM log_files
                       WHERE tenant_id=%s AND application='Therefore Server' AND status='parsed'""", (tenant.id,))
        g = cur.fetchone()["g"]
    return g is not None and g >= dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=1)


def serve(settings: Settings) -> None:
    with connect(settings.database_url) as conn:
        migrate(conn)
    sched = BlockingScheduler()
    for t in settings.tenants:
        tz = ZoneInfo(t.display_tz)
        cron = (t.schedule or {}).get("daily", "30 3 * * *")
        sched.add_job(run_tenant, CronTrigger.from_crontab(cron, timezone=tz), args=[settings, t],
                      id=f"daily-{t.id}", misfire_grace_time=3600, coalesce=True, max_instances=1)

        def catch_up(tenant=t):
            if not _has_todays_log(settings, tenant):
                log.info("%s: today's Server log not seen yet, re-running", tenant.id)
                run_tenant(settings, tenant, send_digest=False)

        # Hourly retry for 6 hours after the daily run, only if the log hadn't arrived.
        minute, hour = cron.split()[:2]
        if hour.isdigit():
            hours = ",".join(str((int(hour) + i) % 24) for i in range(1, 7))
            sched.add_job(catch_up, CronTrigger.from_crontab(f"{minute} {hours} * * *", timezone=tz),
                          id=f"catchup-{t.id}", coalesce=True, max_instances=1)
        log.info("Scheduled %s: '%s' (%s)", t.id, cron, t.display_tz)
    sched.start()
