"""One run for one tenant: collect -> settings snapshot -> rules -> LLM triage -> digest."""
from __future__ import annotations

import datetime as dt
import logging
from typing import Callable

from . import collector, digest, llm
from .config import Settings, Tenant
from .db import connect, migrate
from .rules.engine import Context, run_rules, save_findings
from .therefore import ThereforeClient

log = logging.getLogger(__name__)


def run_tenant(settings: Settings, tenant: Tenant, kind: str = "daily", since: dt.date | None = None,
               use_llm: bool = True, send_digest: bool = True, rules_from: dt.datetime | None = None,
               on_started: Callable[[int], None] | None = None) -> dict:
    """`on_started`, if given, is called with the new `runs.id` as soon as it's known (before
    any of the slow work below) - lets a caller running this in a background thread hand the
    run id back to a web request immediately, rather than blocking on the whole run."""
    conn = connect(settings.database_url)
    migrate(conn)
    started = dt.datetime.now(dt.timezone.utc)
    with conn.cursor() as cur:
        cur.execute("INSERT INTO runs (tenant_id, kind) VALUES (%s, %s) RETURNING id", (tenant.id, kind))
        run_id = cur.fetchone()["id"]
    conn.commit()
    if on_started:
        on_started(run_id)
    stats: dict = {"tenant": tenant.id, "kind": kind}
    try:
        client = ThereforeClient(tenant)
        res = collector.collect(conn, client, tenant, since=since)
        stats.update(files_new=res.files_new, events=res.events)
        snap = collector.snapshot_settings(conn, client, tenant)
        stats["settings_snapshot"] = snap is not None

        now = dt.datetime.now(dt.timezone.utc)
        start = rules_from or min(filter(None, [res.min_ts, now - dt.timedelta(days=2)]))
        # Align to UTC midnight so per-day aggregates (deletes per day, etc.) are always whole days
        start = dt.datetime.combine(start.astimezone(dt.timezone.utc).date(), dt.time(), dt.timezone.utc)
        ctx = Context(conn, settings, tenant, start, now + dt.timedelta(minutes=1),
                      realtime=(kind != "backfill"))
        findings = run_rules(ctx)
        changed = save_findings(conn, tenant, findings)
        stats.update(findings=len(findings), findings_changed=len(changed))

        provider = None
        if use_llm and tenant.llm.get("enabled", True) and settings.llm_base_url and settings.llm_model:
            try:
                provider = llm.OpenAICompatProvider(settings.llm_base_url, settings.llm_api_key, settings.llm_model)
            except llm.LLMError as exc:
                log.warning("LLM unavailable: %s", exc)
        if provider:
            with conn.cursor() as cur:   # plus anything in the window not yet triaged
                cur.execute("""SELECT id FROM findings WHERE tenant_id=%s AND llm_verdict IS NULL
                               AND severity <> 'info' AND last_ts >= %s""", (tenant.id, ctx.start))
                todo = sorted(set(changed) | {r["id"] for r in cur.fetchall()})
            stats["llm"] = llm.triage(conn, settings, tenant, todo, provider=provider)

        if send_digest:
            data = digest.gather(conn, tenant, started)
            summary = None
            if provider and data["findings"]:
                summary = llm.summarise(provider, tenant, {"counts": data["counts"], **stats}, data["findings"])
            if provider:
                stats["llm_tokens"] = provider.usage.total
            subject, md, body = digest.render(tenant, data, summary, stats, dashboard_url=settings.dashboard_url,
                                              review_secret=settings.review_link_secret)
            stats["report"] = str(digest.write_and_send(settings, tenant, subject, md, body,
                                                         has_new_findings=stats["findings_changed"] > 0))
    except Exception as exc:
        conn.rollback()
        stats["error"] = str(exc)
        log.exception("Run failed for %s", tenant.id)
    finally:
        llm_stats = stats.get("llm") or {}
        with conn.cursor() as cur:
            cur.execute("""UPDATE runs SET finished_at=now(), files=%s, events=%s, findings=%s,
                               llm_tokens=%s, error=%s, findings_changed=%s, llm_triaged=%s,
                               llm_failed=%s, llm_skipped=%s WHERE id=%s""",
                        (stats.get("files_new", 0), stats.get("events", 0), stats.get("findings", 0),
                         stats.get("llm_tokens", 0), stats.get("error"), stats.get("findings_changed", 0),
                         llm_stats.get("triaged"), llm_stats.get("failed"), llm_stats.get("skipped"),
                         run_id))
        conn.commit()
        conn.close()
    return stats
