"""Command line: auditor {migrate,run,backfill,serve,findings}"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import sys

from .config import load_settings


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="auditor", description="Therefore log auditor")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("migrate", help="create/upgrade the database schema")

    r = sub.add_parser("run", help="collect new logs, run rules, triage, send digest")
    r.add_argument("--tenant", help="tenant id (default: all)")
    r.add_argument("--no-llm", action="store_true")
    r.add_argument("--no-digest", action="store_true")

    b = sub.add_parser("backfill", help="load history and run rules over it (no LLM/digest by default)")
    b.add_argument("--tenant", required=True)
    b.add_argument("--since", required=True, help="YYYY-MM-DD")
    b.add_argument("--llm", action="store_true", help="also triage the findings (costs tokens)")

    sub.add_parser("serve", help="run the scheduler (each tenant's schedule.daily cron)")

    f = sub.add_parser("findings", help="list recent findings")
    f.add_argument("--tenant", required=True)
    f.add_argument("--days", type=int, default=7)
    f.add_argument("--min-severity", default="low", choices=["info", "low", "medium", "high"])

    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load_settings()

    if a.cmd == "migrate":
        from .db import connect, migrate
        with connect(settings.database_url) as conn:
            print("applied:", migrate(conn) or "nothing to do")
        return 0

    if a.cmd == "run":
        from .pipeline import run_tenant
        tenants = [settings.tenant(a.tenant)] if a.tenant else settings.tenants
        ok = True
        for t in tenants:
            stats = run_tenant(settings, t, use_llm=not a.no_llm, send_digest=not a.no_digest)
            print(json.dumps(stats, default=str, indent=1))
            ok &= "error" not in stats
        return 0 if ok else 1

    if a.cmd == "backfill":
        from .pipeline import run_tenant
        since = dt.date.fromisoformat(a.since)
        stats = run_tenant(settings, settings.tenant(a.tenant), kind="backfill", since=since, use_llm=a.llm,
                           send_digest=a.llm, rules_from=dt.datetime.combine(since, dt.time(), dt.timezone.utc))
        print(json.dumps(stats, default=str, indent=1))
        return 0 if "error" not in stats else 1

    if a.cmd == "serve":
        from .scheduler import serve
        serve(settings)
        return 0

    if a.cmd == "findings":
        from .db import connect
        order = ["info", "low", "medium", "high"]
        allowed = order[order.index(a.min_severity):]
        with connect(settings.database_url) as conn, conn.cursor() as cur:
            cur.execute("""SELECT severity, rule_id, title, last_ts, llm_verdict FROM findings
                           WHERE tenant_id=%s AND last_ts >= now() - %s * interval '1 day' AND severity = ANY(%s)
                           ORDER BY last_ts DESC""", (a.tenant, a.days, allowed))
            for row in cur.fetchall():
                print(f"{row['last_ts']:%Y-%m-%d %H:%M} {row['severity']:6} {row['rule_id']:22} {row['title']}"
                      + (f"  [{row['llm_verdict']}]" if row["llm_verdict"] else ""))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
