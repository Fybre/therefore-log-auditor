"""Command line: auditor {migrate,run,backfill,serve,web,findings,create-user,import-legacy-config}"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
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

    sub.add_parser("serve", help="run the scheduler (tenants + schedules come from the database)")

    w = sub.add_parser("web", help="run the findings dashboard")
    w.add_argument("--host", default="0.0.0.0")
    w.add_argument("--port", type=int, default=8080)

    f = sub.add_parser("findings", help="list recent findings")
    f.add_argument("--tenant", required=True)
    f.add_argument("--days", type=int, default=7)
    f.add_argument("--min-severity", default="low", choices=["info", "low", "medium", "high"])

    u = sub.add_parser("create-user", help="create/update a dashboard login")
    u.add_argument("username")
    u.add_argument("--password", help="omit to be prompted (not echoed)")

    sub.add_parser("import-legacy-config",
                    help="one-time: import config/tenants.yaml + THEREFORE_<ID>_USERNAME/PASSWORD "
                         "and SMTP_* from .env into the database")

    sub.add_parser("live", help="run opt-in live Console shadow collection (no notifications)")

    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load_settings()

    if a.cmd == "migrate":
        from .db import connect, migrate
        with connect(settings.database_url) as conn:
            print("applied:", migrate(conn) or "nothing to do")
        return 0

    if a.cmd in ("run", "backfill", "findings"):
        from . import config
        from .db import connect, migrate
        with connect(settings.database_url) as conn:
            migrate(conn)
            config.refresh_from_db(settings, conn)

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

    if a.cmd == "live":
        from .live.worker import serve
        serve(settings)
        return 0

    if a.cmd == "serve":
        from .scheduler import serve
        serve(settings)
        return 0

    if a.cmd == "web":
        import uvicorn
        from .web.app import create_app
        uvicorn.run(create_app(settings), host=a.host, port=a.port)
        return 0

    if a.cmd == "findings":
        order = ["info", "low", "medium", "high"]
        allowed = order[order.index(a.min_severity):]
        from .db import connect
        with connect(settings.database_url) as conn, conn.cursor() as cur:
            cur.execute("""SELECT severity, rule_id, title, last_ts, llm_verdict, incident_key FROM findings
                           WHERE tenant_id=%s AND last_ts >= now() - %s * interval '1 day' AND severity = ANY(%s)
                           ORDER BY last_ts DESC""", (a.tenant, a.days, allowed))
            for row in cur.fetchall():
                print(f"{row['last_ts']:%Y-%m-%d %H:%M} {row['severity']:6} {row['rule_id']:22} {row['title']}"
                      + (f"  [{row['llm_verdict']}]" if row["llm_verdict"] else "")
                      + (f"  (incident: {row['incident_key']})" if row["incident_key"] else ""))
        return 0

    if a.cmd == "create-user":
        from . import passwords
        from .db import connect, migrate
        password = a.password or getpass.getpass(f"Password for {a.username}: ")
        with connect(settings.database_url) as conn:
            migrate(conn)
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO web_users (username, password_hash) VALUES (%s, %s)
                       ON CONFLICT (username) DO UPDATE SET password_hash=EXCLUDED.password_hash,
                           disabled=false""",
                    (a.username, passwords.hash_password(password)))
            conn.commit()
        print(f"ok: {a.username} can now log in to the dashboard")
        return 0

    if a.cmd == "import-legacy-config":
        from .legacy_import import import_legacy_config
        from .db import connect, migrate
        with connect(settings.database_url) as conn:
            migrate(conn)
            report = import_legacy_config(conn)
        print(json.dumps(report, indent=1))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
