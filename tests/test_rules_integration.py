"""Needs a Postgres at TEST_DATABASE_URL; skipped otherwise."""
import datetime as dt
import os

import pytest

from auditor.config import Settings, Tenant
from auditor.parsers import parse
from auditor.therefore import LogDoc

DB = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB, reason="TEST_DATABASE_URL not set")


def _lines(start, n, fmt):
    return "\n".join(fmt(start + dt.timedelta(seconds=10 * i), i) for i in range(n))


def test_rules_detect_attack_pattern():
    import yaml, psycopg
    from auditor import collector, db
    from auditor.rules.engine import Context, run_rules, save_findings
    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    conn.commit()
    db.migrate(conn)
    tenant = Tenant(id="t1", base_url="https://t1.thereforeonline.com", known={"users": []})
    rules = yaml.safe_load(open(os.path.join(os.path.dirname(__file__), "..", "config", "rules.yaml")))["rules"]
    settings = Settings(DB, [tenant], rules, "", "", "", {}, None)
    # 20 days of quiet history so warm-up passes, then an attack on day 21
    base = dt.datetime(2026, 1, 1, 9, 0)
    hist = "\n".join(f"{(base + dt.timedelta(days=d)):%Y-%m-%d, %H:%M:%S}|alice|PC1 (1.1.1.1)|Connect|0||||||Web Client 35.0.3"
                     for d in range(20))
    atk_t = base + dt.timedelta(days=21)
    fails = _lines(atk_t, 6, lambda t, i: f"{t:%Y-%m-%d, %H:%M:%S}|bob|EVIL (9.9.9.9)|Connect|27||||||failed: Invalid user name or password.   - API 35.0.3")
    ok = f"{atk_t + dt.timedelta(minutes=5):%Y-%m-%d, %H:%M:%S}|bob|EVIL (9.9.9.9)|Connect|0||||||Console 35.0.3"
    dels = _lines(atk_t + dt.timedelta(minutes=10), 250, lambda t, i: f"{t:%Y-%m-%d, %H:%M:%S}|bob|EVIL (9.9.9.9)|Doc Delete|0|{1000+i}|0|Invoices|||DocNo {1000+i}")
    raw = "\n".join([hist, fails, ok, dels]).encode()
    collector.store_file(conn, tenant, LogDoc(1, "Therefore Server", "srv", atk_t.date(), 4, None), "Server1U.txt", raw)
    ctx = Context(conn, settings, tenant, dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc),
                  dt.datetime(2026, 3, 1, tzinfo=dt.timezone.utc), realtime=False)
    found = {(f.rule_id, f.dedupe_key.split(":")[0]) for f in run_rules(ctx)}
    assert ("brute_force", "user") in found
    assert ("success_after_failures", "bob") in found
    assert ("new_entity", "admin_client") in found
    assert ("new_entity", "ip") in found
    assert ("mass_delete", "bob") in found
    # Suppression: marking bob as known downgrades to info, idempotent upsert
    tenant.known = {"users": ["bob"]}
    fs = run_rules(ctx)
    save_findings(conn, tenant, fs); save_findings(conn, tenant, fs)
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) n, count(*) FILTER (WHERE severity='info') i FROM findings WHERE rule_id='mass_delete'")
        r = cur.fetchone()
    assert r["n"] == 1 and r["i"] == 1
