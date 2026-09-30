"""Needs a Postgres at TEST_DATABASE_URL; skipped otherwise."""
import os
import threading

import pytest

DB = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB, reason="TEST_DATABASE_URL not set")


def test_concurrent_migrate_against_fresh_schema_does_not_race():
    """Regression test for a real race hit in production: the `auditor` (serve) and `web`
    containers both call migrate() independently on startup, and against a brand-new database
    they used to be able to race inside `CREATE TABLE IF NOT EXISTS schema_migrations` -
    Postgres's IF NOT EXISTS isn't safe against two sessions creating the same table at
    genuinely the same instant (both pass the existence check, then collide in pg_type).
    migrate() now serializes via a pg_advisory_lock, so this must succeed cleanly every time."""
    from auditor import db

    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    conn.commit()
    conn.close()

    errors = []
    results = []

    def run():
        try:
            c = db.connect(DB)
            results.append(db.migrate(c))
            c.close()
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, f"migrate() raised under concurrency: {errors}"

    conn = db.connect(DB)
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM schema_migrations")
        row_count = cur.fetchone()["n"]
        cur.execute("SELECT count(DISTINCT version) AS n FROM schema_migrations")
        distinct_count = cur.fetchone()["n"]
    conn.close()
    assert row_count == distinct_count   # no version applied/recorded more than once
    assert row_count > 0
