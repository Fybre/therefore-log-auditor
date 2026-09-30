"""Postgres access and migrations."""
from __future__ import annotations

import re
from importlib import resources

import psycopg
from psycopg.rows import dict_row


def connect(database_url: str) -> psycopg.Connection:
    return psycopg.connect(database_url, row_factory=dict_row, autocommit=False)


# Arbitrary fixed key for a session-level advisory lock, just to serialize migrate() across
# processes - the `auditor` (serve) and `web` containers both call this independently on
# startup with nothing else coordinating them, so against a fresh database they can race:
# both see schema_migrations doesn't exist yet and both run `CREATE TABLE IF NOT EXISTS`,
# which isn't safe against true concurrent execution (a narrow window where both sessions pass
# the existence check and then collide in Postgres's internal catalog). The lock forces one
# process to fully finish migrating before the other even starts.
_MIGRATION_LOCK_KEY = 0x41554449544F52   # "AUDITOR" in hex, arbitrary but stable


def migrate(conn: psycopg.Connection) -> list[int]:
    """Apply any migrations/NNN_*.sql not yet recorded. Returns versions applied."""
    files = sorted(
        (int(m.group(1)), f.name)
        for f in resources.files("auditor.migrations").iterdir()
        if (m := re.match(r"(\d+)_.*\.sql$", f.name))
    )
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_lock(%s)", (_MIGRATION_LOCK_KEY,))
        try:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
            )
            cur.execute("SELECT version FROM schema_migrations")
            done = {r["version"] for r in cur.fetchall()}
            applied = []
            for version, name in files:
                if version in done:
                    continue
                sql = resources.files("auditor.migrations").joinpath(name).read_text()
                cur.execute(sql)
                cur.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (version,))
                applied.append(version)
            conn.commit()
        finally:
            cur.execute("SELECT pg_advisory_unlock(%s)", (_MIGRATION_LOCK_KEY,))
            conn.commit()
    return applied
