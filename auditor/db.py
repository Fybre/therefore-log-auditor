"""Postgres access and migrations."""
from __future__ import annotations

import re
from importlib import resources

import psycopg
from psycopg.rows import dict_row


def connect(database_url: str) -> psycopg.Connection:
    return psycopg.connect(database_url, row_factory=dict_row, autocommit=False)


def migrate(conn: psycopg.Connection) -> list[int]:
    """Apply any migrations/NNN_*.sql not yet recorded. Returns versions applied."""
    files = sorted(
        (int(m.group(1)), f.name)
        for f in resources.files("auditor.migrations").iterdir()
        if (m := re.match(r"(\d+)_.*\.sql$", f.name))
    )
    with conn.cursor() as cur:
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
    return applied
