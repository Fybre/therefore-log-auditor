"""Admin audit trail: records changes made to the auditor's own configuration (tenants, SMTP,
rule toggles, accounts) - separate from the findings this app raises about *tenants'* activity.
`detail` must never contain secrets (passwords, API keys); pass field names and non-secret
values only.
"""
from __future__ import annotations

from typing import Any

import psycopg
from psycopg.types.json import Jsonb


def log_action(conn: psycopg.Connection, actor: str, action: str,
                tenant_id: str | None = None, detail: dict[str, Any] | None = None) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO admin_audit_log (actor, action, tenant_id, detail)
               VALUES (%s, %s, %s, %s)""",
            (actor, action, tenant_id, Jsonb(detail or {})))
    conn.commit()


def recent(conn: psycopg.Connection, limit: int = 200) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM admin_audit_log ORDER BY at DESC LIMIT %s", (limit,))
        return cur.fetchall()
