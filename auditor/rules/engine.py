"""Rule engine: rules produce findings (with evidence) for a time window; findings are upserted
by (tenant, rule, dedupe_key) so re-running a window never duplicates."""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable

import psycopg
from psycopg.types.json import Jsonb

from ..config import Settings, Tenant

log = logging.getLogger(__name__)

SEVERITIES = ["info", "low", "medium", "high"]


@dataclass
class Finding:
    rule_id: str
    dedupe_key: str
    title: str
    severity: str
    first_ts: dt.datetime
    last_ts: dt.datetime
    details: dict[str, Any] = field(default_factory=dict)
    evidence_ids: list[int] = field(default_factory=list)
    subject_users: list[str] = field(default_factory=list)
    subject_ips: list[str] = field(default_factory=list)


@dataclass
class Context:
    conn: psycopg.Connection
    settings: Settings
    tenant: Tenant
    start: dt.datetime
    end: dt.datetime
    realtime: bool          # False during backfill: skip checks that compare against "now"

    def cfg(self, rule_id: str) -> dict[str, Any]:
        return self.settings.rule_config(self.tenant, rule_id)

    def q(self, sql: str, params: dict[str, Any] | None = None) -> list[dict]:
        p = {"tenant": self.tenant.id, "start": self.start, "end": self.end}
        p.update(params or {})
        with self.conn.cursor() as cur:
            cur.execute(sql, p)
            return cur.fetchall()


RULES: dict[str, Callable[[Context], list[Finding]]] = {}


def rule(rule_id: str):
    def deco(fn):
        RULES[rule_id] = fn
        return fn
    return deco


def template(message: str | None) -> str:
    """Normalise a message so the same failure with different ids groups together."""
    m = message or ""
    m = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "<guid>", m)
    m = re.sub(r"\d+", "#", m)
    m = re.sub(r"\s+", " ", m).strip()
    return m[:300]


def short_hash(*parts: Any) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def run_rules(ctx: Context, only: list[str] | None = None) -> list[Finding]:
    from . import builtin  # noqa: F401  (registers rules)
    out: list[Finding] = []
    for rule_id, fn in RULES.items():
        if only and rule_id not in only:
            continue
        cfg = ctx.cfg(rule_id)
        if not cfg.get("enabled", True):
            continue
        try:
            found = fn(ctx)
        except Exception:
            ctx.conn.rollback()
            log.exception("Rule %s failed", rule_id)
            continue
        out.extend(found)
    return out


# --- Suppressions ----------------------------------------------------------------------

def suppression_for(f: Finding, tenant: Tenant) -> str | None:
    known = tenant.known or {}
    users = {u.lower() for u in known.get("users", [])}
    ips = set(known.get("ips", []))
    if f.subject_users and all(u and u.lower() in users for u in f.subject_users):
        return "known user"
    if f.subject_ips and all(ip in ips for ip in f.subject_ips):
        return "known ip"
    for w in known.get("windows", []) or []:
        try:
            ws, we = dt.datetime.fromisoformat(str(w["start"])), dt.datetime.fromisoformat(str(w["end"]))
        except (KeyError, ValueError):
            continue
        if ws <= f.first_ts and f.last_ts <= we:
            return f"change window: {w.get('note', '')}".strip()
    return None


# --- Persistence -----------------------------------------------------------------------

def save_findings(conn: psycopg.Connection, tenant: Tenant, findings: list[Finding]) -> list[int]:
    """Upsert findings. Returns ids of findings that are new or materially changed
    (these need (re-)triage by the LLM)."""
    changed: list[int] = []
    with conn.cursor() as cur:
        for f in findings:
            supp = suppression_for(f, tenant)
            severity = "info" if supp else f.severity
            cur.execute(
                """INSERT INTO findings (tenant_id, rule_id, dedupe_key, title, rule_severity, severity,
                       first_ts, last_ts, details, evidence_ids, suppressed_by)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (tenant_id, rule_id, dedupe_key) DO UPDATE SET
                       title=EXCLUDED.title,
                       first_ts=LEAST(findings.first_ts, EXCLUDED.first_ts),
                       last_ts=GREATEST(findings.last_ts, EXCLUDED.last_ts),
                       details=EXCLUDED.details, evidence_ids=EXCLUDED.evidence_ids,
                       rule_severity=EXCLUDED.rule_severity,
                       severity=CASE WHEN findings.llm_verdict IS NOT NULL
                                      AND findings.details = EXCLUDED.details
                                     THEN findings.severity ELSE EXCLUDED.severity END,
                       suppressed_by=EXCLUDED.suppressed_by,
                       llm_verdict=CASE WHEN findings.details = EXCLUDED.details
                                        THEN findings.llm_verdict ELSE NULL END,
                       updated_at=CASE WHEN findings.details = EXCLUDED.details
                                       THEN findings.updated_at ELSE now() END
                   RETURNING id, (xmax = 0) AS inserted, llm_verdict""",
                (tenant.id, f.rule_id, f.dedupe_key, f.title, f.severity, severity, f.first_ts,
                 f.last_ts, Jsonb(f.details), f.evidence_ids[:200], supp),
            )
            row = cur.fetchone()
            if row["llm_verdict"] is None:
                changed.append(row["id"])
    conn.commit()
    return changed
