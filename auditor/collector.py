"""Discover, fetch, parse and store Therefore log files. Safe to re-run: files are keyed by DocNo."""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
from dataclasses import dataclass

import psycopg

from . import parsers
from .config import Tenant
from .therefore import LogDoc, ThereforeClient

log = logging.getLogger(__name__)

EVENT_COLS = (
    "tenant_id", "doc_no", "line_no", "source", "ts", "username", "host", "ip", "action",
    "result_code", "success", "obj_doc_no", "obj_version", "category", "wf_instance", "wf_name",
    "client", "client_ver", "message",
)


@dataclass
class CollectResult:
    files_seen: int = 0
    files_new: int = 0
    events: int = 0
    min_ts: dt.datetime | None = None
    max_ts: dt.datetime | None = None
    doc_nos: list[int] | None = None


def last_generated(conn: psycopg.Connection, tenant_id: str) -> dt.date | None:
    with conn.cursor() as cur:
        cur.execute("SELECT max(generated) AS g FROM log_files WHERE tenant_id=%s", (tenant_id,))
        return cur.fetchone()["g"]


def known_doc_nos(conn: psycopg.Connection, tenant_id: str) -> set[int]:
    with conn.cursor() as cur:
        cur.execute("SELECT doc_no FROM log_files WHERE tenant_id=%s AND status='parsed'", (tenant_id,))
        return {r["doc_no"] for r in cur.fetchall()}


def collect(conn: psycopg.Connection, client: ThereforeClient, tenant: Tenant,
            since: dt.date | None = None, lookback_days: int = 7) -> CollectResult:
    """Fetch every log document with GENERATED >= since that isn't stored yet.
    Default `since` = last stored GENERATED date minus `lookback_days` (catches late files)."""
    if since is None:
        last = last_generated(conn, tenant.id)
        since = (last - dt.timedelta(days=lookback_days)) if last else dt.date.today() - dt.timedelta(days=30)
    docs = client.list_log_docs(since)
    have = known_doc_nos(conn, tenant.id)
    res = CollectResult(files_seen=len(docs), doc_nos=[])
    for doc in docs:
        if doc.doc_no in have:
            continue
        try:
            n, lo, hi = _ingest(conn, client, tenant, doc)
        except Exception as exc:  # keep going; record the error on the file row
            conn.rollback()
            log.exception("Failed to ingest DocNo %s", doc.doc_no)
            _mark_error(conn, tenant.id, doc, str(exc))
            continue
        res.files_new += 1
        res.events += n
        res.doc_nos.append(doc.doc_no)
        if lo and (res.min_ts is None or lo < res.min_ts):
            res.min_ts = lo
        if hi and (res.max_ts is None or hi > res.max_ts):
            res.max_ts = hi
    return res


def _ingest(conn, client: ThereforeClient, tenant: Tenant, doc: LogDoc):
    file_name, raw = client.get_stream(doc.doc_no)
    return store_file(conn, tenant, doc, file_name, raw)


def store_file(conn, tenant: Tenant, doc: LogDoc, file_name: str, raw: bytes):
    pf = parsers.parse(raw, doc.application, doc.log_format, tenant.log_tz)
    first = min((e.ts for e in pf.events), default=None)
    last = max((e.ts for e in pf.events), default=None)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM events WHERE tenant_id=%s AND doc_no=%s", (tenant.id, doc.doc_no))
        cur.execute(
            """INSERT INTO log_files (tenant_id, doc_no, application, server, generated, log_format,
                   file_name, size_bytes, sha256, raw, first_ts, last_ts, line_count, parser_version, status)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'parsed')
               ON CONFLICT (tenant_id, doc_no) DO UPDATE SET
                   raw=EXCLUDED.raw, sha256=EXCLUDED.sha256, first_ts=EXCLUDED.first_ts,
                   last_ts=EXCLUDED.last_ts, line_count=EXCLUDED.line_count,
                   parser_version=EXCLUDED.parser_version, status='parsed', error=NULL,
                   fetched_at=now()""",
            (tenant.id, doc.doc_no, doc.application, doc.server, doc.generated, doc.log_format,
             file_name, len(raw), hashlib.sha256(raw).hexdigest(), raw, first, last,
             len(pf.events), parsers.PARSER_VERSION),
        )
        with cur.copy(f"COPY events ({', '.join(EVENT_COLS)}) FROM STDIN") as cp:
            for e in pf.events:
                cp.write_row((
                    tenant.id, doc.doc_no, e.line_no, e.source, e.ts, e.username, e.host, e.ip,
                    e.action, e.result_code, e.success, e.obj_doc_no, e.obj_version, e.category,
                    e.wf_instance, e.wf_name, e.client, e.client_ver, e.message,
                ))
    conn.commit()
    if pf.unparsed:
        log.warning("DocNo %s: %d unparsed lines", doc.doc_no, len(pf.unparsed))
    return len(pf.events), first, last


def _mark_error(conn, tenant_id: str, doc: LogDoc, error: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO log_files (tenant_id, doc_no, application, server, generated, log_format, status, error)
               VALUES (%s,%s,%s,%s,%s,%s,'error',%s)
               ON CONFLICT (tenant_id, doc_no) DO UPDATE SET status='error', error=EXCLUDED.error""",
            (tenant_id, doc.doc_no, doc.application, doc.server, doc.generated, doc.log_format, error[:2000]),
        )
    conn.commit()


def snapshot_settings(conn, client: ThereforeClient, tenant: Tenant) -> dict | None:
    """Store the logging settings (keys 700-704). Returns the snapshot, or None if unreadable."""
    try:
        values = client.get_settings()
    except Exception as exc:
        log.warning("Could not read settings for %s: %s", tenant.id, exc)
        return None
    snap = {str(k): v for k, v in sorted(values.items())}
    with conn.cursor() as cur:
        cur.execute("INSERT INTO settings_snapshots (tenant_id, settings) VALUES (%s, %s)",
                    (tenant.id, psycopg.types.json.Jsonb(snap)))
    conn.commit()
    return snap
