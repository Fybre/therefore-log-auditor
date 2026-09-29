"""Minimal Therefore Online REST client for the auditor.

Every call is authenticated with Basic auth (the token from GetConnectionToken is not a
usable Bearer token), and every call is itself logged by Therefore as a Connect/Disconnect
when connect logging is on — so keep the number of calls per run small.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Iterator

import requests

from .config import Tenant


class ThereforeError(RuntimeError):
    def __init__(self, op: str, status: int, message: str):
        super().__init__(f"{op} failed ({status}): {message}")
        self.op, self.status, self.message = op, status, message


@dataclass
class LogDoc:
    doc_no: int
    application: str
    server: str | None
    generated: dt.date
    log_format: int | None
    size: int | None


LOGFILE_FIELDS = ("APPLICATION", "SERVER", "GENERATED", "LogFormat")
LOGGING_SETTING_KEYS = (700, 701, 702, 703, 704)


class ThereforeClient:
    def __init__(self, tenant: Tenant, timeout: int = 120):
        self.tenant = tenant
        root = tenant.base_url.rstrip("/")
        if "/restun" not in root:
            root += "/theservice/v0001/restun"
        self.url = root + "/"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = (tenant.username, tenant.password)
        self.session.headers["Content-Type"] = "application/json; charset=utf-8"
        if tenant.tenant_name:
            self.session.headers["TenantName"] = tenant.tenant_name

    def post(self, op: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        r = self.session.post(self.url + op, json=body or {}, timeout=self.timeout)
        if r.status_code != 200:
            msg = r.text[:500]
            try:
                msg = r.json()["WSError"]["ErrorMessage"].strip()
            except Exception:
                pass
            raise ThereforeError(op, r.status_code, msg)
        return r.json() if r.content else {}

    # --- Logfiles ------------------------------------------------------------------

    def list_log_docs(self, since: dt.date, until: dt.date | None = None) -> list[LogDoc]:
        """Log documents with GENERATED in [since, until). Queried month by month because an
        unconditioned query silently stops at 500 rows."""
        until = until or (dt.date.today() + dt.timedelta(days=2))
        out: dict[int, LogDoc] = {}
        for lo, hi in _month_windows(since, until):
            for row in self._query_all(
                self.tenant.log_category_no,
                [{"FieldNoOrName": "GENERATED", "Condition": f">= {lo.isoformat()} AND < {hi.isoformat()}"}],
            ):
                gen = row.get("GENERATED")
                out[row["DocNo"]] = LogDoc(
                    doc_no=row["DocNo"],
                    application=row.get("APPLICATION") or "",
                    server=row.get("SERVER"),
                    generated=dt.date.fromisoformat(str(gen)[:10]) if gen else lo,
                    log_format=int(row["LogFormat"]) if str(row.get("LogFormat") or "").isdigit() else None,
                    size=row.get("_size"),
                )
        return sorted(out.values(), key=lambda d: (d.generated, d.doc_no))

    def _query_all(self, category_no: int, conditions: list[dict]) -> Iterator[dict]:
        res = self.post("ExecuteAsyncSingleQuery", {"Query": {
            "CategoryNo": category_no, "Conditions": conditions,
            "SelectedFieldsNoOrNames": list(LOGFILE_FIELDS),
            "MaxRows": 2147483647, "RowBlockSize": 500, "Mode": 0,
        }})
        qid = res.get("QueryId")
        try:
            while True:
                qr = res.get("QueryResult") or {}
                cols = [c.get("ColName") or c.get("Caption") for c in qr.get("Columns", [])]
                for row in qr.get("ResultRows", []):
                    d = dict(zip(cols, row.get("IndexValues", [])))
                    d["DocNo"], d["_size"] = row["DocNo"], row.get("Size")
                    yield d
                if not res.get("HasRemainingRows"):
                    break
                res = self.post("GetNextSingleQueryRows", {"QueryID": qid, "RowBlockSize": 500})
        finally:
            if qid is not None:
                try:
                    self.post("ReleaseSingleQuery", {"QueryID": qid})
                except ThereforeError:
                    pass

    def get_stream(self, doc_no: int, stream_no: int = 0) -> tuple[str, bytes]:
        res = self.post("GetDocumentStream", {"DocNo": doc_no, "StreamNo": stream_no})
        return res.get("FileName") or f"{doc_no}.txt", bytes(res.get("FileData") or [])

    # --- Settings ------------------------------------------------------------------

    def get_settings(self, keys: tuple[int, ...] = LOGGING_SETTING_KEYS) -> dict[int, Any]:
        """Read settings by key. One unknown key fails the whole batch, so only pass known keys."""
        res = self.post("GetSettings", {"SettingKeys": list(keys)})
        return {s["Key"]: s.get("IntValue", s.get("StringValue")) for s in res.get("Settings") or []}

    def test_connection(self) -> None:
        """Raises ThereforeError (bad credentials/tenant) or requests.RequestException
        (unreachable host) on failure. Does not touch Logfiles/settings - just auth."""
        self.post("GetConnectionToken")


def _month_windows(since: dt.date, until: dt.date) -> Iterator[tuple[dt.date, dt.date]]:
    lo = since
    while lo < until:
        nxt = (lo.replace(day=1) + dt.timedelta(days=32)).replace(day=1)
        hi = min(nxt, until)
        yield lo, hi
        lo = hi
