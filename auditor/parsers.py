"""Parse Therefore log files into normalised events.

LogFormat 4 (Therefore Server, Server1U.txt): 11 pipe-delimited columns
    date | user | computer (ip) | action | result code | DocNo | version | category |
    workflow instance | workflow name | message
LogFormat 5 (Therefore Migrate) and 6 (Content Connector): "YYYY-MM-DD, HH:MM:SS <free text>"
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from zoneinfo import ZoneInfo

PARSER_VERSION = 1

TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}), (\d{2}:\d{2}:\d{2})")
HOST_IP_RE = re.compile(r"^(?P<host>.*?)\s*\((?P<ip>[0-9a-fA-F:.]+)\)\s*$")
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*$")
# Client + version at the end of the message: "... - Console 35.0.3", "API 35.0.3", "eForms (anonymous) 31.0.9"
CLIENT_RE = re.compile(r"(?:^|\s-\s+)(?P<client>[A-Za-z][A-Za-z ()]*?)\s+(?P<ver>\d+(?:\.\d+){1,3})\s*$")
NOT_CLIENTS = {"DocNo", "Id", "InstanceNo", "TokenNo", "Counter", "Category"}
DOCNO_RE = re.compile(r"DocNo[:\s]+(\d+)(?:\.(\d+))?")

SOURCES = {4: "server", 5: "migrate", 6: "content_connector"}
APP_SOURCES = {
    "therefore server": "server",
    "therefore migrate": "migrate",
    "therefore content connector": "content_connector",
}


@dataclass
class Event:
    line_no: int
    source: str
    ts: dt.datetime
    action: str
    username: str | None = None
    host: str | None = None
    ip: str | None = None
    result_code: int | None = None
    success: bool | None = None
    obj_doc_no: int | None = None
    obj_version: int | None = None
    category: str | None = None
    wf_instance: str | None = None
    wf_name: str | None = None
    client: str | None = None
    client_ver: str | None = None
    message: str | None = None


@dataclass
class ParsedFile:
    source: str
    header: dict[str, str] = field(default_factory=dict)
    events: list[Event] = field(default_factory=list)
    unparsed: list[tuple[int, str]] = field(default_factory=list)


def decode(raw: bytes) -> str:
    text = raw.decode("utf-8-sig", errors="replace")
    # Some headers are double-encoded ("Thereforeâ„¢"); fix the common case.
    return text.replace("â„¢", "™")


def source_for(application: str | None, log_format: int | None) -> str:
    if log_format in SOURCES:
        return SOURCES[log_format]
    return APP_SOURCES.get((application or "").strip().lower(), "server")


def parse(raw: bytes, application: str | None = None, log_format: int | None = None,
          log_tz: str = "UTC") -> ParsedFile:
    source = source_for(application, log_format)
    tz = ZoneInfo(log_tz)
    pf = ParsedFile(source=source)
    for i, line in enumerate(decode(raw).splitlines(), start=1):
        line = line.rstrip()
        if not line:
            continue
        m = TS_RE.match(line)
        if not m:
            if ":" in line and not pf.events:
                k, _, v = line.strip().partition(":")
                pf.header[k.strip()] = v.strip()
            elif pf.events:
                pf.unparsed.append((i, line))
            continue
        ts = dt.datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}").replace(tzinfo=tz)
        try:
            ev = _parse_server(i, ts, line) if source == "server" else _parse_text(i, ts, source, line[m.end():])
        except Exception:  # never drop a line silently
            ev = None
        if ev is None:
            pf.unparsed.append((i, line))
        else:
            pf.events.append(ev)
    return pf


def _parse_server(line_no: int, ts: dt.datetime, line: str) -> Event | None:
    cols = line.split("|", 10)
    if len(cols) < 11:
        return None
    _, user, computer, action, code, docno, ver, category, wf_inst, wf_name, message = (c.strip() for c in cols)
    host, ip = split_computer(computer)
    message = message or None
    code_i = int(code) if code.lstrip("-").isdigit() else None
    failed = (message or "").lower().startswith("failed:") or action == "Server Task Failure"
    ev = Event(
        line_no=line_no, source="server", ts=ts, action=action or "Unknown",
        username=user or None, host=host, ip=ip, result_code=code_i,
        success=(not failed) if code_i is not None else None,
        obj_doc_no=int(docno) if docno.isdigit() else None,
        obj_version=int(ver) if ver.isdigit() else None,
        category=category or None, wf_instance=wf_inst or None, wf_name=wf_name or None,
        message=message,
    )
    if message:
        cm = CLIENT_RE.search(message)
        if cm and len(cm.group("client")) <= 40 and cm.group("client").strip() not in NOT_CLIENTS:
            ev.client, ev.client_ver = cm.group("client").strip(), cm.group("ver")
        if ev.obj_doc_no is None:
            dm = DOCNO_RE.search(message)
            if dm:
                ev.obj_doc_no = int(dm.group(1))
                if dm.group(2):
                    ev.obj_version = int(dm.group(2))
    return ev


def split_computer(computer: str) -> tuple[str | None, str | None]:
    computer = computer.strip()
    if not computer:
        return None, None
    m = HOST_IP_RE.match(computer)
    if m:
        return (m.group("host").strip() or None), m.group("ip")
    if IP_RE.match(computer):
        return None, computer
    return computer, None


# Free-text templates for Migrate / Content Connector. First match wins.
TEXT_TEMPLATES: list[tuple[str, re.Pattern]] = [
    ("Service Stopped", re.compile(r"service stopped", re.I)),
    ("Tenant Started", re.compile(r"tenant started", re.I)),
    ("Migrate Stopped", re.compile(r"Therefore Migrate stopped", re.I)),
    ("Resultset Empty", re.compile(r"^BuildResultSet\s+The resultset is empty", re.I)),
    ("Documents Pending", re.compile(r"^BuildResultSet\s+\S+\s+(\d+) documents pending", re.I)),
    ("Worker Started", re.compile(r"^Start worker\s", re.I)),
    ("Worker Completed", re.compile(r"^Worker completed\s", re.I)),
    ("Fetch", re.compile(r"^Fetch\s", re.I)),
    ("Process", re.compile(r"^Process\s", re.I)),
]
ERROR_RE = re.compile(r"\bError\s*\d*\s*:", re.I)


def _parse_text(line_no: int, ts: dt.datetime, source: str, rest: str) -> Event:
    msg = rest.strip()
    action = "Message"
    for name, pat in TEXT_TEMPLATES:
        if pat.search(msg):
            action = name
            break
    failed = bool(ERROR_RE.search(msg))
    return Event(line_no=line_no, source=source, ts=ts, action=action, success=not failed,
                 message=re.sub(r"\s{2,}", "  ", msg))
