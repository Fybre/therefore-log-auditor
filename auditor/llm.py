"""LLM triage over findings, via any OpenAI-compatible chat completions endpoint
(OpenRouter, Azure OpenAI, Ollama, LM Studio). The LLM never sees raw log files: it gets one
finding, its evidence lines and the tenant's known-activity notes, and must return JSON."""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import psycopg
import requests
from psycopg.types.json import Jsonb

from .config import Settings, Tenant

log = logging.getLogger(__name__)

SEVERITIES = ["info", "low", "medium", "high"]

TRIAGE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "severity", "confidence", "explanation", "recommended_actions"],
    "properties": {
        "verdict": {"type": "string", "enum": ["benign", "suspicious", "malicious", "operational", "unknown"]},
        "severity": {"type": "string", "enum": SEVERITIES},
        "confidence": {"type": "number"},
        "explanation": {"type": "string"},
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
    },
}

SUMMARY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["headline", "summary"],
    "properties": {"headline": {"type": "string"}, "summary": {"type": "string"}},
}

SYSTEM_TRIAGE = """You are a security and operations analyst reviewing audit findings from a \
Therefore Online document-management tenant. Deterministic rules raised each finding from the \
Therefore Server log. You may receive a single finding, or several findings that were grouped into \
one incident because they share the same user/IP and day (e.g. a new user plus a login-after-failures \
plus first admin-tool use, all in one session) - in that case give ONE overall verdict and severity \
that covers the whole incident, and write an explanation that ties the findings together rather than \
treating them separately. Your job: decide whether it is benign, suspicious, malicious, or an \
operational problem (misconfiguration, failing job), set a severity, and explain it in 2-4 plain \
sentences an administrator can act on. Be concrete: name the user/IP pseudonyms, counts and times \
you see. Do not invent facts that are not in the evidence. If the evidence is inconclusive say so \
and use verdict "unknown". Use the tenant's known-activity notes and past verdicts when relevant.

Log facts: timestamps are UTC. Result code 0 = success. "Connect" = a login by a client \
(API, Web Client, Console = admin console, Solution Designer = admin tool, eForms, Capture Client). \
Every REST API request is logged as its own Connect/Disconnect pair. "Server Start/Stop" are \
service restarts. Result codes 148/149/154 on Connect are token expiry/format problems.

Severity guide: high = likely compromise, data loss or outage; medium = needs a look this week; \
low = hygiene/ops; info = expected activity. Reply with JSON only."""

SYSTEM_SUMMARY = """You write the daily audit summary for a Therefore Online tenant administrator. \
Given the day's counts and triaged findings, write a one-line headline and a short summary \
(max ~120 words) covering what needs attention first. Plain language, no markdown headings. JSON only."""


class LLMError(RuntimeError):
    pass


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class OpenAICompatProvider:
    def __init__(self, base_url: str, api_key: str, model: str, timeout: int = 120):
        if not (base_url and model):
            raise LLMError("LLM_BASE_URL and LLM_MODEL must be set")
        self.base_url, self.api_key, self.model, self.timeout = base_url.rstrip("/"), api_key, model, timeout
        self.usage = Usage()

    def complete_json(self, system: str, user: str, schema: dict, name: str, max_tokens: int = 800) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if "openrouter.ai" in self.base_url:
            headers["X-Title"] = "therefore-log-auditor"
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": max_tokens,
            "temperature": 0.1,
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": name, "strict": True, "schema": schema}},
        }
        last_err: Exception | None = None
        for attempt in range(2):
            try:
                r = requests.post(f"{self.base_url}/chat/completions", headers=headers, json=body, timeout=self.timeout)
                if r.status_code == 400 and attempt == 0 and "response_format" in r.text:
                    body["response_format"] = {"type": "json_object"}   # endpoint without json_schema support
                    continue
                r.raise_for_status()
                data = r.json()
                u = data.get("usage") or {}
                self.usage.prompt_tokens += int(u.get("prompt_tokens") or 0)
                self.usage.completion_tokens += int(u.get("completion_tokens") or 0)
                content = data["choices"][0]["message"].get("content") or ""
                return _validate(_extract_json(content), schema)
            except Exception as exc:   # retry once, then give up (pipeline never blocks on the LLM)
                last_err = exc
        raise LLMError(str(last_err))


def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    return json.loads(text[start:end + 1])


def _validate(obj: dict, schema: dict) -> dict:
    for key in schema["required"]:
        if key not in obj:
            raise LLMError(f"missing key {key}")
    for key, spec in schema["properties"].items():
        if "enum" in spec and obj.get(key) not in spec["enum"]:
            raise LLMError(f"bad value for {key}: {obj.get(key)!r}")
    return {k: obj[k] for k in schema["properties"] if k in obj}


# --- Redaction ---------------------------------------------------------------------

@dataclass
class Redactor:
    """Stable pseudonyms for users, IPs and hosts, reversible after the LLM replies."""
    enabled: bool = True
    forward: dict[str, str] = field(default_factory=dict)

    def _alias(self, value: str, prefix: str) -> str:
        if not value:
            return value
        key = value.lower() if prefix == "user" else value
        if key not in self.forward:
            n = sum(1 for v in self.forward.values() if v.startswith(prefix + "_")) + 1
            self.forward[key] = f"{prefix}_{n}"
        return self.forward[key]

    def user(self, v: str | None) -> str | None:
        return self._alias(v, "user") if (self.enabled and v) else v

    def ip(self, v: str | None) -> str | None:
        return self._alias(v, "ip") if (self.enabled and v) else v

    def host(self, v: str | None) -> str | None:
        return self._alias(v, "host") if (self.enabled and v) else v

    def text(self, s: str | None) -> str | None:
        if not (self.enabled and s):
            return s
        for real, alias in sorted(self.forward.items(), key=lambda kv: -len(kv[0])):
            s = re.sub(rf"(?<![\w.@-]){re.escape(real)}(?![\w@-])", alias, s, flags=re.I)
        return s

    def restore(self, s: str) -> str:
        if not self.enabled:
            return s
        for real, alias in sorted(self.forward.items(), key=lambda kv: -len(kv[1])):
            s = re.sub(rf"\b{re.escape(alias)}\b", real, s)
        return s


def _redact_obj(obj: Any, rd: Redactor) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in ("user", "users", "username") and v:
                out[k] = [rd.user(x) for x in v] if isinstance(v, list) else rd.user(v)
            elif k in ("ip", "ips") and v:
                out[k] = [rd.ip(x) for x in v] if isinstance(v, list) else rd.ip(v)
            elif k == "host" and v:
                out[k] = rd.host(v)
            else:
                out[k] = _redact_obj(v, rd)
        return out
    if isinstance(obj, list):
        return [_redact_obj(x, rd) for x in obj]
    if isinstance(obj, str):
        return rd.text(obj)
    return obj


# --- Triage ------------------------------------------------------------------------

def _evidence(conn, tenant_id: str, ids: list[int], rd: Redactor, limit: int = 25) -> list[str]:
    if not ids:
        return []
    with conn.cursor() as cur:
        cur.execute("""SELECT ts, username, host, ip, action, result_code, obj_doc_no, category, client, message
                       FROM events WHERE tenant_id=%s AND id = ANY(%s) ORDER BY ts LIMIT %s""",
                    (tenant_id, ids, limit))
        rows = cur.fetchall()
    for r in rows:   # register aliases before redacting free text
        rd.user(r["username"]); rd.ip(r["ip"]); rd.host(r["host"])
    lines = []
    for r in rows:
        parts = [r["ts"].strftime("%Y-%m-%d %H:%M:%S"), rd.user(r["username"]) or "-",
                 rd.host(r["host"]) or "-", rd.ip(r["ip"]) or "-", r["action"], f"code={r['result_code']}"]
        if r["obj_doc_no"]:
            parts.append(f"doc={r['obj_doc_no']}")
        if r["category"]:
            parts.append(f"cat={r['category']}")
        if r["client"]:
            parts.append(f"client={r['client']}")
        if r["message"]:
            parts.append("msg=" + (rd.text(r["message"]) or "")[:240])
        lines.append(" | ".join(parts))
    return lines


def _past_verdicts(conn, tenant_id: str, rule_id: str, exclude_id: int, rd: Redactor) -> list[str]:
    with conn.cursor() as cur:
        cur.execute("""SELECT title, status, llm_verdict, suppressed_by FROM findings
                       WHERE tenant_id=%s AND rule_id=%s AND id<>%s
                         AND (llm_verdict IS NOT NULL OR status <> 'open')
                       ORDER BY last_ts DESC LIMIT 5""", (tenant_id, rule_id, exclude_id))
        return [f"{rd.text(r['title'])} -> verdict={r['llm_verdict']}, status={r['status']}"
                + (f", suppressed: {r['suppressed_by']}" if r["suppressed_by"] else "") for r in cur.fetchall()]


def triage(conn: psycopg.Connection, settings: Settings, tenant: Tenant, finding_ids: list[int],
           provider: OpenAICompatProvider | None = None, max_findings: int = 40) -> dict[str, int]:
    """Triage findings with the LLM. Findings sharing an `incident_key` (same primary user/IP,
    same day) are sent as one incident and get one shared verdict/severity/explanation - this is
    what lets e.g. a new-user + login-after-failures + first-admin-tool-use sequence for the same
    person be triaged as a single story instead of three disconnected findings.
    Never raises; failures leave rule severity in place."""
    stats = {"triaged": 0, "failed": 0, "skipped": 0}
    if not finding_ids or not tenant.llm.get("enabled", True):
        stats["skipped"] = len(finding_ids)
        return stats
    try:
        provider = provider or OpenAICompatProvider(settings.llm_base_url, settings.llm_api_key, settings.llm_model)
    except LLMError as exc:
        log.warning("LLM disabled: %s", exc)
        stats["skipped"] = len(finding_ids)
        return stats
    with conn.cursor() as cur:
        cur.execute("""SELECT * FROM findings WHERE id = ANY(%s) AND severity <> 'info'
                       ORDER BY array_position(ARRAY['high','medium','low','info'], severity), last_ts DESC""",
                    (finding_ids,))
        rows = cur.fetchall()[:max_findings]
    stats["skipped"] = len(finding_ids) - len(rows)
    known_notes = _known_notes(tenant)

    groups: dict[str, list[dict]] = {}
    for f in rows:
        groups.setdefault(f["incident_key"] or f"solo:{f['id']}", []).append(f)

    for members in groups.values():
        rd = Redactor(enabled=bool(tenant.llm.get("redact", True)))
        finding_payloads = []
        for f in members:
            finding_payloads.append({
                "rule": f["rule_id"], "title": rd.text(f["title"]), "rule_severity": f["rule_severity"],
                "first_utc": f["first_ts"].isoformat(), "last_utc": f["last_ts"].isoformat(),
                "details": _redact_obj(f["details"], rd),
                "evidence_lines": _evidence(conn, tenant.id, list(f["evidence_ids"] or []), rd),
            })
        payload = {
            "findings": finding_payloads,
            "known_activity_notes": [rd.text(n) for n in known_notes],
            "past_verdicts_same_rule": _past_verdicts(conn, tenant.id, members[0]["rule_id"], members[0]["id"], rd),
        }
        try:
            out = provider.complete_json(SYSTEM_TRIAGE, json.dumps(payload, default=str, indent=1),
                                         TRIAGE_SCHEMA, "triage")
        except LLMError as exc:
            log.warning("Triage failed for %d finding(s): %s", len(members), exc)
            stats["failed"] += len(members)
            continue
        conf = max(0.0, min(1.0, float(out.get("confidence") or 0)))
        explanation = rd.restore(out["explanation"])
        actions = Jsonb([rd.restore(a) for a in out.get("recommended_actions", [])])
        with conn.cursor() as cur:
            cur.execute("""UPDATE findings SET llm_verdict=%s, severity=%s, llm_confidence=%s,
                               llm_explanation=%s, llm_actions=%s, llm_model=%s, updated_at=now()
                           WHERE id = ANY(%s)""",
                        (out["verdict"], out["severity"], conf, explanation, actions,
                         provider.model, [f["id"] for f in members]))
        conn.commit()
        stats["triaged"] += len(members)
    stats["tokens"] = provider.usage.total
    return stats


def summarise(provider: OpenAICompatProvider, tenant: Tenant, day_stats: dict, findings: list[dict]) -> dict | None:
    rd = Redactor(enabled=bool(tenant.llm.get("redact", True)))
    items = [{"severity": f["severity"], "rule": f["rule_id"], "title": rd.text(f["title"]),
              "verdict": f.get("llm_verdict"), "explanation": rd.text(f.get("llm_explanation") or "")}
             for f in findings[:40]]
    try:
        out = provider.complete_json(SYSTEM_SUMMARY, json.dumps({"stats": day_stats, "findings": items}, default=str),
                                     SUMMARY_SCHEMA, "summary", max_tokens=400)
    except LLMError as exc:
        log.warning("Summary failed: %s", exc)
        return None
    return {"headline": rd.restore(out["headline"]), "summary": rd.restore(out["summary"])}


def _known_notes(tenant: Tenant) -> list[str]:
    k = tenant.known or {}
    notes = []
    if k.get("users"):
        notes.append("Expected accounts: " + ", ".join(k["users"]))
    if k.get("ips"):
        notes.append("Expected IPs: " + ", ".join(k["ips"]))
    for w in k.get("windows", []) or []:
        notes.append(f"Planned activity {w.get('start')} to {w.get('end')}: {w.get('note', '')}")
    for n in k.get("notes", []) or []:
        notes.append(str(n))
    return notes
