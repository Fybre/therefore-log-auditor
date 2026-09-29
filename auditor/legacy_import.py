"""One-time import of the old file/env-based config (config/tenants.yaml,
THEREFORE_<ID>_USERNAME/PASSWORD, SMTP_* in .env) into the database, run via
`auditor import-legacy-config`. Safe to re-run: existing rows are left alone unless --overwrite
semantics are added later; for now it skips tenants that already exist in the database."""
from __future__ import annotations

import os
import re
from pathlib import Path

import psycopg
import yaml

from . import config

ROOT = Path(__file__).resolve().parents[1]


def _env_key(tenant_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", tenant_id).upper()


def import_legacy_config(conn: psycopg.Connection) -> dict:
    report: dict = {"tenants_imported": [], "tenants_skipped_existing": [], "smtp_imported": False}

    tenants_path = Path(os.environ.get("AUDITOR_TENANTS_FILE", ROOT / "config" / "tenants.yaml"))
    if tenants_path.exists():
        raw = yaml.safe_load(tenants_path.read_text()) or {}
        for t in raw.get("tenants", []):
            tid = t["id"]
            if config.get_tenant_row(conn, tid):
                report["tenants_skipped_existing"].append(tid)
                continue
            key = _env_key(tid)
            config.save_tenant(
                conn, id=tid, base_url=t["base_url"],
                username=os.environ.get(f"THEREFORE_{key}_USERNAME", ""),
                password=os.environ.get(f"THEREFORE_{key}_PASSWORD", ""),
                tenant_name_override=os.environ.get(f"THEREFORE_{key}_TENANTNAME"),
                log_category_no=t.get("log_category_no", 1), log_tz=t.get("log_tz", "UTC"),
                display_tz=t.get("display_tz", "UTC"),
                schedule_cron=(t.get("schedule") or {}).get("daily", "30 3 * * *"),
                llm_enabled=(t.get("llm") or {}).get("enabled", True),
                llm_redact=(t.get("llm") or {}).get("redact", True),
                digest_email_to=(t.get("digest") or {}).get("email_to", []) or [],
                digest_only_on_new=(t.get("digest") or {}).get("only_on_new", False),
                known=t.get("known", {}) or {}, enabled=True,
            )
            for rule_id, override in (t.get("rules") or {}).items():
                override = dict(override)
                enabled = override.pop("enabled", None)
                config.set_rule_setting(conn, tid, rule_id, enabled, override)
            report["tenants_imported"].append(tid)

    if os.environ.get("SMTP_HOST") and not config.load_smtp(conn):
        config.save_smtp(conn, host=os.environ.get("SMTP_HOST", ""),
                          port=int(os.environ.get("SMTP_PORT", "587") or 587),
                          user=os.environ.get("SMTP_USER", ""),
                          password=os.environ.get("SMTP_PASSWORD", ""),
                          from_addr=os.environ.get("SMTP_FROM", ""),
                          starttls=os.environ.get("SMTP_STARTTLS", "true").lower() != "false")
        report["smtp_imported"] = True

    return report
