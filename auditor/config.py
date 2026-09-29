"""Configuration: tenants/servers, per-tenant rule toggles and SMTP delivery live in the database
(tables `tenants`, `tenant_rule_settings`, `app_settings`) and are managed from the dashboard -
see auditor/web/app.py's /admin/* routes. Only what has to exist before the database does -
DATABASE_URL, the LLM connection, AUDITOR_ENC_KEY - stays in the environment/.env. The rule
*defaults* (thresholds) still come from config/rules.yaml; tenants only override them."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psycopg
import yaml
from psycopg.types.json import Jsonb

from . import crypto

ROOT = Path(__file__).resolve().parents[1]


def load_dotenv(path: Path | None = None) -> None:
    """Minimal .env loader (no dependency). Existing environment variables win."""
    path = path or Path(os.environ.get("AUDITOR_ENV_FILE", ROOT / ".env"))
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


@dataclass
class Tenant:
    id: str
    base_url: str
    username: str = ""
    password: str = ""
    tenant_name_override: str | None = None
    log_category_no: int = 1
    log_tz: str = "UTC"
    display_tz: str = "UTC"
    schedule: dict[str, str] = field(default_factory=lambda: {"daily": "30 3 * * *"})
    llm: dict[str, Any] = field(default_factory=lambda: {"enabled": True, "redact": True})
    digest: dict[str, Any] = field(default_factory=dict)
    known: dict[str, Any] = field(default_factory=dict)
    rules: dict[str, Any] = field(default_factory=dict)   # per-tenant rule overrides
    enabled: bool = True

    @property
    def tenant_name(self) -> str | None:
        if self.tenant_name_override:
            return self.tenant_name_override
        host = re.sub(r"^https?://", "", self.base_url).split("/")[0].lower()
        if host.endswith(".thereforeonline.com"):
            return host.split(".")[0]
        return None


@dataclass
class Settings:
    database_url: str
    tenants: list[Tenant]
    rules: dict[str, Any]
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    smtp: dict[str, Any]
    reports_dir: Path
    dashboard_url: str = ""   # e.g. https://audit.example.com - used to link back from digest emails
    alert_email_to: list[str] = field(default_factory=list)   # scheduler self-health alerts, see health.py

    def tenant(self, tenant_id: str) -> Tenant:
        for t in self.tenants:
            if t.id == tenant_id:
                return t
        raise KeyError(f"Unknown tenant '{tenant_id}'. Configured: {[t.id for t in self.tenants]}")

    def rule_config(self, tenant: Tenant, rule_id: str) -> dict[str, Any]:
        merged = dict(self.rules.get(rule_id, {}))
        merged.update(tenant.rules.get(rule_id, {}))
        return merged


def load_settings() -> Settings:
    """Env/file-only settings. Does NOT touch the tenants/app_settings tables (they may not
    exist yet, e.g. before the first migration) - call refresh_from_db() once a connection is
    available."""
    load_dotenv()
    rules_path = Path(os.environ.get("AUDITOR_RULES_FILE", ROOT / "config" / "rules.yaml"))
    rules_raw = yaml.safe_load(rules_path.read_text()) if rules_path.exists() else {}
    return Settings(
        database_url=os.environ.get("DATABASE_URL", "postgresql://auditor:auditor@localhost:5432/auditor"),
        tenants=[],
        rules=(rules_raw or {}).get("rules", {}),
        llm_base_url=os.environ.get("LLM_BASE_URL", "").rstrip("/"),
        llm_api_key=os.environ.get("LLM_API_KEY", ""),
        llm_model=os.environ.get("LLM_MODEL", ""),
        smtp={"host": "", "port": 587, "user": "", "password": "", "from": "", "starttls": True},
        reports_dir=Path(os.environ.get("AUDITOR_REPORTS_DIR", ROOT / "reports")),
    )


def refresh_from_db(settings: Settings, conn: psycopg.Connection) -> None:
    """Reload tenants + SMTP + general config from the database into an existing Settings in
    place, so callers that already handed the object to a scheduler/pipeline see the update."""
    settings.tenants = load_tenants(conn)
    settings.smtp = load_smtp(conn) or settings.smtp
    general = load_general(conn)
    settings.dashboard_url = general.get("dashboard_url", "") or settings.dashboard_url
    settings.alert_email_to = general.get("alert_email_to") or settings.alert_email_to


# --- Tenants -----------------------------------------------------------------------------

def _row_to_tenant(conn: psycopg.Connection, r: dict) -> Tenant:
    with conn.cursor() as cur:
        cur.execute("SELECT rule_id, enabled, config FROM tenant_rule_settings WHERE tenant_id=%s",
                    (r["id"],))
        rules = {}
        for row in cur.fetchall():
            override: dict[str, Any] = dict(row["config"] or {})
            if row["enabled"] is not None:
                override["enabled"] = row["enabled"]
            if override:
                rules[row["rule_id"]] = override
    return Tenant(
        id=r["id"], base_url=r["base_url"],
        username=r["therefore_username"],
        password=crypto.decrypt(r["therefore_password_enc"]),
        tenant_name_override=r["tenant_name_override"],
        log_category_no=r["log_category_no"], log_tz=r["log_tz"], display_tz=r["display_tz"],
        schedule={"daily": r["schedule_cron"]},
        llm={"enabled": r["llm_enabled"], "redact": r["llm_redact"]},
        digest={"email_to": list(r["digest_email_to"] or []), "only_on_new": r["digest_only_on_new"]},
        known=r["known"] or {},
        rules=rules,
        enabled=r["enabled"],
    )


def load_tenants(conn: psycopg.Connection, include_disabled: bool = False) -> list[Tenant]:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM tenants" + ("" if include_disabled else " WHERE enabled")
                     + " ORDER BY id")
        rows = cur.fetchall()
    return [_row_to_tenant(conn, r) for r in rows]


def get_tenant_row(conn: psycopg.Connection, tenant_id: str) -> dict | None:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM tenants WHERE id=%s", (tenant_id,))
        return cur.fetchone()


def get_tenant(conn: psycopg.Connection, tenant_id: str) -> Tenant | None:
    row = get_tenant_row(conn, tenant_id)
    return _row_to_tenant(conn, row) if row else None


def save_tenant(conn: psycopg.Connection, *, id: str, base_url: str, username: str,
                 password: str | None, tenant_name_override: str | None, log_category_no: int,
                 log_tz: str, display_tz: str, schedule_cron: str, llm_enabled: bool,
                 llm_redact: bool, digest_email_to: list[str], digest_only_on_new: bool,
                 known: dict, enabled: bool) -> None:
    """Create or update a tenant. `password=None` keeps the existing encrypted password
    (used when editing a tenant without re-entering its Therefore login)."""
    with conn.cursor() as cur:
        if password is None:
            cur.execute(
                """UPDATE tenants SET base_url=%s, therefore_username=%s, tenant_name_override=%s,
                       log_category_no=%s, log_tz=%s, display_tz=%s, schedule_cron=%s,
                       llm_enabled=%s, llm_redact=%s, digest_email_to=%s, digest_only_on_new=%s,
                       known=%s, enabled=%s, updated_at=now()
                   WHERE id=%s""",
                (base_url, username, tenant_name_override, log_category_no, log_tz, display_tz,
                 schedule_cron, llm_enabled, llm_redact, digest_email_to, digest_only_on_new,
                 Jsonb(known), enabled, id))
            if cur.rowcount == 0:
                raise KeyError(f"Unknown tenant '{id}' (password required to create a new tenant)")
        else:
            password_enc = crypto.encrypt(password)
            cur.execute(
                """INSERT INTO tenants (id, base_url, therefore_username, therefore_password_enc,
                       tenant_name_override, log_category_no, log_tz, display_tz, schedule_cron,
                       llm_enabled, llm_redact, digest_email_to, digest_only_on_new, known, enabled)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (id) DO UPDATE SET
                       base_url=EXCLUDED.base_url, therefore_username=EXCLUDED.therefore_username,
                       therefore_password_enc=EXCLUDED.therefore_password_enc,
                       tenant_name_override=EXCLUDED.tenant_name_override,
                       log_category_no=EXCLUDED.log_category_no, log_tz=EXCLUDED.log_tz,
                       display_tz=EXCLUDED.display_tz, schedule_cron=EXCLUDED.schedule_cron,
                       llm_enabled=EXCLUDED.llm_enabled, llm_redact=EXCLUDED.llm_redact,
                       digest_email_to=EXCLUDED.digest_email_to,
                       digest_only_on_new=EXCLUDED.digest_only_on_new, known=EXCLUDED.known,
                       enabled=EXCLUDED.enabled, updated_at=now()""",
                (id, base_url, username, password_enc, tenant_name_override, log_category_no,
                 log_tz, display_tz, schedule_cron, llm_enabled, llm_redact, digest_email_to,
                 digest_only_on_new, Jsonb(known), enabled))
    conn.commit()


def delete_tenant(conn: psycopg.Connection, tenant_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute("DELETE FROM tenants WHERE id=%s", (tenant_id,))
    conn.commit()


# --- Per-tenant rule settings --------------------------------------------------------------

def rule_settings_for(conn: psycopg.Connection, tenant_id: str) -> dict[str, dict]:
    with conn.cursor() as cur:
        cur.execute("SELECT rule_id, enabled, config FROM tenant_rule_settings WHERE tenant_id=%s",
                    (tenant_id,))
        return {r["rule_id"]: {"enabled": r["enabled"], "config": r["config"] or {}}
                for r in cur.fetchall()}


def set_rule_setting(conn: psycopg.Connection, tenant_id: str, rule_id: str,
                      enabled: bool | None, config: dict) -> None:
    """enabled=None and an empty config means 'inherit the global default' - remove any
    existing override row rather than storing a no-op one."""
    with conn.cursor() as cur:
        if enabled is None and not config:
            cur.execute("DELETE FROM tenant_rule_settings WHERE tenant_id=%s AND rule_id=%s",
                        (tenant_id, rule_id))
        else:
            cur.execute(
                """INSERT INTO tenant_rule_settings (tenant_id, rule_id, enabled, config)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (tenant_id, rule_id) DO UPDATE SET enabled=EXCLUDED.enabled,
                       config=EXCLUDED.config""",
                (tenant_id, rule_id, enabled, Jsonb(config)))
    conn.commit()


# --- App-wide settings (SMTP) ---------------------------------------------------------------

def load_smtp(conn: psycopg.Connection) -> dict | None:
    with conn.cursor() as cur:
        cur.execute("SELECT value FROM app_settings WHERE key='smtp'")
        row = cur.fetchone()
    if not row:
        return None
    smtp = dict(row["value"])
    smtp["password"] = crypto.decrypt(smtp.get("password_enc", "")) if smtp.get("password_enc") else ""
    return smtp


def save_smtp(conn: psycopg.Connection, *, host: str, port: int, user: str,
              password: str | None, from_addr: str, starttls: bool) -> None:
    existing = load_smtp(conn) or {}
    password_enc = crypto.encrypt(password) if password is not None else existing.get("password_enc", "")
    if password is not None and not password:
        password_enc = ""
    value = {"host": host, "port": port, "user": user, "password_enc": password_enc,
             "from": from_addr, "starttls": starttls}
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO app_settings (key, value) VALUES ('smtp', %s)
               ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value""", (Jsonb(value),))
    conn.commit()


# --- App-wide settings (general) ------------------------------------------------------------

def load_general(conn: psycopg.Connection) -> dict:
    with conn.cursor() as cur:
        cur.execute("SELECT value FROM app_settings WHERE key='general'")
        row = cur.fetchone()
    return dict(row["value"]) if row else {"dashboard_url": "", "alert_email_to": []}


def save_general(conn: psycopg.Connection, *, dashboard_url: str, alert_email_to: list[str] | None = None) -> None:
    value = {"dashboard_url": dashboard_url.strip().rstrip("/"),
             "alert_email_to": alert_email_to or []}
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO app_settings (key, value) VALUES ('general', %s)
               ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value""", (Jsonb(value),))
    conn.commit()
