"""Configuration: tenants from YAML, secrets and service settings from the environment."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

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


def _env_key(tenant_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", tenant_id).upper()


@dataclass
class Tenant:
    id: str
    base_url: str
    log_category_no: int = 1
    log_tz: str = "UTC"
    display_tz: str = "UTC"
    schedule: dict[str, str] = field(default_factory=lambda: {"daily": "30 3 * * *"})
    llm: dict[str, Any] = field(default_factory=lambda: {"enabled": True, "redact": True})
    digest: dict[str, Any] = field(default_factory=dict)
    known: dict[str, Any] = field(default_factory=dict)
    rules: dict[str, Any] = field(default_factory=dict)   # per-tenant rule overrides

    @property
    def username(self) -> str:
        return os.environ.get(f"THEREFORE_{_env_key(self.id)}_USERNAME", "")

    @property
    def password(self) -> str:
        return os.environ.get(f"THEREFORE_{_env_key(self.id)}_PASSWORD", "")

    @property
    def tenant_name(self) -> str | None:
        explicit = os.environ.get(f"THEREFORE_{_env_key(self.id)}_TENANTNAME")
        if explicit:
            return explicit
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
    load_dotenv()
    tenants_path = Path(os.environ.get("AUDITOR_TENANTS_FILE", ROOT / "config" / "tenants.yaml"))
    rules_path = Path(os.environ.get("AUDITOR_RULES_FILE", ROOT / "config" / "rules.yaml"))
    tenants_raw = yaml.safe_load(tenants_path.read_text()) if tenants_path.exists() else {}
    rules_raw = yaml.safe_load(rules_path.read_text()) if rules_path.exists() else {}
    tenants = [Tenant(**t) for t in (tenants_raw or {}).get("tenants", [])]
    return Settings(
        database_url=os.environ.get("DATABASE_URL", "postgresql://auditor:auditor@localhost:5432/auditor"),
        tenants=tenants,
        rules=(rules_raw or {}).get("rules", {}),
        llm_base_url=os.environ.get("LLM_BASE_URL", "").rstrip("/"),
        llm_api_key=os.environ.get("LLM_API_KEY", ""),
        llm_model=os.environ.get("LLM_MODEL", ""),
        smtp={
            "host": os.environ.get("SMTP_HOST", ""),
            "port": int(os.environ.get("SMTP_PORT", "587") or 587),
            "user": os.environ.get("SMTP_USER", ""),
            "password": os.environ.get("SMTP_PASSWORD", ""),
            "from": os.environ.get("SMTP_FROM", ""),
            "starttls": os.environ.get("SMTP_STARTTLS", "true").lower() != "false",
        },
        reports_dir=Path(os.environ.get("AUDITOR_REPORTS_DIR", ROOT / "reports")),
    )
