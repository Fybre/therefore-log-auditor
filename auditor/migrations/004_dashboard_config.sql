-- Move tenant/server config, per-tenant rule toggles, SMTP delivery, and dashboard logins out of
-- config/tenants.yaml + .env and into the database, so they're manageable from the dashboard.

CREATE TABLE IF NOT EXISTS web_users (
    id            bigserial PRIMARY KEY,
    username      text UNIQUE NOT NULL,
    password_hash text NOT NULL,
    disabled      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenants (
    id                      text PRIMARY KEY,
    base_url                text NOT NULL,
    therefore_username      text NOT NULL DEFAULT '',
    therefore_password_enc  text NOT NULL DEFAULT '',    -- Fernet-encrypted, see auditor/crypto.py
    tenant_name_override    text,                        -- TenantName header, if not derivable from base_url
    log_category_no         int NOT NULL DEFAULT 1,
    log_tz                  text NOT NULL DEFAULT 'UTC',
    display_tz              text NOT NULL DEFAULT 'UTC',
    schedule_cron           text NOT NULL DEFAULT '30 3 * * *',
    llm_enabled             boolean NOT NULL DEFAULT true,
    llm_redact              boolean NOT NULL DEFAULT true,
    digest_email_to         text[] NOT NULL DEFAULT '{}',
    known                   jsonb NOT NULL DEFAULT '{}',  -- users/ips/windows/notes
    enabled                 boolean NOT NULL DEFAULT true,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now()
);

-- Per-tenant rule toggle/threshold overrides. enabled=NULL means "inherit the global default
-- from config/rules.yaml" - a row only needs to exist when a tenant overrides something.
CREATE TABLE IF NOT EXISTS tenant_rule_settings (
    tenant_id  text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id    text NOT NULL,
    enabled    boolean,
    config     jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, rule_id)
);

-- Small global settings store (currently just 'smtp'); one JSON blob per key.
CREATE TABLE IF NOT EXISTS app_settings (
    key   text PRIMARY KEY,
    value jsonb NOT NULL
);
