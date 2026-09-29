-- Admin audit trail: this app audits *tenants'* Therefore activity, but nothing previously
-- recorded changes made *to the auditor itself* - who added a service account, changed SMTP
-- creds, toggled a rule, or deleted a tenant. detail is freeform JSON and must never contain
-- secrets (passwords/API keys) - only field names/non-secret values, same discipline as the
-- findings LLM redaction already applies elsewhere in this app.
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id        bigserial PRIMARY KEY,
    at        timestamptz NOT NULL DEFAULT now(),
    actor     text NOT NULL,
    action    text NOT NULL,
    tenant_id text,
    detail    jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS admin_audit_log_at ON admin_audit_log (at DESC);
