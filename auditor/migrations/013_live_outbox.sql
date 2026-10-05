ALTER TABLE live_settings ADD COLUMN alerting_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE live_settings ADD COLUMN alert_recipients text NOT NULL DEFAULT '';
ALTER TABLE live_settings ADD COLUMN alerting_enabled_at timestamptz;

ALTER TABLE live_findings ADD COLUMN last_alert_ts timestamptz;
ALTER TABLE live_findings ADD COLUMN last_alert_count int;
ALTER TABLE live_findings ADD COLUMN last_alert_severity text;
ALTER TABLE live_findings ADD COLUMN alert_count int NOT NULL DEFAULT 0;

CREATE TABLE live_outbox (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id bigint REFERENCES live_findings(id) ON DELETE CASCADE,
    alert_type text NOT NULL CHECK (alert_type IN ('initial', 'escalation', 'test')),
    severity text NOT NULL,
    recipients text[] NOT NULL,
    subject text NOT NULL,
    body_text text NOT NULL,
    body_html text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'cancelled')),
    attempts int NOT NULL DEFAULT 0,
    max_attempts int NOT NULL DEFAULT 5,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz,
    last_attempt_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX live_outbox_queue ON live_outbox(status, next_attempt_at) WHERE status IN ('pending', 'failed');
CREATE INDEX live_outbox_finding ON live_outbox(finding_id);
CREATE INDEX live_outbox_tenant ON live_outbox(tenant_id, created_at DESC);
