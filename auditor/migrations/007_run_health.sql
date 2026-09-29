-- Scheduler self-health check: `runs` already records every attempt, but nothing previously
-- noticed if a tenant's runs just stopped happening (container crash-looped, cron misconfigured,
-- credentials expired and every run has errored for days) - only the tenant's own Therefore log
-- staleness was covered by the log_gap rule, not the auditor's own scheduling. This table dedupes
-- alert emails so a persistent problem doesn't re-email every health-check tick.
CREATE TABLE IF NOT EXISTS run_health_alerts (
    tenant_id     text PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    reason        text NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_alert_at timestamptz NOT NULL DEFAULT now()
);
