-- Group related findings (same primary user/IP, same local day) into one incident so
-- they get one combined LLM triage and one digest entry instead of N separate ones.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS subject_users text[] NOT NULL DEFAULT '{}';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS subject_ips   text[] NOT NULL DEFAULT '{}';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS incident_key  text;

CREATE INDEX IF NOT EXISTS findings_tenant_incident ON findings (tenant_id, incident_key)
    WHERE incident_key IS NOT NULL;
