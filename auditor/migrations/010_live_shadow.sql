-- Live evidence is intentionally separate from archived events and daily notifications.
CREATE TABLE live_settings (
    tenant_id text PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT false,
    retrieval_limit int NOT NULL DEFAULT 100 CHECK (retrieval_limit > 0),
    api_limit int NOT NULL DEFAULT 500 CHECK (api_limit > 0)
);
CREATE TABLE live_state (
    tenant_id text PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    endpoint text NOT NULL,
    cursor bigint NOT NULL DEFAULT 0,
    evaluated_id bigint NOT NULL DEFAULT 0,
    last_poll timestamptz,
    last_evaluation timestamptz,
    last_error text,
    gap_since timestamptz,
    resets int NOT NULL DEFAULT 0
);
CREATE TABLE live_observations (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    endpoint text NOT NULL,
    fingerprint text NOT NULL,
    event_key bigint NOT NULL,
    payload jsonb NOT NULL,
    activity jsonb NOT NULL,
    event_time timestamptz,
    received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, endpoint, fingerprint)
);
CREATE INDEX live_observations_time ON live_observations(tenant_id, event_time);
CREATE INDEX live_observations_progress ON live_observations(tenant_id, id);
CREATE TABLE live_approvals (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name text NOT NULL,
    username text NOT NULL,
    network text NOT NULL,
    kind text NOT NULL CHECK(kind IN ('retrieval', 'api_activity')),
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL CHECK (ends_at > starts_at),
    max_count int NOT NULL CHECK (max_count > 0),
    reason text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE TABLE live_findings (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id text NOT NULL,
    subject text NOT NULL,
    first_ts timestamptz NOT NULL,
    last_ts timestamptz NOT NULL,
    expected boolean NOT NULL DEFAULT false,
    approval_id bigint REFERENCES live_approvals(id),
    details jsonb NOT NULL,
    evidence_ids bigint[] NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX live_findings_episode ON live_findings(tenant_id, rule_id, subject, last_ts);
