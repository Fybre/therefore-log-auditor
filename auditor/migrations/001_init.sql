-- Therefore Log Auditor schema v1. Every table carries tenant_id.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     int PRIMARY KEY,
    applied_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS log_files (
    tenant_id       text        NOT NULL,
    doc_no          int         NOT NULL,
    application     text        NOT NULL,
    server          text,
    generated       date        NOT NULL,
    log_format      int,
    file_name       text,
    size_bytes      int,
    sha256          text,
    raw             bytea,          -- original file, kept for re-parsing / evidence
    first_ts        timestamptz,
    last_ts         timestamptz,
    line_count      int,
    parser_version  int,
    status          text        NOT NULL DEFAULT 'new',   -- new | parsed | error
    error           text,
    fetched_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, doc_no)
);

CREATE TABLE IF NOT EXISTS events (
    id           bigserial PRIMARY KEY,
    tenant_id    text        NOT NULL,
    doc_no       int         NOT NULL,
    line_no      int         NOT NULL,
    source       text        NOT NULL,     -- server | migrate | content_connector
    ts           timestamptz NOT NULL,
    username     text,
    host         text,
    ip           text,
    action       text        NOT NULL,
    result_code  int,
    success      boolean,
    obj_doc_no   int,
    obj_version  int,
    category     text,
    wf_instance  text,
    wf_name      text,
    client       text,                     -- e.g. "API", "Console", "Solution Designer"
    client_ver   text,
    message      text,
    UNIQUE (tenant_id, doc_no, line_no)
);
CREATE INDEX IF NOT EXISTS events_tenant_ts   ON events (tenant_id, ts);
CREATE INDEX IF NOT EXISTS events_tenant_user ON events (tenant_id, username, ts);
CREATE INDEX IF NOT EXISTS events_tenant_ip   ON events (tenant_id, ip, ts);
CREATE INDEX IF NOT EXISTS events_tenant_act  ON events (tenant_id, action, ts);

CREATE TABLE IF NOT EXISTS findings (
    id               bigserial PRIMARY KEY,
    tenant_id        text        NOT NULL,
    rule_id          text        NOT NULL,
    dedupe_key       text        NOT NULL,
    title            text        NOT NULL,
    rule_severity    text        NOT NULL,     -- info | low | medium | high
    severity         text        NOT NULL,     -- after suppressions / LLM
    status           text        NOT NULL DEFAULT 'open',
    first_ts         timestamptz NOT NULL,
    last_ts          timestamptz NOT NULL,
    details          jsonb       NOT NULL DEFAULT '{}',
    evidence_ids     bigint[]    NOT NULL DEFAULT '{}',
    suppressed_by    text,
    llm_verdict      text,
    llm_confidence   real,
    llm_explanation  text,
    llm_actions      jsonb,
    llm_model        text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, rule_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS findings_tenant_ts ON findings (tenant_id, last_ts);

CREATE TABLE IF NOT EXISTS settings_snapshots (
    id          bigserial PRIMARY KEY,
    tenant_id   text        NOT NULL,
    taken_at    timestamptz NOT NULL DEFAULT now(),
    settings    jsonb       NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id          bigserial PRIMARY KEY,
    tenant_id   text        NOT NULL,
    kind        text        NOT NULL,      -- daily | backfill | manual
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    files       int  DEFAULT 0,
    events      int  DEFAULT 0,
    findings    int  DEFAULT 0,
    llm_tokens  int  DEFAULT 0,
    error       text
);
