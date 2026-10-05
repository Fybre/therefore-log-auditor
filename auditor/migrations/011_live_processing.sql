ALTER TABLE live_state ADD COLUMN total_messages bigint NOT NULL DEFAULT 0;
ALTER TABLE live_state ADD COLUMN evaluated_messages bigint NOT NULL DEFAULT 0;
ALTER TABLE live_state ADD COLUMN last_received timestamptz;
ALTER TABLE live_state ADD COLUMN latest_event timestamptz;

UPDATE live_state s SET total_messages=a.total, evaluated_messages=a.evaluated,
    last_received=a.last_received, latest_event=a.latest_event
FROM (SELECT o.tenant_id,count(*) AS total,
             count(*) FILTER (WHERE o.id <= s.evaluated_id) AS evaluated,
             max(o.received_at) AS last_received, max(o.event_time) AS latest_event
      FROM live_observations o JOIN live_state s USING (tenant_id)
      GROUP BY o.tenant_id) a
WHERE s.tenant_id=a.tenant_id;

CREATE INDEX live_observations_key ON live_observations(tenant_id, endpoint, event_key, id DESC);
