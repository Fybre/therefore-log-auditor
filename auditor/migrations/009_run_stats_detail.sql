-- Persist the finer-grained run stats (previously only held in the in-memory `stats` dict
-- returned by run_tenant()) so a poll of the `runs` row after the fact can reconstruct the
-- same result page an inline/synchronous response used to show. Needed for "Run now" to poll
-- for completion instead of holding the HTTP request open for the run's whole duration - long
-- runs were timing out through reverse proxies (e.g. a Cloudflare Tunnel's ~100s limit).
ALTER TABLE runs ADD COLUMN IF NOT EXISTS findings_changed int;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS llm_triaged int;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS llm_failed int;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS llm_skipped int;
