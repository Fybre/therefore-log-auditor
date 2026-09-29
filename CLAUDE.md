# CLAUDE.md — Therefore Log Auditor

Context for continuing this project in Claude Code. It records the project's purpose, what has
been built, what was learned about Therefore logging, and what is still to do.
Last updated: 29 Sep 2026 (end of the first working session).

## Purpose

A **multi-tenant auditing/monitoring service for Therefore Online** (Canon's document management
SaaS). It reads each tenant's server logs from the Therefore `Logfiles` category and looks for
**operational problems and security issues**. **Deterministic rules** find the issues, and an
**LLM** triages, explains and summarises them. Results go to a web dashboard (Phase 2),
email/Teams alerts, and a daily report (also to be saved back into Therefore in Phase 2).

Decisions made with Craig:
- **Multi-tenant service** (craigdemo, Sumitomo, customer tenants) from one deployment.
- **Runs in Docker** (docker compose: Postgres + a Python scheduler container).
- **Pluggable LLM** via any **OpenAI-compatible** endpoint. The current choice is **OpenRouter** with
  model **`openai/gpt-6-luna`** (cheap: about 13K tokens per daily run, a fraction of a cent).
- **Outputs:** web dashboard + email/Teams alerts + report doc in Therefore (all three wanted).
- **Rules first, LLM second.** The LLM never reads raw logs, only individual findings with their
  evidence lines. Users/IPs/hosts are pseudonymised before sending.

Architecture design doc (Claude Doc, kept up to date during the session):
https://claude.ai/code/artifact/c5ac517e-8f0c-4648-9df8-4e84bf3acd39

## Status

**Phase 1 (MVP) is built, tested against craigdemo, and committed locally** (`main`, one commit,
no GitHub remote yet).

Verified in the cloud dev environment (Python 3.11 + Postgres 16):
- Parser: 267,020 events from 507 historical log files (Sep 2023 – Sep 2026), **0 unparsed lines**.
- Rules over the full history run in about 5s and found every incident identified by hand:
  - Oct 2025: licence document limit hit (7,706 Doc New failures), a retry storm of about 200k
    failed retrievals of deleted docs, and a mass delete of 4,682 documents
  - 20 Aug 2026: mass delete of 3,303 documents
  - The RefWSTableSync server task failing with HTTP 403 every night
  - 28–29 Sep 2026: `cameron.lamond` from 77.98.171.55. Three failed logins, then Console,
    Solution Designer and API access, then five server restarts. **Craig confirmed this was
    legitimate testing for another issue.** It is now a known-activity window in
    `config/tenants.yaml`.
- LLM triage and the daily digest worked end to end through OpenRouter. Explanations were
  specific and accurate.
- `pytest`: 7 tests pass (parsers, redaction/validation, and a DB integration test with a
  synthetic attack; that test needs `TEST_DATABASE_URL`).
- **Not yet verified:** building the Docker image (Docker Hub rate-limited the dev environment).
  The first `docker compose up --build` on the Mac is its first real test.

## Run it

```bash
docker compose up -d --build                                                    # Postgres + scheduler
docker compose run --rm auditor backfill --tenant craigdemo --since 2023-09-01   # load history, rules only
docker compose run --rm auditor run --tenant craigdemo                          # full daily run now
docker compose run --rm auditor findings --tenant craigdemo --days 30 --min-severity medium
open reports/craigdemo/                                                          # HTML/MD digests
```
Local dev without Docker: `pip install -e '.[dev]'`, set `DATABASE_URL`, then `auditor migrate`
and the same commands. Postgres from compose is exposed on `127.0.0.1:5433` (user/db `auditor`).

Config:
- `.env` (gitignored). It holds `LLM_BASE_URL`, `LLM_API_KEY` (OpenRouter key, $250 limit),
  `LLM_MODEL`, `THEREFORE_CRAIGDEMO_USERNAME/PASSWORD` (currently Craig's own login; **replace with
  a dedicated read-only service account**) and optional `SMTP_*` (empty, so no email is sent yet).
  `DATABASE_URL` is set by compose.
- `config/tenants.yaml` (gitignored; copy from `tenants.example.yaml`) has per-tenant `base_url`,
  `log_category_no`, `log_tz`, `display_tz`, schedule cron (in display_tz, default `30 3 * * *`),
  `llm.enabled/redact`, `digest.email_to`, and `known.users/ips/windows/notes`.
- `config/rules.yaml` holds the rule thresholds (per-tenant overrides go under `rules:` in
  tenants.yaml).

## Code map

```
auditor/
  config.py      .env loader, Tenant/Settings dataclasses, per-tenant creds via THEREFORE_<ID>_*
  db.py          psycopg3 connect + numbered SQL migrations (auditor/migrations/NNN_*.sql)
  therefore.py   REST client: Logfiles listing (month windows), GetDocumentStream, GetSettings
  parsers.py     LogFormat 4 (Server, 11 pipe columns) + 5/6 (Migrate / Content Connector free text)
  collector.py   discover -> fetch -> parse -> store (idempotent by DocNo, raw file kept); settings snapshot
  rules/engine.py   Context, Finding, rule registry, suppressions, upsert by (tenant, rule, dedupe_key)
  rules/builtin.py  10 rules (below)
  llm.py         OpenAICompatProvider (json_schema strict, falls back to json_object), Redactor, triage, summary
  digest.py      gather/render HTML + Markdown, write reports/<tenant>/, SMTP send
  pipeline.py    run_tenant(): collect -> snapshot -> rules (UTC-midnight-aligned window) -> triage -> digest
  scheduler.py   APScheduler: daily cron per tenant + hourly catch-up (6h) until the day's log arrives
  cli.py         auditor migrate | run | backfill | serve | findings
```
DB tables: `log_files`, `events`, `findings`, `settings_snapshots`, `runs`, `schema_migrations`.

Rules: `brute_force` (per-user sliding window + password spray per IP), `success_after_failures`,
`new_entity` (new user / new public IP / first admin-tool use via Console or Solution Designer; 14-day
warm-up; service principals ignored; new IPs are `low`), `mass_delete` (≥200/day or 5x the 30-day
baseline), `unplanned_restart` (≥3 in 60 min), `log_gap` (no Server log for 48h, realtime only),
`config_drift` (settings keys 700–704 changed), `recurring_failure` (same failure on ≥3 of 7 days),
`retry_storm` (≥1000 identical failures/day), `licence_limit`.

Behaviours worth knowing:
- Findings are upserted. `updated_at` only changes when `details` change, and the digest shows
  findings updated during the run. A detail change clears `llm_verdict`, so the finding is re-triaged.
- Suppressions (`known.*`) downgrade to `info` and record `suppressed_by`. They never delete.
  The auditor does **not** auto-suppress its own account (this was removed on purpose: during dev
  the auditor ran as craig.mewett, which hid his own mass deletes). Put the service account in
  `known.users` instead.
- Triage runs on findings that changed, plus any untriaged non-info findings in the window
  (max 40 per run). If the LLM fails, the finding keeps its rule severity.

## What was learned about Therefore logging (verified on craigdemo, Web API 35.0.3)

- Logs are archived to the **`Logfiles` category (CategoryNo 1)**. Fields: `APPLICATION`, `SERVER`
  (alternates between AD\aueapp00 and aueapp01), `GENERATED` (a UTC date), `LogFormat`
  (4 = Server, 5 = Migrate, 6 = Content Connector). `Logfiles2` (324) is empty.
- **Archiving is set per tenant** in Solution Designer > Settings > Server Logging > Archive:
  Every day / weekday / monthly / by size, plus a time. craigdemo uses **Every day at 17:00 server
  time = UTC (03:00 AEST)**. Files land at about 17:01–17:18 UTC. Migrate and Content Connector
  logs arrive **weekly** (Sunday about 00:00 UTC). The live log can't be read through the API;
  each rotation creates a new version-1 document that is never updated. The Size field only
  applies when archiving by size (it's when a new file starts, not a total cap).
- A **query with no conditions silently stops at 500 rows.** Query by date range:
  `{"FieldNoOrName":"GENERATED","Condition":">= 2026-09-01 AND < 2026-10-01"}`.
- Files are UTF-8 with a BOM and CRLF line endings, with a 6-line header. Some headers are
  double-encoded ("Thereforeâ„¢"). Result code 0 means success, and failures have messages
  starting with `failed:`. Timestamps in the logs are treated as UTC.
- **Default logging records mostly failures.** Deletes, retention deletes, server start/stop and
  collaboration events are "Always". Craig has since set these to Always: New, Retrieve, Change,
  Change index data, Print, Export/Send, Delete, Connect/Disconnect, and admin events. The new
  settings added successful `Connect` (with client type: API, Console, Solution Designer, Content
  Connector, Web Client…), `Disconnect`, successful `Doc Retrieve` and `Change Category`.
  **Every REST call with Basic auth logs its own Connect + Disconnect pair**, including the
  auditor's. The token from `GetConnectionToken` is 12 characters, not a JWT, and returns 401 as
  a Bearer token, so the auditor uses Basic auth and keeps its calls to a handful per run.
- **Settings are readable via `GetSettings`** (integer keys, undocumented):
  700 = LogMask XML (52 positional values: 0 do not log, 1 failure, 3 always; 2 = success is
  presumed), 701 archive mode (1 = daily), 702 weekday, 703 archive time in minutes after
  midnight UTC (1020), 704 split size in MB. **One unknown key fails the whole batch**, and key 4
  is "not accessible". This is documented in the therefore-api skill (pitfall #39) and in the
  therefore-mcp knowledge base, both pushed to GitHub.
- Content Connector's "Start collaboration" is set to "Do not log" on craigdemo, although the
  documented default is Always.

## Open items / next steps

1. ~~**First Docker build on the Mac.**~~ Done 29 Sep: `docker compose up -d --build` builds and
   runs cleanly (Postgres + scheduler), a live `auditor run --tenant craigdemo` worked end to end,
   and all 8 tests pass against the compose Postgres.
2. **LogMask mapping** (a reminder was scheduled for 30 Sep 9am in the Cowork session). Poll
   `GetSettings` key 700 every ~10s while Craig toggles one Server Logging event at a time in
   Solution Designer, and diff to map positions to events. Then name the events in `config_drift`
   and update the therefore-api-skill + therefore-mcp docs.
3. **Does a logging-settings change need a server restart before it takes effect?** Craig's test
   on 29 Sep AEST:
   - DocNo 28016 saved with Doc New at its default (failure only)
   - then Doc New switched to Always and DocNo 28021 saved
   - then a restart, then DocNo 28025 saved (all in category 340 "Counter Test")

   Read the Server log with GENERATED 2026-09-29 (arrives about 03:15 AEST 30 Sep) and see which
   Doc New lines appear:
   - only 28025 → a restart is needed
   - 28021 and 28025 → the change applies immediately

   Related puzzle: Craig's login at about 19:20 AEST on 28 Sep and API calls at about 19:26 were
   *not* logged, and successful Connects only appeared from 00:02 AEST 29 Sep. Also check that
   Craig's 08:47 AEST 29 Sep login and the settings-scan burst (about 1,500 GetSettings calls
   from the dev environment's IP around 11:00 AEST 29 Sep) show up.
4. ~~**Incident grouping.**~~ Done 29 Sep: findings now get an `incident_key` (primary subject —
   first user, else first IP — plus calendar day in `display_tz`; see `incident_key_for` in
   `rules/engine.py`). `llm.triage()` sends all of an incident's findings in one call and applies
   the single verdict/severity/explanation to every member; `digest.py` renders them as one entry
   with a member-title bullet list. Covered by
   `tests/test_rules_integration.py::test_incident_grouping_shares_one_llm_call` (a stub provider
   asserts exactly one LLM call for two grouped findings). Not yet exercised by real tenant data —
   craigdemo's current findings don't happen to co-occur for one user/IP/day — so watch the next
   live incident to confirm the grouped narrative reads well in production, not just in the test.
5. **Service account.** Create `svc.logaudit` (read Logfiles + settings; write only to a future
   "Audit Reports" category) and replace Craig's credentials in `.env`. Test whether a non-admin
   account can read `GetSettings`. Several keys expose infrastructure (SQL server, storage paths,
   SMTP, OAuth config), which may need raising with Therefore.
6. ~~**GitHub.**~~ Done 29 Sep: https://github.com/Fybre/therefore-log-auditor (public), `main`
   pushed and tracked as `origin/main`. Checked git history first — no real secrets were ever
   committed (`.env`/`config/tenants.yaml` were always gitignored, only placeholder values exist).
7. **Phase 2** (per the design doc):
   - web dashboard (FastAPI + simple UI; findings queue, evidence, known-activity management, verdict feedback)
   - Teams webhook alerts for High
   - daily PDF report saved into a Therefore "Audit Reports" category
   - Entra ID sign-in
   - Postgres row-level security per tenant
   - add Sumitomo as a second tenant
8. Later: Migrate/Content Connector-specific rules (disk space "MB free", fetch/process errors),
   GeoIP enrichment (MaxMind GeoLite2), an optional "archive by size" setting for faster
   detection, and optionally deleting processed log docs (they count toward document limits;
   craigdemo hit its 10,000-document evaluation limit in Oct 2025).

## Related repos and resources

- Therefore REST API skill: https://github.com/Fybre/therefore-api-skill (local:
  `~/Documents/source/therefore-api-skill`). Read its SKILL.md before writing any Therefore API code.
- Therefore MCP server + knowledge base: https://github.com/Fybre/therefore-mcp (local:
  `~/Documents/source/therefore-mcp`).
- Therefore Server Logging help:
  https://help.therefore.net/tfo/en-us/sd/sd_r_theobject_settings_serverlogging.htm
- Web API reference: https://therefore.net/help/Online/en-us/AR/SDK/WebAPI/the_webapi_reference.html
- Test tenant: `https://craigdemo.thereforeonline.com` (TenantName header `craigdemo`). The
  credentials are in `.env`; never commit them.
