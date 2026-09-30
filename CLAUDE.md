# CLAUDE.md — Therefore Log Auditor

Context for continuing this project in Claude Code. It records the project's purpose, what has
been built, what was learned about Therefore logging, and what is still to do.
Last updated: 30 Sep 2026.

Session of 30 Sep added (all tested, verified live, committed and pushed): a canonservice
false-positive fix (licence exhaustion misread as password spray), a digest open-backlog summary
+ configurable dashboard link, a per-tenant "only email on new findings" option, a fix for a
Docker volume mount that silently dropped web-triggered reports, an `obj_version` bigint fix for
an ingestion overflow bug, a scheduler self-health check with email alerts, time-boxed
rule/user/IP suppression ("snooze") on the Known Activity page, an admin audit trail
(`/admin/audit`) for changes to the auditor's own config, and one-click "mark reviewed"/"false
positive" links in digest emails. See the relevant sections below for each.

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
docker compose up -d --build                                                    # Postgres + scheduler + dashboard
docker compose run --rm auditor backfill --tenant craigdemo --since 2023-09-01   # load history, rules only
docker compose run --rm auditor run --tenant craigdemo                          # full daily run now
docker compose run --rm auditor findings --tenant craigdemo --days 30 --min-severity medium
open reports/craigdemo/                                                          # HTML/MD digests
open http://localhost:8080                                                       # dashboard (login: AUDITOR_WEB_USER/PASSWORD)
```
Local dev without Docker: `pip install -e '.[dev]'`, set `DATABASE_URL`, then `auditor migrate`
and the same commands. Postgres from compose is exposed on `127.0.0.1:5433` (user/db `auditor`).

**Tests use a separate `auditor_test` database, never the compose `auditor` one** - set
`TEST_DATABASE_URL=postgresql://auditor:auditor@db:5432/auditor_test` (create the DB once with
`docker compose exec db psql -U auditor -d auditor -c "CREATE DATABASE auditor_test;"`).
Every DB-backed test does `DROP SCHEMA public CASCADE` first - pointing `TEST_DATABASE_URL` at
the real `auditor` DB wipes real findings/events (this happened once, on 29 Sep; craigdemo's
findings were recoverable by re-running `auditor run`, but don't repeat the mistake).

Config (rewritten 29 Sep - see "Dashboard config" below for the full story):
- **Tenants/servers, per-tenant rule toggles and SMTP delivery now live in the database**,
  managed from the dashboard (Tenants / SMTP admin pages), not files. `config/tenants.yaml` is
  legacy-only, read once by `auditor import-legacy-config`.
- `.env` (gitignored) now only holds what has to exist before the database does: `LLM_BASE_URL`,
  `LLM_API_KEY` (OpenRouter key, $250 limit), `LLM_MODEL`, `AUDITOR_WEB_USER/PASSWORD/SECRET`
  (dashboard login/session), and `AUDITOR_ENC_KEY` (Fernet key encrypting tenant/SMTP passwords
  at rest - **keep it stable, losing it means every stored password becomes unreadable**).
  `DATABASE_URL` is set by compose.
- `config/rules.yaml` still holds the *global default* rule thresholds - only per-tenant
  overrides/toggles moved to the database (`tenant_rule_settings` table, editable at
  `/admin/tenants/{id}/rules`).

## Code map

```
auditor/
  config.py      Tenant/Settings dataclasses; tenants/rule-overrides/SMTP are DB-backed now (see
                 load_tenants/save_tenant/rule_settings_for/set_rule_setting/load_smtp/save_smtp);
                 load_settings() is env/file-only (safe before migrations run), refresh_from_db()
                 populates Settings.tenants/smtp from the database once a connection exists
  crypto.py      Fernet encrypt/decrypt for tenant + SMTP passwords at rest (key: AUDITOR_ENC_KEY)
  passwords.py   PBKDF2-SHA256 hashing for dashboard accounts (stdlib only, no bcrypt dependency)
  legacy_import.py  one-time config/tenants.yaml + THEREFORE_<ID>_*/SMTP_* .env -> database import
  db.py          psycopg3 connect + numbered SQL migrations (auditor/migrations/NNN_*.sql)
  therefore.py   REST client: Logfiles listing (month windows), GetDocumentStream, GetSettings
  parsers.py     LogFormat 4 (Server, 11 pipe columns) + 5/6 (Migrate / Content Connector free text)
  collector.py   discover -> fetch -> parse -> store (idempotent by DocNo, raw file kept); settings snapshot
  rules/engine.py   Context, Finding, rule registry, suppressions, upsert by (tenant, rule, dedupe_key)
  rules/builtin.py  10 rules (below)
  llm.py         OpenAICompatProvider (json_schema strict, falls back to json_object), Redactor, triage, summary
  digest.py      gather/render HTML + Markdown, write reports/<tenant>/, SMTP send
  pipeline.py    run_tenant(): collect -> snapshot -> rules (UTC-midnight-aligned window) -> triage -> digest
  scheduler.py   APScheduler: daily cron per tenant + hourly catch-up (6h). A `reconcile` job runs
                 every 5 min, re-reading tenants from the DB and add/remove/reschedule-ing jobs, so
                 dashboard changes take effect without restarting the `auditor` (serve) container
  cli.py         auditor migrate | run | backfill | serve | web | findings | create-user |
                 import-legacy-config
  web/app.py     FastAPI dashboard: findings queue/detail/evidence/review, known-activity
                 (read-only), and /admin/* config management (tenants CRUD, per-tenant rule
                 toggles, SMTP, local accounts)
  web/auth.py    Session-cookie login against the `web_users` table (PBKDF2). Local accounts are
                 the intended long-term model - Entra ID/OIDC was considered and explicitly
                 declined (29 Sep). First account is seeded from AUDITOR_WEB_USER/PASSWORD on
                 first boot only if web_users is empty; manage further accounts at /admin/users
```
DB tables: `log_files`, `events`, `findings`, `settings_snapshots`, `runs`, `schema_migrations`,
`web_users`, `tenants`, `tenant_rule_settings`, `app_settings` (added 29 Sep - migration 004).

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
- Digest emails include an all-time "currently open" backlog summary (not just what changed this
  run) and, when `dashboard_url` is set (`/admin/smtp`'s "Dashboard link" card), links back to the
  dashboard - both a general link and per-finding deep links. The report file is *always* written
  to `reports/<tenant>/` regardless. Whether it's *emailed* can additionally be gated per-tenant:
  the "Only email the digest when there are new findings" checkbox
  (`tenants.digest_only_on_new`, `/admin/tenants/{id}/edit`) skips the send when
  `findings_changed == 0` for that run (migration 005). Off by default - existing tenants keep
  emailing every run until they opt in.

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
  presumed - see the LogMask position map below), 701 archive mode, 702 weekday, 703 archive
  time in minutes after midnight UTC (1020 confirmed = 17:00 UTC), 704 split size in MB.
  **One unknown key fails the whole batch**, and key 4 is "not accessible". This is documented
  in the therefore-api skill (pitfall #39) and in the therefore-mcp knowledge base, both pushed
  to GitHub.
  - **701 (archive mode) - fully confirmed 30 Sep:** `1` = Every day, `2` = Every week,
    `3` = Every month, `4` = On size (the UI's own label - not "by size").
  - **702 (weekday, only meaningful in weekly mode) confirmed values:** `1` = Sunday,
    `2` = Monday - a 1-indexed week starting Sunday (so presumably `3`=Tue ... `7`=Sat, untested
    beyond Sun/Mon but the pattern is clear). In monthly/on-size mode the Weekday dropdown is
    blank/disabled in the UI but 702 keeps whatever value it last held (not reset server-side).
  - **Monthly mode has no exposed day-of-month control** in Solution Designer - the archive day
    is presumably hardcoded server-side; not discoverable without waiting for a real monthly
    rotation and checking the date it lands on.
- Content Connector's "Start collaboration" is set to "Do not log" on craigdemo, although the
  documented default is Always.

## Open items / next steps

1. ~~**First Docker build on the Mac.**~~ Done 29 Sep: `docker compose up -d --build` builds and
   runs cleanly (Postgres + scheduler), a live `auditor run --tenant craigdemo` worked end to end,
   and all 8 tests pass against the compose Postgres.
2. **LogMask mapping** — in progress, started 30 Sep. Method: fetch `GetSettings` key 700 via the
   `auditor` container (`docker compose exec auditor python -c "..."`, using
   `ThereforeClient.get_settings((700,))` against the craigdemo tenant loaded from the DB - see
   below for the exact snippet), have Craig toggle one Server Logging event at a time in Solution
   Designer, then re-fetch and diff by index.
   - **Confirmed 30 Sep: a settings change applies as soon as the Solution Designer dialog is
     saved (OK clicked) - no server restart needed.** Re-fetching immediately after Save but
     before clicking OK showed no change; re-fetching after OK showed the diff. This also answers
     open item 3 below (no restart required) without needing to wait for a log file.
   - Fetch snippet (run inside the `auditor` container, which already has craigdemo's DB-stored
     credentials loaded):
     ```python
     from auditor.config import load_settings
     from auditor.db import connect
     from auditor import config as cfg
     from auditor.therefore import ThereforeClient

     settings = load_settings()
     with connect(settings.database_url) as conn:
         cfg.refresh_from_db(settings, conn)
     tenant = next(t for t in settings.tenants if t.id == 'craigdemo')
     print(ThereforeClient(tenant).get_settings((700,))[700])
     ```
   - **Confirmed positions (0-indexed), from clean single-diff tests, each followed by a full
     Solution Designer restart + fresh screenshot to rule out UI caching:**
     - Position 5 = Document New
     - Position 15 = Change
     - Position 23 = Document Retrieve
     - Position 25 = Delete
     - Position 26 = Check Out
     Values confirmed so far: `0` = Do not log, `2` = Log success, `3` = Log always (per the
     skill). `1` = Log failure is documented but **see the anomaly below before trusting a `1`
     result** for New/Retrieve/Change specifically.
   - **Open anomaly, found 30 Sep, not yet root-caused:** for New, Retrieve and Change
     specifically, "Log failure" vs "Log always" as shown in the Solution Designer UI is
     consistently the opposite of what `GetSettings` key 700 reports for those positions -
     reproduced independently on two separate days/sessions, always in the same direction
     (UI="Log always" ↔ backend=`1`, UI="Log failure" ↔ backend=`3`), surviving a full Solution
     Designer restart and a tenant restart. "Do not log" (`0`) and "Log success" (`2`) are
     unaffected and read/write consistently on the same rows. Three live hypotheses, **none
     confirmed - do not assume which is correct**:
     1. A real Therefore-side business rule that silently promotes certain core write-critical
        events to "Always" when "failure-only" is requested.
     2. A Solution Designer UI/dropdown bug where these two options are bound to swapped
        underlying values for these three rows only.
     3. **(Craig's suggestion, 30 Sep, probably the best next test)** Both the UI and the config
        are actually correct/consistent, and it's specifically `GetSettings`'s *reporting* of key
        700 that's wrong for these two values on these rows - i.e. the logging itself works as
        configured, only our read-back via the REST API is misleading.
     **Definitive test for next time (settles all three hypotheses at once):** set New to "Log
     always" via the UI, create/save a test document, then set New to "Log failure" via the UI,
     create/save another test document - then check the actual Server log to see whether both
     documents' New events were logged (→ hypothesis 3, always-really-was-always and
     failure-really-was-failure, API read-back is just wrong) or only one was (→ hypothesis 1 or
     2, the configured level really did end up different from what was selected). Not urgent -
     Craig doesn't currently need this resolved, but worth doing before trusting any `1`/`3`
     read from positions 5/15/23 for real monitoring decisions.
   - Remaining: map the other 47 positions the same way, one event at a time (Craig's stated
     protocol: change one event, save, confirm; then revert it, save, confirm; then move to the
     next - and always screenshot after a full dialog close/reopen, not just after Save, since a
     screenshot without a fresh reload turned out not to be trustworthy). Once the map is
     complete, name the events in `config_drift` and update the therefore-api-skill +
     therefore-mcp docs (per the skill's "Keeping Knowledge in Sync" section).
3. ~~**Does a logging-settings change need a server restart before it takes effect?**~~ Answered
   30 Sep via the LogMask-mapping test above: **no restart needed, applies on Save.** Craig's
   earlier 29 Sep DocNo-based test (28016/28021/28025 in category 340) is no longer needed to
   confirm this, though the log file for that day can still be read if the *related* puzzle below
   is worth chasing.

   Related puzzle (still open, lower priority now): Craig's login at about 19:20 AEST on 28 Sep
   and API calls at about 19:26 were *not* logged, and successful Connects only appeared from
   00:02 AEST 29 Sep. Also check that Craig's 08:47 AEST 29 Sep login and the settings-scan burst
   (about 1,500 GetSettings calls from the dev environment's IP around 11:00 AEST 29 Sep) show up.
4. ~~**Incident grouping.**~~ Done 29 Sep: findings now get an `incident_key` (primary subject —
   first user, else first IP — plus calendar day in `display_tz`; see `incident_key_for` in
   `rules/engine.py`). `llm.triage()` sends all of an incident's findings in one call and applies
   the single verdict/severity/explanation to every member; `digest.py` renders them as one entry
   with a member-title bullet list. Covered by
   `tests/test_rules_integration.py::test_incident_grouping_shares_one_llm_call` (a stub provider
   asserts exactly one LLM call for two grouped findings). Not yet exercised by real tenant data —
   craigdemo's current findings don't happen to co-occur for one user/IP/day — so watch the next
   live incident to confirm the grouped narrative reads well in production, not just in the test.
5. ~~**Service account.**~~ Done 29 Sep: `svc.logaudit` created on craigdemo and `.env` switched
   over from Craig's own login (Craig updated `.env` himself — creating a user via the API needs
   the account's admin credentials read from disk, which Claude Code's auto-mode classifier blocks
   as "credential materialization" even after in-chat confirmation; it can only be done by the user
   directly, e.g. via `!`). A live `auditor run --tenant craigdemo` with the new credentials
   succeeded end to end with no warnings, confirming `svc.logaudit` can already read the Logfiles
   category and `GetSettings` (keys 700-704) - so a non-admin/service account **can** read
   `GetSettings` on craigdemo, resolving the open question about Server Settings access.
   Not yet done: writing to a future "Audit Reports" category (that category doesn't exist yet -
   Phase 2 work) and tightening `svc.logaudit`'s permissions down from whatever it inherited by
   default (it was never scoped to read-only; worth checking in Solution Designer what it can
   actually do beyond Logfiles/settings). Craig also plans to move from Basic auth to JWT/Bearer
   auth later - note per the therefore-api-skill that `GetConnectionToken`'s token is a 12-char
   string, not a JWT, and fails as a Bearer token, so this needs checking whether Therefore Online
   has a separate JWT/OAuth flow before implementing (settings keys 187/189 - JWT trusted issuers,
   OAuth settings XML - suggest one exists).
6. ~~**GitHub.**~~ Done 29 Sep: https://github.com/Fybre/therefore-log-auditor (public), `main`
   pushed and tracked as `origin/main`. Checked git history first — no real secrets were ever
   committed (`.env`/`config/tenants.yaml` were always gitignored, only placeholder values exist).
7. **Phase 2** (per the design doc):
   - ~~web dashboard~~ Started 29 Sep, config management added later the same day: FastAPI app at
     `auditor/web/`, runs as the `web` compose service on :8080. Findings queue
     (`/t/{tenant}/findings`, filterable by severity/status/days), finding detail with evidence
     lines and incident cross-links (`/t/{tenant}/findings/{id}`), known-activity display
     (read-only), and verdict feedback (a status + note per finding, saved to
     `findings.reviewed_by/reviewed_note/reviewed_at` and fed back into future LLM triage of that
     rule via `llm._past_verdicts`). Login is against local accounts in `web_users`
     (PBKDF2-hashed) - **Craig explicitly said Entra ID is not required and local accounts are
     fine**, so this is the intended long-term model, not a placeholder (superseding what an
     earlier session note said). Tested via `tests/test_web.py` (FastAPI TestClient, 16 tests) and
     manually against live craigdemo data through the compose `web` service. Not yet done:
     known-activity editing in the UI (still read-only), and dashboard-level incident-group
     rendering to match the digest (the findings table shows an "N related" pill but still lists
     each finding as its own row).
   - ~~**Config management (tenants/servers, rule toggles, SMTP) from the dashboard**~~ Done
     29 Sep, same session, per Craig's explicit request ("rather than configuration through env
     I want to be able to add/remove/configure tenants/servers from the dashboard... toggling what
     events are to flag alerts... setup for SMTP... entra id auth is not required, local user
     accounts is fine"). Tenants/servers, per-tenant rule enable/disable + threshold overrides, and
     SMTP delivery moved from `config/tenants.yaml`/`.env` into the database (migration 004:
     `tenants`, `tenant_rule_settings`, `app_settings`, `web_users`). Managed at `/admin/tenants`
     (CRUD, live-tested by adding/editing/deleting a real tenant through the running dashboard),
     `/admin/tenants/{id}/rules` (per-rule inherit/on/off + optional JSON threshold override,
     live-tested), `/admin/smtp`, `/admin/users`. Passwords (tenant Therefore logins, SMTP) are
     Fernet-encrypted at rest via `AUDITOR_ENC_KEY`; dashboard passwords are PBKDF2-hashed.
     The scheduler (`auditor serve`) reconciles tenants from the DB every 5 minutes, so dashboard
     changes take effect without a restart - confirmed in the logs after adding a test tenant.
     `auditor import-legacy-config` migrates old `tenants.yaml`/env-based setups once; craigdemo's
     existing config was imported this way and re-verified with a live `auditor run`.
     **`config/rules.yaml` still holds the global default thresholds** - only overrides moved to
     the database, on purpose (Craig didn't ask for that to move, and keeping a file-based base
     config was simpler than also relocating it).
     Not yet done: no RBAC (every dashboard account can manage every tenant - fine for a single
     operator, revisit before onboarding a second team), and `/admin/tenants` has no bulk import
     beyond the one-time legacy path.
   - Teams webhook alerts for High
   - daily PDF report saved into a Therefore "Audit Reports" category
   - Postgres row-level security per tenant
   - add Sumitomo as a second tenant - now genuinely just "add it from the dashboard" per Craig's
     stated plan ("once we can configure tenants from the dashboard I will add another")
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
