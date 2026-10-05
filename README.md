# Therefore Log Auditor

Audits Therefore Online server logs for operational and security issues. Deterministic rules
find the problems, and an LLM (any OpenAI-compatible endpoint) explains and ranks them. The
results go into a daily digest.

Phase 1 (MVP): collector, parsers, Postgres, 10 rules, LLM triage, daily digest (HTML/Markdown
report + optional email). The design doc is in Claude ("Therefore Log Auditor — Architecture").

## How it works

1. **Collect.** Therefore archives its logs into the `Logfiles` category once a day (Server log at
   about 17:00 UTC) and once a week (Migrate / Content Connector). The auditor queries `Logfiles`
   month by month, because a query without conditions stops at 500 rows. It downloads each new
   DocNo once and keeps the raw file.
2. **Parse.** The Server log (LogFormat 4) has 11 pipe-delimited columns, which become one event
   row each (user, host, IP, action, result code, doc, category, workflow, client type, message).
   Migrate and Content Connector logs are matched against text templates.
3. **Snapshot settings.** `GetSettings` keys 700–704 (log mask and archive schedule) are saved on
   every run so changes to the logging configuration are detected.
4. **Rules** (`config/rules.yaml`): brute_force, success_after_failures, new_entity (user / IP /
   first admin-tool use), mass_delete, unplanned_restart, log_gap, config_drift,
   recurring_failure, retry_storm, licence_limit. Findings are upserted by a dedupe key, so re-runs
   never create duplicates.
5. **Known activity.** `known.users`, `known.ips` and `known.windows` on a tenant downgrade
   matching findings to `info`. They never delete them.
6. **LLM triage.** For each finding the LLM gets its details, up to 25 evidence lines, the
   known-activity notes and past verdicts. Users, IPs and hosts are replaced with pseudonyms
   before sending (`redact: true`). The reply must be JSON with a verdict, severity, explanation
   and actions. If the LLM fails, the finding keeps the severity the rule gave it.
7. **Digest.** Written to `reports/<tenant>/<date>.html|.md`, and emailed if SMTP is configured.
8. **Incidents.** Findings that share a primary subject (first user, else first IP) and calendar
   day get an `incident_key` and are triaged together in one LLM call, so a new-user + login-
   after-failures + first-admin-tool-use sequence reads as one story instead of three.

## Setup

Tenants/servers, per-tenant rule toggles and SMTP delivery are configured **from the dashboard**,
not files - only what has to exist before the database does stays in `.env`:

```bash
cp .env.example .env      # DATABASE_URL is set by compose; fill in LLM_*, AUDITOR_ENC_KEY,
                           # AUDITOR_WEB_USER/PASSWORD/SECRET (see comments in the file)
docker compose up -d --build              # Postgres + scheduler + dashboard
open http://localhost:8080                # log in with AUDITOR_WEB_USER/PASSWORD, then
                                           # Tenants -> Add tenant to add your first Therefore server
docker compose run --rm auditor backfill --tenant <id> --since 2023-09-01   # load history
docker compose run --rm auditor run --tenant <id>                          # one daily run now
docker compose run --rm auditor findings --tenant <id> --days 30
```

Use a dedicated Therefore service account that can read `Logfiles` (and settings), and list it
under the tenant's known users. Every API call is logged by Therefore as a Connect/Disconnect.
The scheduler re-reads tenants from the database every 5 minutes, so adding, editing or deleting
one from the dashboard takes effect without a restart.

**Upgrading from file-based config** (pre-dashboard versions used `config/tenants.yaml` +
`THEREFORE_<ID>_USERNAME/PASSWORD` in `.env`): run
`docker compose run --rm auditor import-legacy-config` once to copy them into the database
(existing tenants with the same id are left alone, so it's safe to re-run). `config/rules.yaml`
still holds the *global default* thresholds; only per-tenant overrides live in the database.

### Dashboard

```bash
docker compose up -d web                 # http://localhost:8080
```

Findings queue, evidence view, human verdict feedback (a status + note per finding, fed back to
the LLM as context for future triage of that rule), and config management under **Tenants** /
**SMTP** / **Accounts**:

- **Tenants** - add/edit/delete Therefore servers (base URL, credentials, schedule, LLM
  on/off, digest recipients), and per-tenant rule toggles (inherit the global default from
  `config/rules.yaml`, force on, force off, or override thresholds with a JSON blob).
- **SMTP** - one global delivery config for the daily digest emails.
- **Accounts** - local dashboard logins (username + password, PBKDF2-hashed). The first account
  is seeded from `AUDITOR_WEB_USER`/`AUDITOR_WEB_PASSWORD` in `.env` on first boot only; after
  that, manage accounts here or with `auditor create-user <name>`. Local accounts are the
  intended long-term auth model (not a placeholder for SSO).

Tenant Therefore passwords and the SMTP password are encrypted at rest with `AUDITOR_ENC_KEY`
(a Fernet key - generate one with
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`).
Keep it stable: losing it means every stored password becomes unreadable and has to be re-entered.

### LLM

Any OpenAI-compatible `/chat/completions` endpoint works:

| Provider | LLM_BASE_URL | LLM_MODEL example |
|---|---|---|
| OpenRouter | `https://openrouter.ai/api/v1` | `openai/gpt-6-luna` |
| Ollama | `http://host.docker.internal:11434/v1` | `qwen3:14b` |
| LM Studio | `http://host.docker.internal:1234/v1` | loaded model id |

It asks for strict `json_schema` output and falls back to `json_object` if the endpoint doesn't
support it. Set `llm.enabled: false` on a tenant for rules only.

## Development

```bash
pip install -e '.[dev]'
DATABASE_URL=postgresql://... auditor migrate
TEST_DATABASE_URL=postgresql://.../auditor_test pytest -q
```

## Known limitations / next phases

- Logs arrive once a day, so detection lags by up to 24h. Archiving by file size can make it faster.
- The LogMask (key 700) position → event mapping is not mapped yet, so config-drift reports
  changed positions rather than event names.
- The dashboard's known-activity page (`/t/<id>/known`) is still read-only - editing it is a
  future step, since it wasn't part of the tenant/rules/SMTP config move.
- Phase 2 remaining: Teams alerts, PDF report saved into Therefore, known-activity editing in
  the UI, Postgres row-level security per tenant (all dashboard accounts currently see all
  tenants - fine for a single-operator deployment, not yet for multiple customers/teams).

## Live security monitoring and notifications

An opt-in Console collector now records live observations separately from archived logs.
It detects credential failures (5/account/15 minutes), password spray (3 accounts/IP/60 minutes),
success after failures (2 failures/2 hours), distinct-document retrieval bursts and explicitly
labelled API activity bursts (both over rolling 5-minute windows). These are conservative pilot
mappings, not a claim of complete Console coverage or exact API HTTP request counts.

Start the worker with `docker compose --profile live up -d --build live web`. On the dashboard,
open **Tenants → Edit tenant → Live monitoring settings**, choose thresholds and enable collection.
Use **Live security** to see connection status, collected-message counts and the latest messages;
the monitoring view refreshes every 10 seconds. The worker
uses that tenant's existing encrypted credentials and HTTPS endpoint; its account needs Console
view access. Tenants are disabled for live collection by default. Collection runs without a browser,
with one database-locked worker per tenant, configurable 5–60-second polls (default 15 seconds)
and recovery snapshots approximately every 60 seconds. Change the polling interval in Live
monitoring settings; the worker picks it up on its next cycle without a restart.

The live worker maintains event-time rolling counters between polls, batches observation inserts
and finding updates, and maintains collection totals in the same database transactions. Restart,
late messages and approval changes rebuild the necessary context from stored observations.
See [live processing](docs/live-processing.md) for recovery behavior and validation.

**Security emails are opt-in and disabled by default.** In tenant **Live monitoring settings →
Security notifications**, save custom recipients or leave them blank to use tenant digest recipients,
then enable notifications. The existing SMTP configuration is used. **Send test security email**
queues an explicit test to the saved recipients even in shadow mode; the live worker must be running.
Delivery and retry status appear in **Recent security alerts** and beside findings.

One initial email is queued per unexpected finding episode. Routine activity updates that episode;
an escalation requires at least 15 minutes since the previous queued alert and either doubled volume
or increased severity. Activity after more than 30 minutes of inactivity begins a new episode.
Historical replay and expected activity do not generate automatic emails. Disabling notifications,
disabling collection, or marking a finding expected cancels queued automatic alerts when dispatched;
a send already in progress may finish. Queued tests are explicit requests and still deliver.
See [notification delivery](docs/live-notifications.md) for retry and crash behavior.

Review findings and raw evidence on the Live security page; the daily archive pipeline/digests are unchanged. Initial/recovery backlog is
also evaluated and may produce historical shadow findings. Known-user/IP blanket suppressions
from archive rules do not suppress live security findings.

In tenant **Live monitoring settings**, use **Approve a bulk workload** to exclude legitimate bulk activity from the default live queue.
An approval requires account, source IP/CIDR, activity, start/expiry (with explicit UTC offset),
a maximum count per 5 minutes and a reason. Every restriction must match. Approval is specific
to retrieval or observed API activity and never suppresses login rules. Matching work remains
recorded under **Show expected activity**; exceeding the limit produces an actionable finding.
Overlapping approvals use the earliest matching record, never combined limits. Revoke an approval
to stop its use in subsequent evaluations. Existing findings retain their recorded assessment unless explicitly reviewed. From a bulk finding,
choose **Approve this activity** to prefill a scoped approval, review the suggested one-hour window
and observed volume, and add a reason. An optional checkbox marks that selected finding expected;
the review is audited and other findings remain unchanged. Multiple or missing source IPs require
an explicit network choice. General error messages and login findings do not create bulk approvals.

Current pilot boundaries:

- API attribution requires explicit message context. General retrieval detection still catches
  unattributed retrieval bursts; proximity to an API Connect is not treated as proof of attribution.
- Only recognised successful completions count toward retrieval/API bursts. Unknown messages are
  preserved for investigation and mapping improvements. Started rows do not count as completions.
- Use **Last successful poll** and **Last evaluation** to check freshness; errors and suspected gaps
  remain visible. The server backlog is bounded, so recovery cannot promise complete coverage.
- No archive reconciliation, automatic blocking, recurring approval schedules, category-specific
  approvals, learned baselines or automatic retention pruning yet. Raw
  observations and supporting evidence currently remain in Postgres; monitor storage in the pilot.
- No live tenant was contacted to validate this implementation. Console 35.0.3 and ASCII passwords
  are the established upstream protocol scope; validate your tenant in shadow mode first.

See [the implementation plan](docs/live-security-monitoring-plan.md) and
[the coverage analysis](docs/live-monitoring-analysis.md) for subsequent increments.
