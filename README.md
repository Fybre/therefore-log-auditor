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
