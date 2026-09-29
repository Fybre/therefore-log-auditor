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
5. **Known activity.** `known.users`, `known.ips` and `known.windows` in `tenants.yaml` downgrade
   matching findings to `info`. They never delete them.
6. **LLM triage.** For each finding the LLM gets its details, up to 25 evidence lines, the
   known-activity notes and past verdicts. Users, IPs and hosts are replaced with pseudonyms
   before sending (`redact: true`). The reply must be JSON with a verdict, severity, explanation
   and actions. If the LLM fails, the finding keeps the severity the rule gave it.
7. **Digest.** Written to `reports/<tenant>/<date>.html|.md`, and emailed if SMTP is configured.

## Setup

```bash
cp .env.example .env                      # Therefore creds, LLM_*, optional SMTP
cp config/tenants.example.yaml config/tenants.yaml
docker compose up -d --build              # Postgres + scheduler (runs each tenant's cron)
docker compose run --rm auditor backfill --tenant craigdemo --since 2023-09-01   # load history
docker compose run --rm auditor run --tenant craigdemo                          # one daily run now
docker compose run --rm auditor findings --tenant craigdemo --days 30
```

Use a dedicated Therefore service account that can read `Logfiles` (and settings), and list it
under `known.users`. Every API call is logged by Therefore as a Connect/Disconnect.

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
- Findings aren't grouped into incidents yet (one login can raise new-user, new-IP and
  admin-tool findings).
- Phase 2: web dashboard, suppressions managed in the UI, Teams alerts, PDF report saved into Therefore.
