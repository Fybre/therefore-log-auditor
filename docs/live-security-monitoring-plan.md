# Live security monitoring implementation plan

5 October 2026. Proposed implementation, not enabled functionality. Builds on [the source and capture analysis](live-monitoring-analysis.md), including the user's print example for document 27953.2.

## Implementation status — first increment

Implemented locally: opt-in `auditor live`/Compose service, Postgres raw observations and atomic cursors, recovery snapshots and per-tenant worker locking, conservative stage/outcome normalization, shadow login/retrieval/API-activity findings, authenticated dashboard/evidence views, and time-bounded account/network/volume workload approvals with audit history. No live tenant has been enabled or contacted during implementation.

This first increment deliberately has no security notification delivery. It keeps live findings separate from daily archive findings, so it cannot double-count the two sources in existing rules or accidentally send pilot findings in digests. The implemented UI exposes one-off approvals and two bulk thresholds; login thresholds currently use fixed pilot defaults.

Still to implement after validating the pilot: notification outbox/delivery, archive reconciliation, independent live-worker health alerts, recurring/scoped-category approvals and approval-from-finding prefill, historical/late-arrival reconciliation beyond newly ingested endpoints, baseline anomaly rules, configurable retention, and richer review/episode lifecycle controls. Existing collector timestamps and errors support manual health inspection.

## Intended outcome

Detect suspicious login and document activity while it is happening, alert an operator promptly, and subsequently reconcile with archived logs. Keep existing archive-only detections and daily digests. The first release responds by notifying and supplying evidence; automatic account blocking, session termination or server actions are outside scope.

Healthy-state target: an eligible security finding reaches the dashboard and is handed to the configured notification service within 60 seconds of crossing its detection threshold. Measure this during the pilot; it is not a guarantee of server emission or email arrival time.

## End-to-end flow

```text
Console view 3 → durable raw observations → validated live activity → rolling security rules
                                                                       ↓
                                                            findings / incidents
                                                                       ↓
                                                         durable notification outbox
                                                                       ↓
                                                           dashboard + email alert

Logfiles category → existing archive ingestion → existing audit rules ───┘
                           ↓
              correlate with live evidence → enrich existing incidents

Console view 9 → connector snapshots → operational rules (follow-on increment)
```

The collector runs continuously without an open browser. Rules and delivery are independently checkpointed so a slow LLM or email server cannot stop collection. LLM enrichment happens after deterministic detection and does not gate urgent alerts.

## 1. Capture and validate the events we need

Start with one tenant in shadow mode: persist observations and calculate candidate findings, but send no security notifications. Reuse the web console's proven protocol client, authentication and recovery behaviour, with a recorded upstream revision. Do not consume the web console's browser-session API or memory buffer.

Collect evidence for:

- Failed login, successful login and failure followed by success. Verify username/IP availability and distinguish password rejection from licence limits and token expiry. The supplied screenshot supports RetCode 27 for an invalid-password Connect in that context; do not apply it to unrelated result fields.
- Successful and failed document retrieval, repeated retrieval of one document, retrieval of many documents, and normal indexing activity.
- Started/completed pairs. Preserve raw Oper and its high bit without inventing their meaning. Use validated completion text/fields for the initial mapping; ambiguous stages stay unknown.
- Delete and index change as subsequent candidates; printing is not required for the first live security release.
- The archive covering the user's existing 27953.2 print example, to establish whether the missing Console action appears there.

Use fixtures and offline replay for password-spray/burst volumes. A small controlled test on a disposable account is sufficient to establish the actual failure payload; do not generate a real high-volume attack just to test a rule.

Deliver a coverage matrix keyed by server/client version and operation/outcome, with statuses: observed, validated for detection, unknown, or unsupported in the tested path. Record raw samples privately, redact fixture identities, and keep capture gaps explicit. Do not require the full event catalog to be mapped before enabling individually validated rules.

**Exit gate:** login and retrieval mappings can distinguish known outcomes and completed activity from stage messages, with reproducible fixtures. Obtain overlapping live/archive evidence over at least two actual archive cycles for the core pilot comparisons. Archive parity is not assumed for untested event types.

## 2. Add durable, independently supervised collection

Add `auditor live` as a separate Compose service using the existing image and Postgres. It reads enabled tenants and live settings from the database and refreshes configuration periodically.

- Proposed initial poll interval: 5 seconds; evaluate rules every 10 seconds. Measure server load before reducing polling to 2 seconds.
- One active collector per tenant/endpoint, enforced through database ownership/locking. Stop polling on ownership loss; never let two replicas advance the same cursor independently.
- Reuse encrypted credential storage. Allow an optional separate Console account if existing archive credentials lack permission. Verify permissions and licence consumption in the pilot.
- Commit raw observations and cursor together. Deduplicate full raw-payload fingerprints within a tenant/endpoint, with the documented limitation that completely identical payloads cannot be distinguished.
- Use zero-cursor snapshots on startup/recovery and periodically, plus backoff and reauthentication for verified invalid-session results. Allow keys to reset without erasing history.
- Monitor last successful poll, last durable commit, worker heartbeat, reconnects, cursor resets, rule evaluation lag and possible unrecoverable gaps. Empty successful polls are healthy connectivity observations.
- Persist suspected gap intervals. A zero-cursor snapshot cannot promise recovery of retained-out events, and archive ingestion may not reconstruct everything seen in Console.

Extend the existing scheduler health check to watch the live worker, so the worker does not have to report its own death. A host-wide outage also needs an external uptime check; an entirely stopped deployment cannot send its own email.

**Exit gate:** restarts, reused keys, replayed snapshots, malformed payloads, database failures and a second worker cannot silently advance checkpoints past uncommitted events or duplicate established observations.

## 3. Introduce source-aware activity and evidence

Keep existing archived `events` intact initially. Add conceptual tables (final names chosen during implementation):

| Table | Purpose |
|---|---|
| `live_observations` | Raw payload, fingerprint, key, tenant/endpoint, event time, receipt time and mapping version |
| `live_activity` | Validated operation, stage, outcome, actor, IP, document/version, client when available, and raw-observation reference |
| `live_collector_state` | Cursor, ownership, heartbeat, health and gap information |
| `detection_state` | Durable per-rule progress and open alert episodes |
| `finding_evidence` | Explicit links to live or archived evidence without fabricating archive DocNos |
| `event_correlations` | Candidate/confirmed live-to-archive links, confidence and reasons |
| `notification_outbox` | Pending delivery, attempts, retry time and delivery status |

Every identity and relationship is tenant scoped. Store event time in UTC after validating timestamp interpretation, retain the original timestamp, and record receipt time separately. Use event time for activity windows, receipt time for freshness/latency and durable ingestion order for processing checkpoints. Unknown outcomes and stages must not become successful activity by default.

Use event-triggered rolling windows with enough prior context for each rule, including across midnight. Re-evaluate late arrivals and mark delayed findings appropriately. Persist window/episode state or reconstruct it from durable activity after restart. Startup replay should yield historical findings, not a flood of “happening now” notifications; fresh, ongoing suspicious activity should still alert.

## 4. Implement the first security rules

These thresholds are **pilot starting points**, not validated security standards. Expose them per tenant and tune them against observed normal activity.

| Rule | Proposed trigger | Counting and interpretation |
|---|---|---|
| Repeated login failures | 5 confirmed credential failures for one account in 15 minutes | Keep token expiry and licence exhaustion separate |
| Password spray | One IP fails against 3 distinct accounts in a rolling 60 minutes | The existing implementation groups by clock hour; adapt it to a genuine rolling window |
| Success after failures | Successful login within 2 hours of at least 2 credential failures for that account | Same IP strengthens the association; a changed IP is context, not proof of compromise |
| Retrieval burst | 100 distinct documents retrieved by one user in 5 minutes | Count validated successful completions; distinct document IDs, not versions or stage rows |
| Retrieval anomaly | 200 distinct documents in 15 minutes and more than 5× the user's comparable-window 95th percentile | Enable only after enough comparable live history; suggested warm-up is 14 healthy days |

For retrieval findings, include unique-document count, total completed retrievals, time range, IPs, available client/category context, baseline and sample document IDs. A repeated-read loop may create high request volume but low unique-document volume: expose it as a separate operational signal. Do not claim downloaded bytes or exfiltration unless independently supported.

Compare baselines using the same event source, completion semantics and window definition. Archived history can enrich user/IP context immediately, but should not supply retrieval-rate baselines unless coverage and count equivalence are validated. Exclude known gap intervals from baseline training and avoid automatically learning confirmed incidents as normal behaviour.

Distinguish indexing and integration activity through validated actor/client context. Prefer rule-specific, time-bounded exceptions and separate service-account thresholds. Existing blanket known-user/IP suppression must be reviewed for the live security rules: a familiar account or network must not automatically hide every security anomaly. Retain suppressed evidence and record the reason.

### Bulk API activity and approved workloads

User requirement: distinguish legitimate bulk API calls/extraction from unexpected activity and let the operator filter legitimate workloads out of the alert queue. Approval applies to a defined workload, not unrestricted trust in an account.

Monitor two separate dimensions:

- **Observed API activity rate:** validated API-associated operations per rolling window, grouped by account and available source/client context. Separate operation types and failures. Do not call this an exact HTTP request count: Console coverage is incomplete, and Connect/Disconnect pairs or stage messages are not independent requests. Establish the relationship with actual API traffic during the pilot; exact request accounting requires an additional authoritative request-log source if Console cannot provide it.
- **Extraction indicators:** distinct successfully retrieved documents, total completed retrievals and breadth of access where context is available. Searching/index reads and document-content retrieval are different behaviours. Do not infer bytes transferred or successful exfiltration from message counts.

Attribute activity to API only when the message or a validated session association supports it. A shared username or nearby API Connect row alone is insufficient to label every operation API traffic. Keep unattributed retrievals eligible for general security detection.

Add an **Approved activity** dashboard page and an **Approve this workload** action on a finding. The action prepares an editable exception from the actual evidence; the operator reviews its scope before saving. Available fields:

| Field | Behaviour |
|---|---|
| Tenant and name | Mandatory scope and human-readable integration/job name |
| Account | Required for the initial exception model; prefer dedicated integration accounts |
| Source IP/CIDR | Optional additional restriction; shared NAT addresses do not identify a workload by themselves |
| Client and operations | Validated API client context and explicit allowed activities, e.g. retrieval rather than all actions |
| Document/category scope | Optional only when reliably present or resolved; missing context must not satisfy the restriction |
| Schedule and expiry | One-off window or recurring schedule in a named timezone, with DST handling; ongoing approval must be explicit |
| Volume limits | Expected maximum observed activity and distinct retrieval volume per configured window |
| Rule scope | Bulk-activity rules affected; approval must not suppress credential attacks, deletion or unrelated security rules |
| Owner and reason | Accountability and rationale, recorded with creator, changes and review/expiry date |

All configured conditions must match. Missing required fields mean no match, not a wildcard. Define identity matching and IP/CIDR parsing explicitly. Evaluate schedule and volume against activity event time, including delayed archive evidence. For overlapping approvals, use a deterministic policy and record the matched exception; never add their permitted volumes together implicitly.

An approved workload remains collected and auditable, but its in-scope bulk findings are marked **Expected activity** and excluded from immediate bulk alerts and the default actionable queue. A dashboard toggle includes expected activity, with the exception name/reason and observed counts. Evidence exports and coverage reporting retain it. A new exception does not silently rewrite historical verdicts; any retrospective application is an explicit audited action.

If the account operates outside the approved IP, operation, schedule or scope, ordinary rules apply. If its permitted volume is exceeded, evaluate the full matching workload window and raise an **Approved workload exceeded limits** finding; do not count only the excess tail. Show which condition was breached. For IP/context changes, identify deviations where evidence permits without claiming they prove malicious use.

Example: approve a named overnight integration's retrievals from a specified source network between 01:00 and 03:00 Australia/Sydney, with an operator-selected distinct-document limit. Its expected overnight volume is retained but filtered from the bulk alert queue. Daytime retrieval, an unexpected source, or volume above its limit remains detectable. The numbers and account/network must come from the actual workload, not a guessed global allowlist.

Pilot this with one normal integration run and offline variants that change IP, time, operation, missing context and volume. Test exception expiry, overlapping approvals, DST transitions, aggregate threshold crossing and preservation of unrelated login alerts. Include approved high-volume runs in capacity tests even though they generate no bulk notifications.

Add mass deletion, rapid index changes, new-IP context and suspicious multi-step sequences after core rule validation. Do not wait for these additions before shipping useful login/retrieval alerts.

**Exit gate:** deterministic fixture tests cover threshold boundaries, started/completed pairs, replay, repeated versus distinct documents, licence/token failures, unknown outcomes, service activity, cross-midnight windows, delayed data and tenant isolation.

## 5. Deliver useful alerts without flooding

Use dashboard findings and existing SMTP configuration for the first release. Add Teams or other channels later through the same delivery interface.

- Open one episode per tenant/rule/subject when its threshold is crossed. Subsequent qualifying activity updates that episode instead of creating an alert every 10 seconds.
- Pilot defaults: close the active episode after 30 minutes without new qualifying activity; permit a new alert for a new episode. Send a material escalation at most once per 15 minutes when severity increases or the previous notified count doubles. Keep review status separate from activity state.
- Store finding changes and outbox entries atomically. Claim delivery work safely, retry with backoff, and expose failures. Database deduplication prevents routine repeats; SMTP cannot guarantee exactly-once receipt after an ambiguous send failure.
- Include what happened, when, the rule threshold, source/coverage status, user/IP, representative evidence and a dashboard link. Describe suspected bulk retrieval as suspicious activity, not a confirmed breach.
- Respect explicit rule-specific suppressions. Provide investigation, acknowledgement and time-bounded snooze controls. Log changes to thresholds and exclusions through the existing admin audit trail.
- Run LLM triage asynchronously with existing redaction, and do not silently retract or rewrite the original alert. Preserve rule severity and human decisions separately.

Use short-lived security episodes rather than the existing user/day incident grouping as the notification identity. Related rules can be linked for investigation without merging unrelated incidents solely because they share a user and date.

**Exit gate:** one simulated attack episode produces one initial alert, justified escalation only, durable retry after delivery failure, and no duplicate initial alert when the same evidence is replayed.

## 6. Reconcile archives and preserve broader audit coverage

Continue the existing scheduled archive collector and archive rules. When an archive arrives, compare compatible observations using tenant, operation, actor, document, calibrated time tolerance and available outcome/node context. Never equate Console Key with a log document number, or assume an identical timestamp uniquely identifies an action.

Link clear matches and retain both originals. Ambiguous matches remain candidates. Until an event class has a reliable counting model, report live and archive counts separately rather than sum them. Run source-specific detection and reconcile incidents; do not let inserting live rows accidentally change existing all-source SQL counts.

Archive arrival enriches existing incidents without reopening a reviewed finding or resending its initial notification. New material archive-only evidence can escalate an incident or create a retrospective finding, labelled with event time and detection delay. An unmatched live observation remains valid evidence; archive absence is not proof that it was false.

Keep archive freshness and live collector health visible independently. Read the actual archive configuration and account for quiet tenants and late publication. The user's current screenshot shows daily at 19:00; do not hardcode the older 17:00 observation.

## 7. Pilot, measure and roll out

1. Enable one tenant in shadow mode and establish core event coverage, protocol permissions and recovery behaviour.
2. Replay synthetic attacks against isolated test data; compare candidate findings with operator expectations. DB tests must use a disposable test database, never the production auditor database.
3. Enable validated failed-login, success-after-failure and fixed retrieval-burst alerts. Baseline-dependent rules remain disabled until warm-up completes.
4. Measure event-to-receipt, receipt-to-finding, finding-to-delivery latency, duplicate notifications, false positives, collection gaps, server load and storage growth. Report percentile latency and delivery failures, not just averages.
5. Set retention from measured volume; provisional starting policy is 30 days of raw live observations and 90 days of normalized activity, preserving evidence linked to findings beyond these periods. Make retention configurable before enabling multiple tenants.
6. Extend tenant by tenant with per-rule enablement and rollback controls. Turning live alerts off keeps archived auditing operational; collection-only mode remains available for diagnosis.
7. Add connector view-9 monitoring and further validated security rules as independent increments.

## Implementation map

| Area | Proposed change |
|---|---|
| `auditor/cli.py`, Compose | Live collector and notification worker commands/services |
| New `auditor/live/` package | Protocol adapter, durable collector, mapping and health |
| SQL migrations | Live storage, checkpoints, evidence links, correlation and outbox |
| `auditor/rules/` | Shared detection helpers and source-aware rolling security rules |
| `auditor/config.py`, rule settings schema, admin pages | Per-tenant live enablement, thresholds, recipients and structured approved-workload exceptions |
| `auditor/pipeline.py`, collector integration | Archive-arrival reconciliation; retain daily pipeline |
| `auditor/health.py` | Independent collector, evaluation and notification health checks |
| Dashboard and digest | Live incidents, provenance, coverage, alert status and reconciled evidence |
| Tests | Offline protocol fixtures, rule windows, recovery, reconciliation and delivery failures |

Completion means security alerts work without an open browser, validated activity is counted correctly, pipeline failures are visible, and later archives add evidence without inflating counts or repeating initial alerts. It does not mean the live feed covers every configured audit event.
