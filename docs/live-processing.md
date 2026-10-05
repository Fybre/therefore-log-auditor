# Incremental live processing

Ordinary polls process only new observations. Each tenant worker owns a disposable
`EvaluationCache`, protected by the existing database advisory lock. The durable evaluation
checkpoint remains in Postgres; collection and evaluation still commit independently.

`RollingDetector` keeps failure windows of 15/60/120 minutes and retrieval/API windows of
5 minutes. Ordered event queues expire entries at the exact open lower boundary of each
window. Counters track distinct documents and spray accounts without rescanning a user's
history. Only rule-relevant normalized events are retained, never raw message payloads.
Empty windows and their account/IP keys are removed as event time advances.

Approval partitions use the earliest matching approval and never combine allowances.
Changing, adding or revoking an approval rebuilds context before the next evaluation.
Threshold changes are applied on the next batch. Expected-activity and evidence semantics
match the original detector, including the last 100 supporting observations.

## Recovery and delayed data

- On startup, a missing cache rebuilds two hours of relevant event-time context.
- An out-of-order event rebuilds its historical context. The next batch rebuilds again
  before resuming incremental processing, so newer context is not lost.
- A backlog can contain rows beyond the 1,000-row batch whose timestamps fall inside
  that batch's window. These rows remain part of the context, matching previous behavior.
  Such batches use the rebuild path until normal chronological processing resumes.
- Exceptions discard the cache. A database checkpoint mismatch also invalidates it,
  including a transaction rollback after evaluation but before commit.
- Like the original implementation, delayed events trigger evaluation at their own
  timestamp; this does not retrospectively re-evaluate every already-processed future event.

## Database work

Ingestion inserts a poll in one batch and updates total/last-received/latest-event metrics
only for newly inserted rows. Duplicate snapshots cannot increase those totals. Evaluation
increments the evaluated-message count in the same transaction as findings and checkpoint.
The monitoring page reads these counters instead of scanning the observation history.

Snapshot key lookups use a composite index and one batched query. Candidate findings are
merged with existing episodes in memory; each changed episode is written once per batch,
preserving the original first/last timestamps and manual review metadata.

Migration 011 backfills counters from existing data. Stop the old live worker before applying
this migration, then start the upgraded web and live services; an old collector does not
maintain the new counters. Do not roll back to the old collector without rebuilding counters
before subsequently upgrading again.

## Validation

`tests/test_live_rolling.py` compares findings directly with the original `detect()` function,
which remains a reference implementation. It covers randomized mixed traffic, overlapping
approvals, expiry, time ties, distinct documents, exact window boundaries and evidence limits.
Database tests cover counters, duplicate snapshots, migration backfill, rollback, restart,
delayed batches, approval changes, backlog and equivalence to sequential finding persistence.

A local synthetic run of 3,000 API events over five minutes produced identical findings:
6.222 seconds for the reference detector and 0.015 seconds for rolling detection. This measures
Python detection only, not network latency, database work or production throughput.

Storage retention is unchanged: raw observations still accumulate until a separate retention
policy is implemented. This change reduces processing work, not historical storage growth.
