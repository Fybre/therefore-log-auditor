# Live security notifications

Automatic emails are disabled by default per tenant. Enable them under tenant Live monitoring
settings after saving custom recipients (commas/new lines), or use the tenant's digest recipients.
Collection and the tenant itself must also be enabled. SMTP settings are shared with daily digests.
Configuration changes and explicit test requests are recorded in the admin audit log.

The test button queues a clearly labelled test email using saved recipients. It works with automatic
alerting disabled. It does not wait for SMTP: the live worker dispatcher attempts delivery on its
next cycle, ordinarily within five seconds when the queue is empty.

## Episodes and freshness

- Findings and email queue entries commit atomically with the evaluation checkpoint.
- Each changed episode is considered for notification once per evaluation batch, using its final
  count and severity. Alert metadata records queued notifications, not confirmed delivery.
- Initial qualifying activity queues one initial alert. Routine updates do not resend it.
- An escalation requires 15 minutes of wall-clock time since the last queued alert and either
  a doubled count or increased severity. Login rules are high severity. Bulk rules are medium,
  rising to high at five times their configured limit; these are pilot heuristics.
- Existing episode grouping starts a new episode after more than 30 minutes without qualifying activity.
- Expected findings never queue automatic alerts. Pending alerts are checked again before delivery
  in case the finding was subsequently marked expected or collection/alerting was disabled.
- Only activity at or after the last opt-in time and within five minutes of the current clock can
  alert. Older replay remains visible as findings. Fresh ongoing activity can alert an episode that
  began in shadow mode. Correct tenant log timezone and synchronized clocks remain necessary.
- Late or retried deliveries are clearly dated with the original activity times; an SMTP outage
  does not erase an already queued alert. Re-enabling notifications invalidates older queued
  automatic alerts from the previous opt-in period.

## Delivery and recovery

A separate dispatcher connection claims exactly one due outbox row with `FOR UPDATE SKIP LOCKED`.
It retains that row lock throughout SMTP delivery and the final status update, and commits before
claiming another row. Other dispatchers can work on other rows without sending that locked row.
The dispatcher does not lock observation, checkpoint or finding rows, so a slow SMTP server does
not block collection/evaluation. Empty checks also end their transactions.

Each SMTP call uses the existing 30-second socket timeout. A failed or missing SMTP configuration
increments attempts and schedules exponential retries after 30, 60, 120 and 240 seconds; the fifth
failed attempt exhausts automatic retries. Error history exposes error classes/status codes rather
than potentially sensitive SMTP response bodies. Successful attempts are counted too.

Delivery status is pending, sent, failed (retry scheduled or exhausted), or cancelled. Sent means
the SMTP call completed successfully; it does not prove the recipient read or received the email.
SMTP cannot promise exactly-once delivery: if it accepts a message and the connection/process fails
before Postgres commits, a retry may deliver a duplicate. A crash releases the row lock so another
dispatcher can retry. Restarting the worker resumes the durable queue.

The current dispatcher keeps the sending transaction open, so its committed status remains pending
until delivery finishes. Disable/approval changes cannot recall a send already in progress.

## Validation

Unit tests cover initial alerts, escalation cooldown/count/severity, expected activity, recipients,
email escaping, direct evidence links and backoff. Isolated Postgres tests cover atomic rollback,
batch coalescing, replay/freshness, new episodes, concurrent dispatchers, retries/exhaustion,
configuration/approval cancellation, UI validation, test queuing, audit logging and tenant scope.
SMTP is mocked throughout; automated validation sends no real emails.
