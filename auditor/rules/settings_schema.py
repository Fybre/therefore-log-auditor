"""Plain-language field definitions for each rule's tunable thresholds, used to render the
per-tenant rule settings page as real form fields instead of a raw JSON blob (nobody managing
a tenant day-to-day should need to know a rule's internal config keys like
"baseline_multiplier" to change its thresholds).

Note: new_entity's "kinds" (user/ip/admin_client) is deliberately NOT here. Excluding a kind
stops the rule creating that finding at all - no record, ever, even if you want to look back
later. What you actually want ("stop flagging new IPs for this tenant") belongs on the Known
Activity page instead (known.muted_kinds): the finding is still created and kept, just
auto-downgraded to info like a known-user match, so the history survives.

Each entry is (key, type, label, help). `key` must match the field name the rule itself reads
via ctx.cfg() in rules/builtin.py. Types: "int", "float", "userlist" (newline-separated values).
"""
from __future__ import annotations

RULE_FIELDS: dict[str, list[tuple[str, str, str, str]]] = {
    "brute_force": [
        ("window_minutes", "int", "Time window (minutes)",
         "How far back to count one user's failed logins."),
        ("min_failures_per_user", "int", "Failed logins to flag",
         "Failed logins by one user within the window before it's a possible brute force."),
        ("spray_window_minutes", "int", "Password-spray window (minutes)",
         "How far back to count one IP's failed logins across different users."),
        ("min_users_per_ip", "int", "Distinct users to flag a spray",
         "How many different usernames one IP must fail against within that window."),
    ],
    "success_after_failures": [
        ("lookback_minutes", "int", "Look-back window (minutes)",
         "How far back to check for failed logins before a successful one."),
        ("min_failures", "int", "Failed attempts to flag",
         "Failed logins right before a success, within the window, before it's flagged."),
    ],
    "new_entity": [
        ("warmup_days", "int", "Warm-up period (days)",
         "How much history is needed before \"first seen\" means anything - avoids flagging "
         "every existing user/IP on day one."),
        ("ignore_users", "userlist", "Never flag these usernames",
         "Service/system accounts that legitimately show up as \"new\" but aren't people."),
    ],
    "mass_delete": [
        ("min_per_day", "int", "Minimum deletes/day to flag",
         "Flag regardless of baseline once one user deletes at least this many documents in a day."),
        ("baseline_days", "int", "Baseline window (days)",
         "How many days of history are used to work out a user's normal delete rate."),
        ("baseline_multiplier", "float", "Flag at this many times the baseline",
         "Also flag if a day's deletes exceed the user's normal rate by this multiple."),
    ],
    "unplanned_restart": [
        ("window_minutes", "int", "Time window (minutes)", "How far back to count server restarts."),
        ("min_restarts", "int", "Restarts to flag", "Restarts within the window before it's flagged."),
    ],
    "log_gap": [
        ("max_hours_without_server_log", "int", "Hours without a log before flagging",
         "How long the Server log can go quiet before this is raised (checked live only, not during backfill)."),
    ],
    "recurring_failure": [
        ("min_days", "int", "Days it must recur", "The same failure must occur on at least this many days..."),
        ("lookback_days", "int", "...out of this many days", "...within this look-back window to count as recurring."),
        ("min_per_day", "int", "Minimum occurrences per day",
         "How many times the failure must happen on a day to count that day at all."),
    ],
    "retry_storm": [
        ("min_identical_per_day", "int", "Identical failures/day to flag",
         "The same failure repeated at least this many times in one day."),
    ],
    "config_drift": [],
    "licence_limit": [],
}

MUTABLE_KINDS = [
    ("new_entity:ip", "New IP addresses", "Keeps every \"new IP\" finding, but auto-downgrades "
     "it to info (like a known user/IP match) instead of leaving it open for review."),
]
