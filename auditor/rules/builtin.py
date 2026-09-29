"""Built-in detection rules. Each takes a Context and returns Findings for events in [start, end)."""
from __future__ import annotations

import datetime as dt
import re

from .engine import Context, Finding, rule, short_hash, template

FAILED_CONNECT = "action='Connect' AND success = false AND NOT (result_code = ANY(%(ignore)s))"


def _day(ts: dt.datetime) -> str:
    return ts.date().isoformat()


@rule("brute_force")
def brute_force(ctx: Context) -> list[Finding]:
    c = ctx.cfg("brute_force")
    ignore = c.get("ignore_result_codes", [])
    out: list[Finding] = []
    # 1) Many failures for one user within a sliding window
    rows = ctx.q(f"""
        WITH f AS (
            SELECT id, ts, username, ip,
                   count(*) OVER (PARTITION BY lower(username) ORDER BY ts
                                  RANGE BETWEEN %(win)s PRECEDING AND CURRENT ROW) AS n
            FROM events
            WHERE tenant_id=%(tenant)s AND ts >= %(start)s AND ts < %(end)s AND {FAILED_CONNECT}
              AND username IS NOT NULL AND username <> '')
        SELECT lower(username) AS u, ts::date AS day, max(n) AS peak, min(ts) AS first, max(ts) AS last,
               array_agg(id ORDER BY ts) AS ids, array_agg(DISTINCT ip) FILTER (WHERE ip IS NOT NULL) AS ips,
               count(*) AS total
        FROM f GROUP BY 1, 2 HAVING max(n) >= %(min)s""",
        {"ignore": ignore, "win": dt.timedelta(minutes=c["window_minutes"]), "min": c["min_failures_per_user"]})
    for r in rows:
        out.append(Finding(
            rule_id="brute_force", dedupe_key=f"user:{r['u']}:{r['day']}",
            title=f"Repeated failed logins for {r['u']} ({r['total']} on {r['day']})",
            severity=c["severity"], first_ts=r["first"], last_ts=r["last"],
            details={"user": r["u"], "day": str(r["day"]), "failures": r["total"],
                     "peak_in_window": r["peak"], "window_minutes": c["window_minutes"], "ips": r["ips"] or []},
            evidence_ids=r["ids"], subject_users=[r["u"]], subject_ips=r["ips"] or []))
    # 2) One IP failing against several users (password spray)
    rows = ctx.q(f"""
        SELECT ip, date_trunc('hour', ts) AS hr, count(DISTINCT lower(username)) AS users,
               array_agg(DISTINCT lower(username)) AS unames, min(ts) AS first, max(ts) AS last,
               array_agg(id ORDER BY ts) AS ids
        FROM events
        WHERE tenant_id=%(tenant)s AND ts >= %(start)s AND ts < %(end)s AND {FAILED_CONNECT}
          AND ip IS NOT NULL AND username IS NOT NULL
        GROUP BY 1, 2 HAVING count(DISTINCT lower(username)) >= %(min)s""",
        {"ignore": ignore, "min": c["min_users_per_ip"]})
    for r in rows:
        out.append(Finding(
            rule_id="brute_force", dedupe_key=f"spray:{r['ip']}:{r['hr']:%Y-%m-%dT%H}",
            title=f"Password spray: {r['ip']} failed against {r['users']} users",
            severity=c["severity"], first_ts=r["first"], last_ts=r["last"],
            details={"ip": r["ip"], "users": r["unames"], "hour": r["hr"].isoformat()},
            evidence_ids=r["ids"], subject_users=r["unames"], subject_ips=[r["ip"]]))
    return out


@rule("success_after_failures")
def success_after_failures(ctx: Context) -> list[Finding]:
    c = ctx.cfg("success_after_failures")
    rows = ctx.q(f"""
        SELECT s.id, s.ts, lower(s.username) AS u, s.ip, s.host, s.client,
               (SELECT array_agg(f.id ORDER BY f.ts) FROM events f
                 WHERE f.tenant_id=s.tenant_id AND lower(f.username)=lower(s.username)
                   AND f.ts < s.ts AND f.ts >= s.ts - %(look)s AND {FAILED_CONNECT.replace('action', 'f.action').replace('success', 'f.success').replace('result_code', 'f.result_code')}
               ) AS fails
        FROM events s
        WHERE s.tenant_id=%(tenant)s AND s.ts >= %(start)s AND s.ts < %(end)s
          AND s.action='Connect' AND s.success AND s.username IS NOT NULL""",
        {"ignore": c.get("ignore_result_codes", []), "look": dt.timedelta(minutes=c["lookback_minutes"])})
    out: list[Finding] = []
    seen: set[str] = set()
    for r in rows:
        fails = r["fails"] or []
        if len(fails) < c["min_failures"]:
            continue
        key = f"{r['u']}:{_day(r['ts'])}"
        if key in seen:        # one finding per user per day; first success wins
            continue
        seen.add(key)
        out.append(Finding(
            rule_id="success_after_failures", dedupe_key=key,
            title=f"{r['u']} logged in after {len(fails)} failed attempts",
            severity=c["severity"], first_ts=r["ts"], last_ts=r["ts"],
            details={"user": r["u"], "ip": r["ip"], "host": r["host"], "client": r["client"],
                     "failures_before": len(fails), "lookback_minutes": c["lookback_minutes"]},
            evidence_ids=fails + [r["id"]], subject_users=[r["u"]], subject_ips=[r["ip"]] if r["ip"] else []))
    return out


@rule("new_entity")
def new_entity(ctx: Context) -> list[Finding]:
    c = ctx.cfg("new_entity")
    hist = ctx.q("SELECT min(ts) AS t FROM events WHERE tenant_id=%(tenant)s AND source='server'")
    hist_start = hist[0]["t"] if hist else None
    if hist_start is None:
        return []
    warm_until = hist_start + dt.timedelta(days=c["warmup_days"])
    private = "(ip LIKE '10.%%' OR ip LIKE '192.168.%%' OR ip ~ '^172\\.(1[6-9]|2[0-9]|3[01])\\.')"
    # kind -> (value expression, filter)
    specs = {
        "user": ("lower(username)", "username IS NOT NULL AND username <> '' AND success"
                 " AND NOT (lower(username) = ANY(%(ignore)s))"),
        "ip": ("ip", f"ip IS NOT NULL AND NOT {private}"),
        "admin_client": ("lower(username) || ' via ' || client",
                         "client = ANY(%(admin)s) AND success AND username IS NOT NULL"
                         " AND NOT (lower(username) = ANY(%(ignore)s))"),
    }
    ignore = [u.lower() for u in c.get("ignore_users", [])]
    labels = {"user": "New user", "ip": "New IP address", "admin_client": "First admin-tool use"}
    out: list[Finding] = []
    for kind in c.get("kinds", list(specs)):
        expr, cond = specs[kind]
        base = f"FROM events WHERE tenant_id=%(tenant)s AND source='server' AND {cond}"
        rows = ctx.q(f"""
            SELECT v, first_seen FROM (SELECT {expr} AS v, min(ts) AS first_seen {base} GROUP BY 1) f
            WHERE first_seen >= %(start)s AND first_seen < %(end)s AND first_seen >= %(warm)s""",
            {"admin": c.get("admin_clients", []), "warm": warm_until, "ignore": ignore})
        for r in rows:
            ev = ctx.q(f"""SELECT id, ip, lower(username) AS u {base} AND {expr} = %(v)s
                           AND ts >= %(fs)s AND ts < %(fs)s + interval '1 day' ORDER BY ts LIMIT 50""",
                       {"admin": c.get("admin_clients", []), "v": r["v"], "fs": r["first_seen"], "ignore": ignore})
            ips = sorted({e["ip"] for e in ev if e["ip"]})
            users = sorted({e["u"] for e in ev if e["u"]})
            out.append(Finding(
                rule_id="new_entity", dedupe_key=f"{kind}:{r['v']}", title=f"{labels[kind]}: {r['v']}",
                severity={"admin_client": c["admin_severity"], "ip": c.get("ip_severity", c["severity"])}.get(kind, c["severity"]),
                first_ts=r["first_seen"], last_ts=r["first_seen"],
                details={"kind": kind, "value": r["v"], "first_seen": r["first_seen"].isoformat(),
                         "ips": ips, "users": users},
                evidence_ids=[e["id"] for e in ev], subject_users=users, subject_ips=ips))
    return out


@rule("mass_delete")
def mass_delete(ctx: Context) -> list[Finding]:
    c = ctx.cfg("mass_delete")
    rows = ctx.q("""
        WITH day AS (
            SELECT lower(username) AS u, ts::date AS d, count(*) AS n, min(ts) AS first, max(ts) AS last,
                   (array_agg(id ORDER BY ts))[1:100] AS ids, array_agg(DISTINCT category) AS cats
            FROM events
            WHERE tenant_id=%(tenant)s AND ts >= %(start)s AND ts < %(end)s
              AND action='Doc Delete' AND success
            GROUP BY 1, 2)
        SELECT day.*, coalesce((
            SELECT count(*)::float / %(bdays)s FROM events b
            WHERE b.tenant_id=%(tenant)s AND lower(b.username)=day.u AND b.action='Doc Delete' AND b.success
              AND b.ts >= day.d - %(bdays)s * interval '1 day' AND b.ts < day.d), 0) AS baseline
        FROM day""", {"bdays": c["baseline_days"]})
    out: list[Finding] = []
    for r in rows:
        threshold = max(c["min_per_day"], c["baseline_multiplier"] * r["baseline"])
        if r["n"] < threshold:
            continue
        out.append(Finding(
            rule_id="mass_delete", dedupe_key=f"{r['u']}:{r['d']}",
            title=f"Mass delete: {r['u']} deleted {r['n']} documents on {r['d']}",
            severity=c["severity"], first_ts=r["first"], last_ts=r["last"],
            details={"user": r["u"], "day": str(r["d"]), "deletes": r["n"],
                     "baseline_per_day": round(r["baseline"], 1), "categories": [x for x in r["cats"] if x][:20]},
            evidence_ids=r["ids"], subject_users=[r["u"]]))
    return out


@rule("unplanned_restart")
def unplanned_restart(ctx: Context) -> list[Finding]:
    c = ctx.cfg("unplanned_restart")
    rows = ctx.q("""
        WITH s AS (
            SELECT id, ts, count(*) OVER (ORDER BY ts RANGE BETWEEN %(win)s PRECEDING AND CURRENT ROW) AS n
            FROM events WHERE tenant_id=%(tenant)s AND ts >= %(start)s AND ts < %(end)s AND action='Server Start')
        SELECT ts::date AS d, max(n) AS peak, count(*) AS total, min(ts) AS first, max(ts) AS last,
               array_agg(id ORDER BY ts) AS ids
        FROM s GROUP BY 1 HAVING max(n) >= %(min)s""",
        {"win": dt.timedelta(minutes=c["window_minutes"]), "min": c["min_restarts"]})
    out = []
    for r in rows:
        # Who was connected to admin tools around the restarts? Useful context for triage.
        who = ctx.q("""SELECT DISTINCT lower(username) AS u, client, ip FROM events
                       WHERE tenant_id=%(tenant)s AND ts BETWEEN %(a)s AND %(b)s AND action='Connect' AND success
                         AND username IS NOT NULL""",
                    {"a": r["first"] - dt.timedelta(minutes=30), "b": r["last"] + dt.timedelta(minutes=5)})
        out.append(Finding(
            rule_id="unplanned_restart", dedupe_key=str(r["d"]),
            title=f"{r['total']} server restarts on {r['d']} (peak {r['peak']} within {c['window_minutes']} min)",
            severity=c["severity"], first_ts=r["first"], last_ts=r["last"],
            details={"day": str(r["d"]), "restarts": r["total"], "peak": r["peak"],
                     "connected_nearby": [dict(x) for x in who][:20]},
            evidence_ids=r["ids"]))
    return out


@rule("log_gap")
def log_gap(ctx: Context) -> list[Finding]:
    if not ctx.realtime:
        return []
    c = ctx.cfg("log_gap")
    rows = ctx.q("""SELECT max(fetched_at) AS fetched, max(last_ts) AS last_event, max(generated) AS gen
                    FROM log_files WHERE tenant_id=%(tenant)s AND application='Therefore Server' AND status='parsed'""")
    r = rows[0] if rows else None
    if not r or r["last_event"] is None:
        return []
    now = dt.datetime.now(dt.timezone.utc)
    age_h = (now - r["last_event"]).total_seconds() / 3600
    if age_h < c["max_hours_without_server_log"]:
        return []
    return [Finding(
        rule_id="log_gap", dedupe_key=f"since:{r['gen']}",
        title=f"No new Therefore Server log for {age_h:.0f} hours",
        severity=c["severity"], first_ts=r["last_event"], last_ts=now,
        details={"last_generated": str(r["gen"]), "last_event": r["last_event"].isoformat(),
                 "hours": round(age_h, 1)})]


@rule("config_drift")
def config_drift(ctx: Context) -> list[Finding]:
    c = ctx.cfg("config_drift")
    rows = ctx.q("""SELECT id, taken_at, settings FROM settings_snapshots
                    WHERE tenant_id=%(tenant)s AND taken_at < %(end)s ORDER BY taken_at DESC LIMIT 2""")
    if len(rows) < 2:
        return []
    new, old = rows[0], rows[1]
    if new["taken_at"] < ctx.start or new["settings"] == old["settings"]:
        return []
    changes = {}
    for k in sorted(set(new["settings"]) | set(old["settings"])):
        a, b = old["settings"].get(k), new["settings"].get(k)
        if a != b:
            changes[k] = {"before": a, "after": b}
    details = {"changes": changes, "previous_snapshot": old["taken_at"].isoformat()}
    if "700" in changes:
        before = re.findall(r"<V>(\d+)</V>", str(changes["700"]["before"] or ""))
        after = re.findall(r"<V>(\d+)</V>", str(changes["700"]["after"] or ""))
        details["logmask_positions_changed"] = [
            {"position": i, "before": x, "after": y}
            for i, (x, y) in enumerate(zip(before, after)) if x != y]
        details["logmask_levels_lowered"] = sum(1 for x, y in zip(before, after) if int(y) < int(x))
    return [Finding(
        rule_id="config_drift", dedupe_key=f"snapshot:{new['id']}",
        title="Server logging configuration changed" + (
            f" ({details.get('logmask_levels_lowered')} event(s) logging less)" if details.get("logmask_levels_lowered") else ""),
        severity=c["severity"], first_ts=old["taken_at"], last_ts=new["taken_at"], details=details)]


@rule("recurring_failure")
def recurring_failure(ctx: Context) -> list[Finding]:
    c = ctx.cfg("recurring_failure")
    lookback_start = ctx.end - dt.timedelta(days=c["lookback_days"])
    rows = ctx.q("""
        SELECT action, coalesce(lower(username), '') AS u, message, ts::date AS d, id, ts
        FROM events
        WHERE tenant_id=%(tenant)s AND ts >= %(ls)s AND ts < %(end)s AND success = false AND source='server'""",
        {"ls": max(lookback_start, ctx.start - dt.timedelta(days=c["lookback_days"]))})
    groups: dict[str, dict] = {}
    for r in rows:
        key = f"{r['action']}|{r['u']}|{template(r['message'])}"
        g = groups.setdefault(key, {"action": r["action"], "user": r["u"], "template": template(r["message"]),
                                    "days": {}, "ids": [], "first": r["ts"], "last": r["ts"], "sample": r["message"]})
        g["days"][r["d"]] = g["days"].get(r["d"], 0) + 1
        if len(g["ids"]) < 20:
            g["ids"].append(r["id"])
        g["first"], g["last"] = min(g["first"], r["ts"]), max(g["last"], r["ts"])
    out = []
    for g in groups.values():
        days = sorted(d for d, n in g["days"].items() if n >= c["min_per_day"])
        if len(days) < c["min_days"] or g["last"] < ctx.start:
            continue
        who = f" for {g['user']}" if g["user"] else ""
        out.append(Finding(
            rule_id="recurring_failure", dedupe_key=short_hash(g["action"], g["user"], g["template"]),
            title=f"Recurring failure{who}: {g['action']} on {len(days)} of the last {c['lookback_days']} days",
            severity=c["severity"], first_ts=g["first"], last_ts=g["last"],
            details={"action": g["action"], "user": g["user"], "message_template": g["template"],
                     "sample": (g["sample"] or "")[:500], "days": len(days),
                     "total": sum(g["days"].values()), "last_day": str(days[-1])},
            evidence_ids=g["ids"], subject_users=[g["user"]] if g["user"] else []))
    return out


@rule("retry_storm")
def retry_storm(ctx: Context) -> list[Finding]:
    c = ctx.cfg("retry_storm")
    rows = ctx.q("""
        SELECT ts::date AS d, action, lower(username) AS u, ip,
               regexp_replace(regexp_replace(coalesce(message,''), '\\d+', '#', 'g'), '\\s+', ' ', 'g') AS tpl,
               count(*) AS n, min(ts) AS first, max(ts) AS last, (array_agg(id ORDER BY ts))[1:50] AS ids
        FROM events
        WHERE tenant_id=%(tenant)s AND ts >= %(start)s AND ts < %(end)s AND success = false
        GROUP BY 1, 2, 3, 4, 5 HAVING count(*) >= %(min)s""", {"min": c["min_identical_per_day"]})
    return [Finding(
        rule_id="retry_storm", dedupe_key=f"{r['d']}:{short_hash(r['action'], r['u'], r['ip'], r['tpl'])}",
        title=f"Retry storm: {r['n']} identical '{r['action']}' failures from {r['u'] or r['ip'] or 'system'} on {r['d']}",
        severity=c["severity"], first_ts=r["first"], last_ts=r["last"],
        details={"day": str(r["d"]), "action": r["action"], "user": r["u"], "ip": r["ip"], "count": r["n"],
                 "message_template": r["tpl"][:300]},
        evidence_ids=r["ids"], subject_users=[r["u"]] if r["u"] else [], subject_ips=[r["ip"]] if r["ip"] else [])
        for r in rows]


@rule("licence_limit")
def licence_limit(ctx: Context) -> list[Finding]:
    c = ctx.cfg("licence_limit")
    rows = ctx.q("""
        SELECT ts::date AS d, count(*) AS n, min(ts) AS first, max(ts) AS last,
               (array_agg(id ORDER BY ts))[1:20] AS ids, (array_agg(message ORDER BY ts))[1] AS sample
        FROM events
        WHERE tenant_id=%(tenant)s AND ts >= %(start)s AND ts < %(end)s AND success = false
          AND message ~* 'licen[cs]e.*(limit|exceeded|in use)|license points'
        GROUP BY 1""")
    return [Finding(
        rule_id="licence_limit", dedupe_key=str(r["d"]),
        title=f"Licence limit hit {r['n']} times on {r['d']}",
        severity=c["severity"], first_ts=r["first"], last_ts=r["last"],
        details={"day": str(r["d"]), "count": r["n"], "sample": (r["sample"] or "")[:500]},
        evidence_ids=r["ids"]) for r in rows]
