"""Postgres persistence. Callers own transactions and the per-tenant advisory lock."""
import datetime as dt
import hashlib
import json
from collections import defaultdict
from psycopg.types.json import Jsonb

from .detection import normalize
from .outbox import determine_alert, format_alert_email, parse_recipients
from .rolling import EvaluationCache, RollingDetector


def ingest(conn, tenant_id, endpoint, events, snapshot=False, timezone='UTC'):
    with conn.cursor() as cur:
        cur.execute('''INSERT INTO live_state(tenant_id,endpoint) VALUES (%s,%s)
                       ON CONFLICT DO NOTHING''', (tenant_id, endpoint))
        cur.execute('SELECT * FROM live_state WHERE tenant_id=%s FOR UPDATE', (tenant_id,))
        state = cur.fetchone()
        old = state['cursor'] if state['endpoint'] == endpoint else 0
        cursor = max((int(e['Key']) for e in events), default=0) if snapshot else old
        reset = snapshot and cursor < old
        previous = {}
        if snapshot and events:
            cur.execute('''SELECT DISTINCT ON (event_key) event_key,fingerprint FROM live_observations
                WHERE tenant_id=%s AND endpoint=%s AND event_key=ANY(%s)
                ORDER BY event_key,id DESC''', (tenant_id, endpoint, [int(e['Key']) for e in events]))
            previous = {r['event_key']: r['fingerprint'] for r in cur.fetchall()}
        batch = []
        for raw in events:
            payload = json.dumps(raw, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
            fingerprint = hashlib.sha256(payload.encode()).hexdigest()
            key = int(raw['Key'])
            if snapshot:
                reset |= key in previous and previous[key] != fingerprint
                previous[key] = fingerprint
            activity = normalize(raw, timezone)
            batch.append(dict(fingerprint=fingerprint, event_key=key, payload=raw,
                              activity=activity, event_time=activity['time']))
            cursor = max(cursor, key)
        if batch:
            # The returned rows exclude conflicts: retries cannot inflate totals.
            cur.execute('''WITH inserted AS (
                INSERT INTO live_observations
                    (tenant_id,endpoint,fingerprint,event_key,payload,activity,event_time)
                SELECT %s,%s,x.* FROM jsonb_to_recordset(%s) AS x(
                    fingerprint text,event_key bigint,payload jsonb,activity jsonb,event_time timestamptz)
                ON CONFLICT DO NOTHING RETURNING received_at,event_time
            ), totals AS (
                SELECT count(*) AS n,max(received_at) AS received,max(event_time) AS event FROM inserted
            ) UPDATE live_state SET total_messages=total_messages+totals.n,
                last_received=greatest(last_received,totals.received),
                latest_event=greatest(latest_event,totals.event)
              FROM totals WHERE tenant_id=%s''', (tenant_id, endpoint, Jsonb(batch), tenant_id))
        cur.execute('''UPDATE live_state SET endpoint=%s,cursor=%s,last_poll=now(),last_error=NULL,
                       resets=resets+%s WHERE tenant_id=%s''', (endpoint, cursor, int(reset), tenant_id))
    return cursor


# Context rows only need to include events that can participate in a rule.
_RELEVANT = """(activity->>'outcome' = 'credential_failure' OR
    (activity->>'outcome' = 'success' AND (activity->>'operation' = 'connect' OR
      (activity->>'stage' = 'completed' AND (activity->>'client' = 'api' OR
        (activity->>'operation' = 'retrieve' AND activity->>'document' IS NOT NULL))))))"""


def evaluate(conn, tenant_id, retrieval_limit=100, api_limit=500, cache=None, base_url=""):
    cache = cache if cache is not None else EvaluationCache()
    try:
        return _evaluate(conn, tenant_id, retrieval_limit, api_limit, cache, base_url)
    except Exception:
        cache.clear()
        raise


def _evaluate(conn, tenant_id, retrieval_limit, api_limit, cache, base_url=""):
    with conn.cursor() as cur:
        cur.execute('SELECT evaluated_id FROM live_state WHERE tenant_id=%s FOR UPDATE', (tenant_id,))
        state = cur.fetchone()
        if not state:
            cache.clear()
            return 0
        if cache.tenant_id != tenant_id or cache.checkpoint != state['evaluated_id']:
            cache.clear()
        cur.execute('''SELECT id,event_time,activity FROM live_observations WHERE tenant_id=%s AND id>%s
                       ORDER BY id LIMIT 1000''', (tenant_id, state['evaluated_id']))
        pending = cur.fetchall()
        if not pending:
            cur.execute('UPDATE live_state SET last_evaluation=now() WHERE tenant_id=%s', (tenant_id,))
            return 0
        valid = sorted((r for r in pending if r['event_time'] is not None), key=lambda r: (r['event_time'], r['id']))
        candidates = []
        if valid:
            lo, hi = valid[0]['event_time'], valid[-1]['event_time']
            cur.execute('SELECT * FROM live_approvals WHERE tenant_id=%s AND revoked_at IS NULL ORDER BY id',
                        (tenant_id,))
            approvals = cur.fetchall()
            # Original semantics include already-ingested rows beyond this batch that
            # fall inside its event-time range. Rebuild for this uncommon backlog case.
            cur.execute('''SELECT EXISTS(SELECT 1 FROM live_observations WHERE tenant_id=%s
                AND id>%s AND event_time BETWEEN %s AND %s) AS overlap''',
                        (tenant_id, pending[-1]['id'], lo-dt.timedelta(hours=2), hi))
            overlap = cur.fetchone()['overlap']
            detector = cache.detector
            late = (detector is not None and detector.last_order is not None
                    and (lo, valid[0]['id']) <= detector.last_order)
            rebuild = detector is None or approvals != detector.approvals or overlap or late
            if rebuild:
                detector = RollingDetector(approvals)
                cur.execute(f'''SELECT id,event_time,activity FROM live_observations WHERE tenant_id=%s
                    AND event_time BETWEEN %s AND %s AND {_RELEVANT} ORDER BY event_time,id''',
                            (tenant_id, lo-dt.timedelta(hours=2), hi))
                events = cur.fetchall()
            else:
                events = valid
            new_ids = {r['id'] for r in valid}
            for event in events:
                candidates.extend(detector.feed(event, event['id'] in new_ids, retrieval_limit, api_limit))
            # A historical rebuild stops at its own hi, leaving previously processed
            # newer context outside the window. Rebuild again before resuming live time.
            cache.detector = None if overlap or late else detector
        _save_findings(cur, tenant_id, candidates, base_url)
        cur.execute('''UPDATE live_state SET evaluated_id=%s,evaluated_messages=evaluated_messages+%s,
                       last_evaluation=now() WHERE tenant_id=%s''',
                    (pending[-1]['id'], len(pending), tenant_id))
        cache.tenant_id, cache.checkpoint = tenant_id, pending[-1]['id']
    return len(pending)


def _save_findings(cur, tenant_id, candidates, base_url=""):
    """Apply the existing episode semantics in memory, writing each changed row once."""
    if not candidates:
        return

    cur.execute('SELECT alerting_enabled,alert_recipients,alerting_enabled_at,enabled FROM live_settings WHERE tenant_id=%s', (tenant_id,))
    lset = cur.fetchone() or {'alerting_enabled': False, 'alert_recipients': '', 'enabled':False}
    alerting_enabled = bool(lset['alerting_enabled'] and lset['enabled'])
    cur.execute('SELECT now() AS now')
    now = cur.fetchone()['now']

    recipients = []
    if alerting_enabled:
        cur.execute('SELECT digest_email_to,enabled FROM tenants WHERE id=%s', (tenant_id,))
        t_row = cur.fetchone()
        digest_to = t_row['digest_email_to'] if t_row and t_row['digest_email_to'] else []
        try:
            recipients = parse_recipients(lset.get('alert_recipients', ''), digest_to) if t_row and t_row['enabled'] else []
        except ValueError:
            recipients = []  # Invalid legacy digest configuration must not stop collection.
        cur.execute("SELECT value->>'dashboard_url' AS url FROM app_settings WHERE key='general'")
        general = cur.fetchone()
        base_url = (general['url'] if general else '') or base_url

    cur.execute('''SELECT id,rule_id,subject,expected,approval_id,first_ts,last_ts,
                          last_alert_ts,last_alert_count,last_alert_severity,alert_count FROM live_findings
        WHERE tenant_id=%s AND last_ts >= %s AND first_ts <= %s ORDER BY last_ts DESC,id DESC''',
        (tenant_id, min(f['last_ts'] for f in candidates)-dt.timedelta(minutes=30),
         max(f['last_ts'] for f in candidates)))
    groups, changed = defaultdict(list), {}
    def key(f):
        return f['rule_id'], f['subject'], f['expected'], f['approval_id']
    for row in cur.fetchall():
        groups[key(row)].append(row)
    for finding in candidates:
        rows = groups[key(finding)]
        eligible = [r for r in rows if r['last_ts'] >= finding['last_ts']-dt.timedelta(minutes=30)
                    and r['first_ts'] <= finding['last_ts']]
        old = max(eligible, key=lambda r: r['last_ts']) if eligible else None
        if old is None:
            old = {**finding, 'id': -(len(changed)+1), 'alert_count': 0,
                   'last_alert_ts': None, 'last_alert_count': None, 'last_alert_severity': None}
            rows.append(old)
        elif old['last_ts'] > finding['last_ts']:
            continue
        first_ts = min(old['first_ts'], finding['first_ts'])
        old.update(finding, first_ts=first_ts)

        changed[old['id']] = old

    for finding_id, f in changed.items():
        fresh = (now-dt.timedelta(minutes=5) <= f['last_ts'] <= now+dt.timedelta(minutes=5)
                 and (not lset.get('alerting_enabled_at') or f['last_ts'] >= lset['alerting_enabled_at']))
        queue_alert = determine_alert(f, f, now) if alerting_enabled and recipients and fresh else None
        if queue_alert:
            f.update(last_alert_ts=now, last_alert_count=f['details']['count'],
                     last_alert_severity=queue_alert[1], alert_count=f.get('alert_count', 0)+1)
        if finding_id > 0:
            cur.execute('''UPDATE live_findings SET first_ts=%s,last_ts=%s,
                details=%s || CASE WHEN details ? 'manual_review' THEN
                jsonb_build_object('manual_review', details->'manual_review') ELSE '{}'::jsonb END,
                evidence_ids=%s, last_alert_ts=%s, last_alert_count=%s,
                last_alert_severity=%s, alert_count=%s, updated_at=now() WHERE id=%s''',
                (f['first_ts'], f['last_ts'], Jsonb(f['details']), f['evidence_ids'],
                 f.get('last_alert_ts'), f.get('last_alert_count'), f.get('last_alert_severity'),
                 f.get('alert_count', 0), finding_id))
            target_id = finding_id
        else:
            cur.execute('''INSERT INTO live_findings
                (tenant_id,rule_id,subject,first_ts,last_ts,expected,approval_id,details,evidence_ids,
                 last_alert_ts,last_alert_count,last_alert_severity,alert_count)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id''',
                (tenant_id, f['rule_id'], f['subject'], f['first_ts'], f['last_ts'],
                 f['expected'], f['approval_id'], Jsonb(f['details']), f['evidence_ids'],
                 f.get('last_alert_ts'), f.get('last_alert_count'), f.get('last_alert_severity'),
                 f.get('alert_count', 0)))
            target_id = cur.fetchone()['id']

        if queue_alert and recipients:
            alert_type, sev = queue_alert
            cur.execute('''SELECT activity FROM live_observations WHERE tenant_id=%s AND id=ANY(%s)
                           ORDER BY event_time DESC,id DESC LIMIT 100''', (tenant_id, f['evidence_ids']))
            evidence = [r['activity'] for r in cur.fetchall()]
            details = {**f['details'],
                       'source_ips':sorted({a['ip'] for a in evidence if a.get('ip')}),
                       'documents':sorted({a['document'] for a in evidence if a.get('document') is not None})[:10]}
            subj, b_text, b_html = format_alert_email(
                tenant_id, target_id, f['rule_id'], f['subject'], details,
                f['first_ts'], f['last_ts'], alert_type, sev, base_url
            )
            cur.execute('''INSERT INTO live_outbox
                (tenant_id, finding_id, alert_type, severity, recipients, subject, body_text, body_html)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)''',
                (tenant_id, target_id, alert_type, sev, recipients, subj, b_text, b_html))
