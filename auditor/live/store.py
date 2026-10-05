"""Postgres persistence. Callers own transactions and the per-tenant advisory lock."""
import datetime as dt
import hashlib
import json
from collections import defaultdict
from psycopg.types.json import Jsonb

from .detection import normalize
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


def evaluate(conn, tenant_id, retrieval_limit=100, api_limit=500, cache=None):
    cache = cache if cache is not None else EvaluationCache()
    try:
        return _evaluate(conn, tenant_id, retrieval_limit, api_limit, cache)
    except Exception:
        cache.clear()
        raise


def _evaluate(conn, tenant_id, retrieval_limit, api_limit, cache):
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
        _save_findings(cur, tenant_id, candidates)
        cur.execute('''UPDATE live_state SET evaluated_id=%s,evaluated_messages=evaluated_messages+%s,
                       last_evaluation=now() WHERE tenant_id=%s''',
                    (pending[-1]['id'], len(pending), tenant_id))
        cache.tenant_id, cache.checkpoint = tenant_id, pending[-1]['id']
    return len(pending)


def _save_findings(cur, tenant_id, candidates):
    """Apply the existing episode semantics in memory, writing each changed row once."""
    if not candidates:
        return
    cur.execute('''SELECT id,rule_id,subject,expected,approval_id,first_ts,last_ts FROM live_findings
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
            old = {**finding, 'id': -(len(changed)+1)}
            rows.append(old)
        elif old['last_ts'] > finding['last_ts']:
            continue
        first_ts = min(old['first_ts'], finding['first_ts'])
        old.update(finding, first_ts=first_ts)
        changed[old['id']] = old
    for finding_id, f in changed.items():
        if finding_id > 0:
            cur.execute('''UPDATE live_findings SET first_ts=%s,last_ts=%s,
                details=%s || CASE WHEN details ? 'manual_review' THEN
                jsonb_build_object('manual_review', details->'manual_review') ELSE '{}'::jsonb END,
                evidence_ids=%s,updated_at=now() WHERE id=%s''',
                (f['first_ts'], f['last_ts'], Jsonb(f['details']), f['evidence_ids'], finding_id))
        else:
            cur.execute('''INSERT INTO live_findings
                (tenant_id,rule_id,subject,first_ts,last_ts,expected,approval_id,details,evidence_ids)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (tenant_id, f['rule_id'], f['subject'], f['first_ts'], f['last_ts'],
                 f['expected'], f['approval_id'], Jsonb(f['details']), f['evidence_ids']))
