"""Conservative Console mappings and source-specific shadow rules.

No inference from Oper's high bit or temporal proximity to an API login.
Unknown fields/outcomes remain unknown. Thresholds are pilot defaults.
"""
from __future__ import annotations

from collections import defaultdict
import datetime as dt
import ipaddress
import re
from zoneinfo import ZoneInfo

UTC = dt.timezone.utc
MAPPING_VERSION = 1
DOC = re.compile(r'\bDocNo\s*:?\s*(\d+)(?:\.(\d+))?', re.I)
CLIENT = re.compile(r'(?:^|\s-\s)(API|Viewer|Navigator|Console|Solution Designer)\s+\d+\.\d+\.\d+\s*$', re.I)


def normalize(raw: dict, timezone: str = 'UTC') -> dict:
    a = {'mapping_version': MAPPING_VERSION, 'operation': None, 'outcome': 'unknown',
         'stage': 'unknown', 'username': str(raw.get('User') or '').casefold(),
         'ip': None, 'document': None, 'client': None, 'time': None}
    node = raw.get('Node')
    if isinstance(node, dict):
        try:
            a['ip'] = str(ipaddress.ip_address(node.get('IP', '')))
        except ValueError:
            pass
    try:
        stamp = str(raw['TmpStmp'])
        if len(stamp) != 17 or not stamp.isdigit():
            raise ValueError('timestamp')
        a['time'] = dt.datetime.strptime(stamp, '%Y%m%d%H%M%S%f').replace(
            tzinfo=ZoneInfo(timezone)).astimezone(UTC).isoformat()
    except (KeyError, ValueError, TypeError):
        pass
    try:
        op = int(raw['Oper']) & 0x7fffffff
        code = int(raw['RetCode'])
    except (KeyError, ValueError, TypeError):
        return a
    a['operation'] = {1: 'connect', 2: 'disconnect', 201: 'disconnect',
                      5: 'retrieve', 16: 'delete', 13: 'index_change'}.get(op)
    text = str(raw.get('Text') or '').strip()
    if m := CLIENT.search(text):
        a['client'] = m[1].casefold()
    if m := DOC.search(text):
        a['document'] = int(m[1])
    if re.search(r'\bcompleted\s*$', text, re.I):
        a['stage'] = 'completed'
        if code == 0 and not text.lower().startswith('failed:'):
            a['outcome'] = 'success'
    elif re.search(r'\bstarted\s*$', text, re.I):
        a['stage'] = 'started'
    if a['operation'] == 'connect':
        if code == 0 and a['stage'] != 'started' and not text.lower().startswith('failed:'):
            a.update(stage='completed', outcome='success')
        elif code == 27 and 'invalid user name or password' in text.lower():
            a.update(stage='completed', outcome='credential_failure')
    return a


def validate_approval(values: dict) -> dict:
    result = {k: str(values.get(k, '')).strip() for k in
              ('name', 'username', 'network', 'kind', 'reason')}
    if not all(result.values()):
        raise ValueError('Name, account, source network, activity and reason are required.')
    if any(len(v) > 500 for v in result.values()):
        raise ValueError('Approval fields must be 500 characters or fewer.')
    result['username'] = result['username'].casefold()
    result['network'] = str(ipaddress.ip_network(result['network'], strict=False))
    if result['kind'] not in ('retrieval', 'api_activity'):
        raise ValueError('Choose retrieval or API activity.')
    for key in ('starts_at', 'ends_at'):
        result[key] = dt.datetime.fromisoformat(str(values.get(key, '')))
        if result[key].tzinfo is None:
            raise ValueError('Approval times must include a UTC offset, e.g. +11:00.')
    if result['ends_at'] <= result['starts_at']:
        raise ValueError('Expiry must be after the start.')
    result['max_count'] = int(values.get('max_count', 0))
    if not 1 <= result['max_count'] <= 2147483647:
        raise ValueError('Maximum count must be between 1 and 2147483647.')
    return result


def _matches(p, event):
    a = event['activity']
    if not a['ip'] or a['username'] != p['username']:
        return False
    return (p['starts_at'] <= event['event_time'] < p['ends_at']
            and ipaddress.ip_address(a['ip']) in ipaddress.ip_network(p['network']))


def detect(events: list[dict], new_ids: set[int], approvals: list[dict],
           retrieval_limit=100, api_limit=500) -> list[dict]:
    """Evaluate windows at each new event, including delayed/replayed event context.

    Callers pass two hours of prior context. Findings include original evidence IDs.
    Approved volume is evaluated over the entire matching window, before filtering.
    """
    events = sorted(events, key=lambda e: (e['event_time'], e['id']))
    results = []
    users, ips = defaultdict(list), defaultdict(list)
    for e in events:
        a, now = e['activity'], e['event_time']
        user = a['username']
        if user:
            users[user].append(e)
        if a['ip']:
            ips[a['ip']].append(e)
        if e['id'] not in new_ids or not user:
            continue
        def window(rows, minutes):
            return [r for r in rows if now - dt.timedelta(minutes=minutes) < r['event_time'] <= now]
        def emit(rule, subject, rows, count, **extra):
            results.append(dict(rule_id=rule, subject=subject,
                                first_ts=min(r['event_time'] for r in rows), last_ts=now,
                                expected=False, approval_id=None,
                                details={'count': count, **extra},
                                evidence_ids=[r['id'] for r in rows][-100:]))
        failures = lambda rows: [r for r in rows if r['activity']['outcome'] == 'credential_failure']
        if a['outcome'] == 'credential_failure':
            rows = failures(window(users[user], 15))
            if len(rows) >= 5:
                emit('login_failures', user, rows, len(rows))
            rows = failures(window(ips[a['ip']], 60)) if a['ip'] else []
            count = len({r['activity']['username'] for r in rows})
            if count >= 3:
                emit('password_spray', a['ip'], rows, count)
        if a['operation'] == 'connect' and a['outcome'] == 'success':
            rows = failures(window(users[user], 120))
            if len(rows) >= 2:
                emit('success_after_failures', user, rows + [e], len(rows))
        for kind, threshold in [('retrieval', retrieval_limit), ('api_activity', api_limit)]:
            def eligible(r):
                b = r['activity']
                return (b['stage'] == 'completed' and b['outcome'] == 'success'
                        and ((b['operation'] == 'retrieve' and b['document'] is not None)
                             if kind == 'retrieval' else b['client'] == 'api'))
            if not eligible(e):
                continue
            rows = [r for r in window(users[user], 5) if eligible(r)]
            count_rows = lambda rs: (len({r['activity']['document'] for r in rs})
                                    if kind == 'retrieval' else len(rs))
            # Overlaps never add limits: the earliest-created matching approval owns a row.
            partitions = defaultdict(list)
            policies = {p['id']: p for p in approvals if p['kind'] == kind}
            for r in rows:
                p = next((p for _, p in sorted(policies.items()) if _matches(p, r)), None)
                partitions[p['id'] if p else None].append(r)
            for pid, group in partitions.items():
                if not any(r['id'] == e['id'] for r in group):
                    continue
                count = count_rows(group)
                p = policies.get(pid)
                exceeded = p is not None and count > p['max_count']
                if count < threshold and not exceeded:
                    continue
                emit(kind + '_burst', user, group, count,
                     window_minutes=5, approval_name=p['name'] if p else None,
                     limit=p['max_count'] if p else threshold, exceeded=exceeded)
                results[-1].update(expected=p is not None and not exceeded, approval_id=pid)
    return results
