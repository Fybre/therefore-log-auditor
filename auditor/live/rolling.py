"""Event-time rolling windows. Raw messages never enter this cache."""
from collections import Counter, deque
import datetime as dt
from itertools import islice

from .detection import _matches


class Window:
    def __init__(self):
        self.rows = {}  # insertion ordered, with O(1) expiry
        self.counts = Counter()

    def add(self, event, distinct):
        self.rows[event['id']] = (event, distinct)
        self.counts[distinct] += 1

    def remove(self, event_id):
        _, distinct = self.rows.pop(event_id)
        self.counts[distinct] -= 1
        if not self.counts[distinct]:
            del self.counts[distinct]

    def evidence(self):
        return list(reversed(list(islice(reversed(self.rows), 100))))


class RollingDetector:
    def __init__(self, approvals):
        self.approvals = sorted(approvals, key=lambda p: p['id'])
        self.windows = {}
        self.expiry = {5: deque(), 15: deque(), 60: deque(), 120: deque()}
        self.last_order = None

    def add(self, key, minutes, event, distinct=None):
        window = self.windows.setdefault(key, Window())
        window.add(event, distinct)
        self.expiry[minutes].append((event['event_time'] + dt.timedelta(minutes=minutes), key, event['id']))
        return window

    def feed(self, event, emit=True, retrieval_limit=100, api_limit=500):
        now, a = event['event_time'], event['activity']
        order = (now, event['id'])
        if self.last_order is not None and order <= self.last_order:
            raise ValueError('Rolling detector requires increasing event-time/id order')
        self.last_order = order
        for queue in self.expiry.values():
            while queue and queue[0][0] <= now:
                _, key, event_id = queue.popleft()
                window = self.windows[key]
                window.remove(event_id)
                if not window.rows:
                    del self.windows[key]
        user, ip = a['username'], a['ip']
        results = []

        def finding(rule, subject, window, count, extra=None, append=None):
            evidence = window.evidence()
            if append is not None:
                evidence = (evidence + [append['id']])[-100:]
            results.append(dict(rule_id=rule, subject=subject,
                first_ts=next(iter(window.rows.values()))[0]['event_time'], last_ts=now,
                expected=False, approval_id=None, details={'count': count, **(extra or {})},
                evidence_ids=evidence))

        if a['outcome'] == 'credential_failure':
            if user:
                recent = self.add(('fail', user), 15, event)
                self.add(('history', user), 120, event)
                if emit and len(recent.rows) >= 5:
                    finding('login_failures', user, recent, len(recent.rows))
            if ip:
                spray = self.add(('spray', ip), 60, event, user)
                if emit and user and len(spray.counts) >= 3:
                    finding('password_spray', ip, spray, len(spray.counts))
        if not user:
            return results
        if emit and a['operation'] == 'connect' and a['outcome'] == 'success':
            history = self.windows.get(('history', user))
            if history and len(history.rows) >= 2:
                finding('success_after_failures', user, history, len(history.rows), append=event)
        if a['stage'] != 'completed' or a['outcome'] != 'success':
            return results
        for kind, eligible, limit in (
            ('retrieval', a['operation'] == 'retrieve' and a['document'] is not None, retrieval_limit),
            ('api_activity', a['client'] == 'api', api_limit),
        ):
            if not eligible:
                continue
            approval = next((p for p in self.approvals if p['kind'] == kind and _matches(p, event)), None)
            pid = approval['id'] if approval else None
            window = self.add((kind, user, pid), 5, event, a['document'] if kind == 'retrieval' else None)
            count = len(window.counts) if kind == 'retrieval' else len(window.rows)
            exceeded = approval is not None and count > approval['max_count']
            if emit and (count >= limit or exceeded):
                finding(kind + '_burst', user, window, count,
                    dict(window_minutes=5, approval_name=approval['name'] if approval else None,
                         limit=approval['max_count'] if approval else limit, exceeded=exceeded))
                results[-1].update(expected=approval is not None and not exceeded, approval_id=pid)
        return results


class EvaluationCache:
    """One per tenant worker; checkpoint mismatch discards uncommitted state."""
    def __init__(self):
        self.clear()

    def clear(self):
        self.tenant_id = None
        self.checkpoint = None
        self.detector = None
