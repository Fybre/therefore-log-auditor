"""Differential checks against the original detector, kept as a reference oracle."""
import datetime as dt
import random

import pytest

from auditor.live.detection import detect, normalize
from auditor.live.rolling import RollingDetector

NOW = dt.datetime(2026, 10, 5, tzinfo=dt.timezone.utc)


def events(seed, n=1200):
    rng = random.Random(seed)
    rows = []
    for i in range(n):
        kind = rng.randrange(6)
        raw = dict(Key=i, Oper='1' if kind < 3 else '5', RetCode='27' if kind == 0 else '0',
                   User=rng.choice(['alice', 'bob', 'carol', '']),
                   Node={'IP': rng.choice(['192.0.2.1', '192.0.2.2', '203.0.113.1', ''])},
                   TmpStmp='20261005000000000',
                   Text=('failed: Invalid user name or password.' if kind == 0 else
                         'API 35.0.3' if kind == 1 else 'Viewer 35.0.3' if kind == 2 else
                         f'DocNo {rng.randrange(12)} - ' + ('started' if kind == 3 else 'completed')))
        rows.append(dict(id=i+1, event_time=NOW+dt.timedelta(seconds=rng.randrange(10000)),
                         activity=normalize(raw)))
    return sorted(rows, key=lambda e: (e['event_time'], e['id']))


def policies():
    base = dict(name='job', username='alice', network='192.0.2.0/24', kind='retrieval',
                starts_at=NOW, ends_at=NOW+dt.timedelta(hours=1), max_count=4)
    return [dict(base, id=1), dict(base, id=2, max_count=100),
            dict(base, id=3, kind='api_activity', ends_at=NOW+dt.timedelta(hours=2))]


@pytest.mark.parametrize('seed', range(5))
def test_rolling_matches_reference_with_approvals_ties_and_expiry(seed):
    rows = events(seed)
    new = {e['id'] for e in rows if e['id'] % 3}
    detector = RollingDetector(policies())
    actual = []
    for e in rows:
        actual.extend(detector.feed(e, e['id'] in new, retrieval_limit=3, api_limit=3))
    assert actual == detect(rows, new, policies(), retrieval_limit=3, api_limit=3)
    # Expiry removes inactive accounts/IPs and bulk partitions, including dict keys.
    end = {**rows[-1], 'id':99999, 'event_time':NOW+dt.timedelta(days=1),
           'activity':normalize({'Oper':'2','RetCode':'0'})}
    detector.feed(end)
    assert not detector.windows
    assert all(not q for q in detector.expiry.values())


def test_exact_window_boundaries_and_last_100_evidence():
    rows = []
    for i in range(150):
        rows.append(dict(id=i+1, event_time=NOW+dt.timedelta(seconds=i*2),
            activity=normalize(dict(Oper='1', RetCode='0', User='alice', Text='API 35.0.3'))))
    rows.append({**rows[-1], 'id':151, 'event_time':NOW+dt.timedelta(minutes=5)})
    detector = RollingDetector([])
    actual = [f for e in rows for f in detector.feed(e, api_limit=2)]
    assert actual == detect(rows, {e['id'] for e in rows}, [], api_limit=2)
    assert actual[-1]['details']['count'] == 150
    assert actual[-1]['evidence_ids'] == list(range(52,152))
