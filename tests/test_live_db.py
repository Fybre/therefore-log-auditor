import os
import datetime as dt
import pytest
from auditor import db, config
from auditor.live.store import ingest, evaluate
from auditor.live.worker import lock_key

DB=os.environ.get('TEST_DATABASE_URL')
pytestmark=pytest.mark.skipif(not DB,reason='TEST_DATABASE_URL not set')


@pytest.fixture
def conn(monkeypatch):
    monkeypatch.setenv('AUDITOR_ENC_KEY','live-test-only')
    with db.connect(DB) as c:
        c.execute('DROP SCHEMA public CASCADE; CREATE SCHEMA public')
        c.commit()
        db.migrate(c)
        c.execute("INSERT INTO tenants(id,base_url) VALUES ('a','https://a.example'),('b','https://b.example')")
        c.commit()
        yield c


def raw(key,doc=None):
    return dict(Key=key,Oper='5',RetCode='0',User='alice',Node={'IP':'192.0.2.1'},
                Text=f'DocNo {doc or key} - completed',TmpStmp='20261005120000000')


def test_atomic_ingest_dedup_reset_evaluation_and_tenant_isolation(conn):
    with conn.transaction():ingest(conn,'a','https://a.example/TheXMLServer',[raw(100)],True)
    with pytest.raises(RuntimeError):
        with conn.transaction():
            ingest(conn,'a','https://a.example/TheXMLServer',[raw(101)])
            raise RuntimeError('crash before commit')
    assert conn.execute("SELECT cursor FROM live_state WHERE tenant_id='a'").fetchone()['cursor']==100
    conn.commit()
    with conn.transaction():ingest(conn,'a','https://a.example/TheXMLServer',[raw(100)],True)
    assert conn.execute('SELECT count(*) n FROM live_observations').fetchone()['n']==1
    conn.commit()
    with conn.transaction():ingest(conn,'a','https://a.example/TheXMLServer',[raw(1)],True)
    assert conn.execute("SELECT cursor,resets FROM live_state WHERE tenant_id='a'").fetchone()==dict(cursor=1,resets=1)
    conn.commit()
    with conn.transaction():evaluate(conn,'a',retrieval_limit=2)
    assert conn.execute('SELECT count(*) n FROM live_findings').fetchone()['n']==1
    conn.commit()
    with conn.transaction():evaluate(conn,'a',retrieval_limit=2)
    assert conn.execute('SELECT count(*) n FROM live_findings').fetchone()['n']==1
    assert conn.execute("SELECT count(*) n FROM live_findings WHERE tenant_id='b'").fetchone()['n']==0
    conn.commit()
    with conn.transaction():ingest(conn,'a','https://a.example/TheXMLServer',[raw(1,999)],True)
    assert conn.execute('SELECT count(*) n FROM live_observations').fetchone()['n']==3


def test_main_dashboard_live_issue_counts(conn, monkeypatch):
    from fastapi.testclient import TestClient
    from auditor.web.app import create_app
    from auditor.config import Settings
    monkeypatch.setenv('AUDITOR_WEB_USER', 'test')
    monkeypatch.setenv('AUDITOR_WEB_PASSWORD', 'pw')
    monkeypatch.setenv('AUDITOR_WEB_SECRET', 'live-test-secret')
    conn.execute("INSERT INTO live_settings(tenant_id,enabled) VALUES ('a',true),('b',true)")
    conn.execute("""INSERT INTO live_findings
        (tenant_id,rule_id,subject,first_ts,last_ts,expected,details) VALUES
        ('a','retrieval_burst','alice',now(),now(),false,'{}'),
        ('a','api_activity_burst','job',now(),now(),true,'{}'),
        ('b','login_failure','bob',now(),now(),false,'{}'),
        ('b','login_failure','carol',now(),now(),false,'{}')""")
    conn.commit()
    with TestClient(create_app(Settings(DB, [], {}, '', '', '', {}, None))) as client:
        client.post('/login', data={'username': 'test', 'password': 'pw', 'next': '/'})
        page = client.get('/')
        assert page.status_code == 200
        assert '1 live security issues for a' in page.text
        assert '2 live security issues for b' in page.text
        assert '/t/a/live#live-findings' in page.text
        assert '/t/a/findings?severity=high&status=open' in page.text
        conn.execute("UPDATE live_findings SET expected=true WHERE tenant_id='a'")
        conn.commit()
        assert '0 live security issues for a' in client.get('/').text
        conn.execute("UPDATE live_settings SET enabled=false WHERE tenant_id='b'")
        conn.commit()
        page = client.get('/').text
        assert 'Live monitoring is not enabled for b' in page
        assert '2 live security issues for b' not in page
        conn.execute("DELETE FROM live_settings WHERE tenant_id='a'")
        conn.commit()
        assert 'Live monitoring is not enabled for a' in client.get('/').text


def test_lock_excludes_other_worker(conn):
    assert conn.execute('SELECT pg_try_advisory_lock(%s) ok',(lock_key('a'),)).fetchone()['ok']
    with db.connect(DB) as other:
        assert not other.execute('SELECT pg_try_advisory_lock(%s) ok',(lock_key('a'),)).fetchone()['ok']
        assert other.execute('SELECT pg_try_advisory_lock(%s) ok',(lock_key('b'),)).fetchone()['ok']


def test_dashboard_settings_approvals_and_evidence_access(conn,monkeypatch):
    from fastapi.testclient import TestClient
    from auditor.web.app import create_app
    from auditor.config import Settings
    monkeypatch.setenv('AUDITOR_WEB_USER','test')
    monkeypatch.setenv('AUDITOR_WEB_PASSWORD','pw')
    monkeypatch.setenv('AUDITOR_WEB_SECRET','live-test-secret')
    app=create_app(Settings(DB,[],{},'','','',{},None))
    client=TestClient(app)
    assert client.get('/t/a/live',follow_redirects=False).status_code==303
    client.post('/login',data={'username':'test','password':'pw','next':'/'})
    initial = client.get('/t/a/live').text
    assert 'Shadow mode' in initial
    assert 'Messages collected' in initial and 'No messages have been collected.' in initial
    assert 'name="retrieval_limit"' not in initial
    assert 'name="max_count"' not in initial
    configuration = client.get('/admin/tenants/a/live').text
    assert 'name="retrieval_limit"' in configuration
    assert 'name="max_count"' in configuration
    assert 'name="poll_interval_seconds"' in configuration
    r=client.post('/t/a/live/settings',data={'enabled':'on','retrieval_limit':3,'api_limit':20,'poll_interval_seconds':30})
    assert r.status_code==200
    assert conn.execute("SELECT enabled FROM live_settings WHERE tenant_id='a'").fetchone()['enabled']
    assert conn.execute("SELECT poll_interval_seconds FROM live_settings WHERE tenant_id='a'").fetchone()['poll_interval_seconds'] == 30
    conn.commit()
    for interval in ['4', '61', '1.5', 'invalid']:
        assert client.post('/t/a/live/settings', data={'enabled':'on','retrieval_limit':3,'api_limit':20,
                                                     'poll_interval_seconds':interval}).status_code == 422
    payload=dict(name='job',username='alice',network='192.0.2.1',kind='retrieval',reason='test',
                 starts_at='2026-10-05T00:00:00+00:00',ends_at='2026-10-06T00:00:00+00:00',max_count=10)
    assert client.post('/t/a/live/approvals',data=payload).status_code==200
    assert client.post('/t/a/live/approvals',data={**payload,'network':'*'}).status_code==422
    assert client.post('/t/a/live/settings',data={},headers={'origin':'https://evil.example'}).status_code==403
    p=conn.execute('SELECT id FROM live_approvals').fetchone()['id'];conn.commit()
    assert client.post(f'/t/b/live/approvals/{p}/revoke').status_code==404
    with conn.transaction():ingest(conn,'a','https://a.example/TheXMLServer',[raw(i) for i in range(1,4)],True)
    with conn.transaction():evaluate(conn,'a',retrieval_limit=3)
    f=conn.execute('SELECT id,expected FROM live_findings').fetchone();conn.commit()
    assert f['expected']
    overview = client.get('/t/a/live').text
    assert 'Expected: job' not in overview
    assert 'DocNo 1 - completed' in overview
    assert '<strong>3</strong>' in overview
    assert 'All collected messages have been analysed.' in overview
    assert overview.index('All collected messages') < overview.index('Refresh now') < overview.index('Recent messages')
    assert 'Recent messages' in overview
    long_message = 'Lengthy diagnostic: ' + 'x' * 500 + '<script>unsafe</script>'
    row = raw(999)
    row['Text'] = long_message
    with conn.transaction():
        ingest(conn, 'a', 'https://a.example/TheXMLServer', [row])
    fragment = client.get('/t/a/live/fragment?expected=true')
    assert fragment.status_code == 200
    assert '<html' not in fragment.text and '<script>' not in fragment.text
    assert 'Show full message' in fragment.text
    assert long_message[:180] + '…' in fragment.text
    assert '&lt;script&gt;unsafe&lt;/script&gt;' in fragment.text
    assert 'Expected: job' in fragment.text
    assert client.get('/t/b/live/fragment').status_code == 200
    assert 'Lengthy diagnostic:' not in client.get('/t/b/live/fragment').text
    assert 'Expected: job' in client.get('/t/a/live?expected=true').text
    assert 'DocNo 1' in client.get(f"/t/a/live/findings/{f['id']}").text
    assert client.get(f"/t/b/live/findings/{f['id']}").status_code==404
    assert client.post(f'/t/a/live/approvals/{p}/revoke').status_code==200

    # Approvals can be prepared from evidence without trusting client-supplied identity.
    overview = client.get('/t/a/live').text
    prefill = client.get(f"/admin/tenants/a/live?from_finding={f['id']}")
    assert prefill.status_code == 200
    assert 'value="alice"' in prefill.text and 'value="192.0.2.1"' in prefill.text
    assert 'name="mark_expected"' in prefill.text
    assert client.get(f"/admin/tenants/b/live?from_finding={f['id']}").status_code == 404
    assert client.post('/admin/tenants/a/live/approvals', data={
        **payload, 'from_finding': f['id'], 'username': 'someone-else', 'mark_expected':'on'}).status_code == 422
    assert client.post('/admin/tenants/a/live/approvals', data={
        **payload, 'from_finding': f['id'], 'mark_expected':'on'}).status_code == 200
    reviewed = conn.execute('SELECT details FROM live_findings WHERE id=%s', (f['id'],)).fetchone()
    assert reviewed['details']['manual_review']['actor'] == 'test'
    conn.commit()
    with conn.transaction():
        ingest(conn,'a','https://a.example/TheXMLServer',[raw(1001)],True)
        evaluate(conn,'a',retrieval_limit=3)
    reviewed = conn.execute('SELECT details FROM live_findings WHERE id=%s', (f['id'],)).fetchone()
    assert reviewed['details']['manual_review']['reason'] == 'test'
    conn.commit()
    conn.execute("UPDATE live_findings SET rule_id='login_failures' WHERE id=%s", (f['id'],))
    conn.commit()
    assert client.get(f"/admin/tenants/a/live?from_finding={f['id']}").status_code == 422


def test_worker_reauthenticates_and_snapshots_after_invalid_session(conn,monkeypatch):
    from auditor.live import worker
    from auditor.config import Settings
    from auditor.live.protocol import ResultError
    conn.execute("INSERT INTO live_settings(tenant_id,enabled,poll_interval_seconds) VALUES ('a',true,30)")
    conn.commit()
    class Stop:
        stopped=False
        waits=[]
        def is_set(self): return self.stopped
        def wait(self,seconds):
            self.waits.append(seconds)
            return self.stopped
    stop=Stop()
    clients=[]
    class FakeClient:
        def __init__(self,*args):
            self.session_id=None
            self.invalid_codes={-1073741672}
            self.logins=0
            self.polls=[]
            clients.append(self)
        def login(self):
            self.logins+=1
            self.session_id='fake-session'
        def poll(self,cursor):
            self.polls.append(cursor)
            if len(self.polls)==1:return [raw(100)]
            if len(self.polls)==2:raise ResultError('RefreshConsoleView',-1073741672)
            stop.stopped=True
            return [raw(1)]
    monkeypatch.setattr(worker,'Client',FakeClient)
    worker.collect_tenant(Settings(DB,[],{},'','','',{},None),'a',stop)
    assert clients[0].polls == [0,100,0]
    assert clients[0].logins == 2
    assert stop.waits == [30, 2, 30]
    state=conn.execute("SELECT * FROM live_state WHERE tenant_id='a'").fetchone()
    assert state['cursor']==1 and state['resets']==1
    assert state['last_error'] is None and state['gap_since'] is not None
    assert conn.execute('SELECT count(*) n FROM live_observations').fetchone()['n']==2


def test_disabled_tenant_never_contacts_console(conn,monkeypatch):
    from auditor.live import worker
    from auditor.config import Settings
    import threading
    def forbidden(*args):raise AssertionError('disabled tenant contacted')
    monkeypatch.setattr(worker,'Client',forbidden)
    worker.collect_tenant(Settings(DB,[],{},'','','',{},None),'a',threading.Event())
    assert conn.execute('SELECT count(*) n FROM live_observations').fetchone()['n']==0


def test_malformed_batch_does_not_advance_cursor(conn):
    with pytest.raises(KeyError):
        with conn.transaction():
            ingest(conn,'a','https://a.example/TheXMLServer',[raw(1),{'Text':'invalid'}])
    assert conn.execute('SELECT count(*) n FROM live_observations').fetchone()['n']==0
    assert conn.execute('SELECT count(*) n FROM live_state').fetchone()['n']==0


def test_incremental_cache_restart_rollback_delays_and_totals(conn, monkeypatch):
    from auditor.live.rolling import EvaluationCache, RollingDetector
    cache = EvaluationCache()
    fed = []
    original = RollingDetector.feed
    def tracked(self, event, *args, **kwargs):
        fed.append(event['id'])
        return original(self, event, *args, **kwargs)
    monkeypatch.setattr(RollingDetector, 'feed', tracked)
    with conn.transaction():
        ingest(conn, 'a', 'https://a.example', [raw(i) for i in range(1, 4)])
        evaluate(conn, 'a', retrieval_limit=2, cache=cache)
    assert len(fed) == 3
    fed.clear()
    with conn.transaction():
        ingest(conn, 'a', 'https://a.example', [raw(3), raw(4)], snapshot=True)
        evaluate(conn, 'a', retrieval_limit=2, cache=cache)
    assert len(fed) == 1  # No context replay on the ordinary path.
    assert conn.execute("SELECT total_messages,evaluated_messages FROM live_state WHERE tenant_id='a'").fetchone() == {
        'total_messages':4, 'evaluated_messages':4}
    conn.commit()
    with conn.transaction():
        ingest(conn, 'a', 'https://a.example', [raw(5)])
    with pytest.raises(RuntimeError):
        with conn.transaction():
            evaluate(conn, 'a', retrieval_limit=2, cache=cache)
            raise RuntimeError('commit failed')
    fed.clear()
    with conn.transaction():
        evaluate(conn, 'a', retrieval_limit=2, cache=cache)
    assert len(fed) == 5  # Database checkpoint invalidates rolled-back cache.
    assert conn.execute('SELECT details FROM live_findings').fetchone()['details']['count'] == 5
    conn.commit()
    delayed = raw(6)
    delayed['TmpStmp'] = '20261005115959000'
    fed.clear()
    with conn.transaction():
        ingest(conn, 'a', 'https://a.example', [delayed])
        evaluate(conn, 'a', retrieval_limit=2, cache=cache)
    assert len(fed) == 1  # Historical window, not incorrectly added to current time.
    fed.clear()
    with conn.transaction():
        ingest(conn, 'a', 'https://a.example', [raw(7)])
        evaluate(conn, 'a', retrieval_limit=2, cache=cache)
    assert len(fed) == 7
    assert conn.execute('SELECT details FROM live_findings').fetchone()['details']['count'] == 7
    state = conn.execute("SELECT * FROM live_state WHERE tenant_id='a'").fetchone()
    assert state['total_messages'] == state['evaluated_messages'] == 7
    conn.commit()
    fed.clear()
    with conn.transaction():
        ingest(conn, 'a', 'https://a.example', [raw(8)])
        evaluate(conn, 'a', retrieval_limit=2, cache=EvaluationCache())
    assert len(fed) == 8
    assert conn.execute('SELECT details FROM live_findings').fetchone()['details']['count'] == 8


def test_cache_rebuilds_when_approval_changes(conn):
    from auditor.live.rolling import EvaluationCache
    cache = EvaluationCache()
    with conn.transaction():
        ingest(conn, 'a', 'https://a.example', [raw(1), raw(2)])
        evaluate(conn, 'a', retrieval_limit=2, cache=cache)
        conn.execute("""INSERT INTO live_approvals
            (tenant_id,name,username,network,kind,starts_at,ends_at,max_count,reason,created_by)
            VALUES ('a','job','alice','192.0.2.1/32','retrieval','2026-10-05','2026-10-06',10,'test','test')""")
    with conn.transaction():
        ingest(conn, 'a', 'https://a.example', [raw(3)])
        evaluate(conn, 'a', retrieval_limit=2, cache=cache)
    finding = conn.execute('SELECT * FROM live_findings WHERE expected').fetchone()
    assert finding['details']['count'] == 3
    conn.commit()
    with conn.transaction():
        conn.execute('UPDATE live_approvals SET revoked_at=now()')
        ingest(conn, 'a', 'https://a.example', [raw(4)])
        evaluate(conn, 'a', retrieval_limit=2, cache=cache)
    assert conn.execute('SELECT details FROM live_findings WHERE NOT expected').fetchone()['details']['count'] == 4


def test_backlog_includes_future_ids_in_event_time_context(conn):
    from auditor.live.rolling import EvaluationCache
    cache = EvaluationCache()
    batch = [raw(i) for i in range(1, 1002)]
    batch[-1]['TmpStmp'] = '20261005115959000'
    with conn.transaction():
        ingest(conn, 'a', 'https://a.example', batch)
        assert evaluate(conn, 'a', retrieval_limit=2, cache=cache) == 1000
    assert cache.detector is None  # Subsequent batch may move backwards in event time.
    assert conn.execute('SELECT details FROM live_findings').fetchone()['details']['count'] == 1001
    conn.commit()
    with conn.transaction():
        assert evaluate(conn, 'a', retrieval_limit=2, cache=cache) == 1
    assert conn.execute('SELECT total_messages-evaluated_messages AS pending FROM live_state').fetchone()['pending'] == 0


def test_processing_migration_backfills_counts_and_timestamps(conn):
    with conn.transaction():
        ingest(conn, 'a', 'https://a.example', [raw(1), raw(2)])
        evaluate(conn, 'a')
        ingest(conn, 'a', 'https://a.example', [raw(3)])
    before = conn.execute('SELECT total_messages,evaluated_messages,last_received,latest_event FROM live_state').fetchone()
    conn.execute('ALTER TABLE live_state DROP COLUMN total_messages, DROP COLUMN evaluated_messages, DROP COLUMN last_received, DROP COLUMN latest_event')
    conn.execute('DROP INDEX live_observations_key')
    conn.execute('DELETE FROM schema_migrations WHERE version=11')
    conn.commit()
    assert db.migrate(conn) == [11]
    assert conn.execute('SELECT total_messages,evaluated_messages,last_received,latest_event FROM live_state').fetchone() == before


def test_incremental_persistence_matches_reference_with_delayed_batches(conn):
    import random
    from auditor.live.rolling import EvaluationCache
    from auditor.live.detection import detect
    from auditor.live.store import _save_findings
    cache = EvaluationCache()
    rng = random.Random(711)
    reference_checkpoint = 0
    for batch_no in range(8):
        batch = []
        for i in range(35):
            event = raw(batch_no*35+i+1, rng.randrange(20))
            event['User'] = rng.choice(['alice','bob','carol'])
            stamp = dt.datetime(2026,10,5,12) + dt.timedelta(seconds=batch_no*50+rng.randrange(-40,50))
            event['TmpStmp'] = stamp.strftime('%Y%m%d%H%M%S')+'000'
            batch.append(event)
        with conn.transaction():
            ingest(conn, 'a', 'https://a.example', batch)
            ingest(conn, 'b', 'https://b.example', batch)
            evaluate(conn, 'a', retrieval_limit=3, cache=cache)
            pending = conn.execute("SELECT id,event_time FROM live_observations WHERE tenant_id='b' AND id>%s ORDER BY id", (reference_checkpoint,)).fetchall()
            lo, hi = min(r['event_time'] for r in pending), max(r['event_time'] for r in pending)
            context = conn.execute("SELECT id,event_time,activity FROM live_observations WHERE tenant_id='b' AND event_time BETWEEN %s AND %s ORDER BY event_time,id", (lo-dt.timedelta(hours=2),hi)).fetchall()
            with conn.cursor() as cur:
                # Original detector and original one-finding-at-a-time write behavior.
                for finding in detect(context, {r['id'] for r in pending}, [], retrieval_limit=3):
                    _save_findings(cur, 'b', [finding])
            reference_checkpoint = pending[-1]['id']
        def summaries(tenant):
            fs = conn.execute('SELECT rule_id,subject,first_ts,last_ts,expected,details,evidence_ids FROM live_findings WHERE tenant_id=%s ORDER BY rule_id,subject,first_ts,last_ts', (tenant,)).fetchall()
            for f in fs:
                f['evidence_ids'] = [conn.execute('SELECT event_key FROM live_observations WHERE id=%s', (i,)).fetchone()['event_key'] for i in f['evidence_ids']]
            return fs
        assert summaries('a') == summaries('b')
        conn.commit()
