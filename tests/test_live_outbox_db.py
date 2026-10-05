import datetime as dt
import os
import smtplib

import pytest

from auditor import db
from auditor.live import outbox
from auditor.live.store import _save_findings
from test_live_db import conn

DB = os.environ.get('TEST_DATABASE_URL')
pytestmark = pytest.mark.skipif(not DB, reason='TEST_DATABASE_URL not set')


@pytest.fixture(autouse=True)
def no_real_email(monkeypatch):
    def forbidden(*args):
        raise AssertionError('Real email delivery is forbidden in tests')
    monkeypatch.setattr(outbox.digest,'send_email',forbidden)
    monkeypatch.setattr(outbox.config,'load_smtp',lambda conn: {'host':'smtp.example','port':25})


def enable(conn):
    conn.execute("""INSERT INTO live_settings(tenant_id,enabled,alerting_enabled,alert_recipients,alerting_enabled_at)
        VALUES ('a',true,true,'security@example.com',now()-interval '10 minutes')""")
    conn.commit()


def candidate(count=500, **extra):
    now = dt.datetime.now(dt.timezone.utc)
    return dict(rule_id='api_activity_burst',subject='alice',first_ts=now-dt.timedelta(minutes=1),
                last_ts=now,expected=False,approval_id=None,details={'count':count,'limit':500},
                evidence_ids=[],**extra)


def save(conn, findings):
    with conn.transaction(), conn.cursor() as cur:
        _save_findings(cur,'a',findings,'https://audit.example')


def queue_test(conn, tenant='a'):
    row = conn.execute("""INSERT INTO live_outbox(tenant_id,alert_type,severity,recipients,subject,body_text,body_html)
        VALUES (%s,'test','info',ARRAY['test@example.com'],'test','test','') RETURNING id""", (tenant,)).fetchone()
    conn.commit()
    return row['id']


def test_atomic_queuing_coalescing_escalation_and_replay(conn):
    enable(conn)
    f = candidate()
    save(conn,[f,{**f,'details':{'count':1000,'limit':500}},{**f,'details':{'count':2500,'limit':500}}])
    assert conn.execute('SELECT count(*) n FROM live_outbox').fetchone()['n'] == 1
    assert conn.execute('SELECT alert_count,last_alert_count FROM live_findings').fetchone() == {'alert_count':1,'last_alert_count':2500}
    conn.commit()
    save(conn,[f])
    assert conn.execute('SELECT count(*) n FROM live_outbox').fetchone()['n'] == 1
    conn.execute("UPDATE live_findings SET last_alert_ts=now()-interval '16 minutes'")
    conn.commit()
    save(conn,[candidate(5000)])
    assert conn.execute("SELECT count(*) n FROM live_outbox WHERE alert_type='escalation'").fetchone()['n'] == 1
    conn.commit()
    with pytest.raises(RuntimeError):
        with conn.transaction(), conn.cursor() as cur:
            _save_findings(cur,'a',[{**candidate(),'subject':'new-user'}])
            raise RuntimeError('rollback')
    assert conn.execute('SELECT count(*) n FROM live_findings').fetchone()['n'] == 1
    assert conn.execute('SELECT count(*) n FROM live_outbox').fetchone()['n'] == 2


def test_shadow_expected_and_history_do_not_queue(conn):
    f = candidate()
    save(conn,[f])
    assert conn.execute('SELECT count(*) n FROM live_outbox').fetchone()['n'] == 0
    conn.commit()
    enable(conn)
    save(conn,[{**f,'expected':True}])
    historical = {**candidate(),'subject':'old','first_ts':f['first_ts']-dt.timedelta(hours=1),'last_ts':f['last_ts']-dt.timedelta(hours=1)}
    save(conn,[historical])
    assert conn.execute('SELECT count(*) n FROM live_outbox').fetchone()['n'] == 0
    conn.commit()
    # Fresh ongoing activity can alert even when an episode began in shadow mode.
    save(conn,[candidate(600)])
    assert conn.execute('SELECT count(*) n FROM live_outbox').fetchone()['n'] == 1


def test_new_episode_after_inactivity(conn):
    enable(conn)
    save(conn,[candidate()])
    conn.execute("UPDATE live_findings SET first_ts=first_ts-interval '31 minutes',last_ts=last_ts-interval '31 minutes'")
    conn.commit()
    save(conn,[candidate()])
    assert conn.execute('SELECT count(*) n FROM live_findings').fetchone()['n'] == 2
    assert conn.execute("SELECT count(*) n FROM live_outbox WHERE alert_type='initial'").fetchone()['n'] == 2


def test_dispatch_success_and_concurrent_claims(conn,monkeypatch):
    ids = [queue_test(conn),queue_test(conn)]
    sent = []
    def send(*args):
        sent.append(args)
        if len(sent) == 1:
            with db.connect(DB) as second:
                from auditor.live.store import ingest, evaluate
                from test_live_db import raw
                # Collection and evaluation proceed while the first SMTP send is in flight.
                with second.transaction():
                    ingest(second,'a','https://a.example',[raw(1)])
                    evaluate(second,'a')
                assert outbox.dispatch_outbox_batch(second,None,batch_size=1) == 1
    monkeypatch.setattr(outbox.digest,'send_email',send)
    assert outbox.dispatch_outbox_batch(conn,None) == 1
    assert len(sent) == 2
    assert conn.execute("SELECT count(*) n FROM live_outbox WHERE status='sent' AND attempts=1").fetchone()['n'] == 2
    assert ids[0] != ids[1]


def test_failure_retry_exhaustion_and_error_redaction(conn,monkeypatch):
    ident = queue_test(conn)
    def failure(*args):
        raise smtplib.SMTPAuthenticationError(535,b'secret credential content')
    monkeypatch.setattr(outbox.digest,'send_email',failure)
    for attempt in range(1,6):
        assert outbox.dispatch_outbox_batch(conn,None) == 1
        row = conn.execute('SELECT * FROM live_outbox WHERE id=%s',(ident,)).fetchone()
        assert row['attempts'] == attempt and row['status'] == 'failed'
        assert 'secret' not in row['last_error']
        assert row['next_attempt_at'] > row['last_attempt_at']
        conn.commit()
        assert outbox.dispatch_outbox_batch(conn,None) == 0
        conn.execute("UPDATE live_outbox SET next_attempt_at=now()-interval '1 second' WHERE id=%s",(ident,))
        conn.commit()
    assert outbox.dispatch_outbox_batch(conn,None) == 0


def test_missing_smtp_backs_off_and_approval_cancels_pending(conn,monkeypatch):
    ident = queue_test(conn)
    monkeypatch.setattr(outbox.config,'load_smtp',lambda conn: None)
    assert outbox.dispatch_outbox_batch(conn,None) == 1
    assert outbox.dispatch_outbox_batch(conn,None) == 0
    enable(conn)
    save(conn,[candidate()])
    conn.execute('UPDATE live_findings SET expected=true')
    conn.commit()
    assert outbox.dispatch_outbox_batch(conn,None) == 1
    assert conn.execute("SELECT count(*) n FROM live_outbox WHERE status='cancelled'").fetchone()['n'] == 1
    assert conn.execute('SELECT attempts FROM live_outbox WHERE id=%s',(ident,)).fetchone()['attempts'] == 1


def test_disable_notifications_cancels_pending(conn):
    enable(conn)
    save(conn,[candidate()])
    conn.execute('UPDATE live_settings SET alerting_enabled=false')
    conn.commit()
    assert outbox.dispatch_outbox_batch(conn,None) == 1
    assert conn.execute('SELECT status FROM live_outbox').fetchone()['status'] == 'cancelled'


def test_retry_after_restart_and_reenable_cancels_old_queue(conn,monkeypatch):
    ident = queue_test(conn)
    monkeypatch.setattr(outbox.config,'load_smtp',lambda conn: None)
    outbox.dispatch_outbox_batch(conn,None)
    conn.execute('UPDATE live_outbox SET next_attempt_at=now() WHERE id=%s',(ident,))
    conn.commit()
    monkeypatch.setattr(outbox.config,'load_smtp',lambda conn: {'host':'smtp.example'})
    sent = []
    monkeypatch.setattr(outbox.digest,'send_email',lambda *args: sent.append(args))
    with db.connect(DB) as restarted:
        assert outbox.dispatch_outbox_batch(restarted,None) == 1
    assert len(sent) == 1
    assert conn.execute('SELECT attempts,status FROM live_outbox WHERE id=%s',(ident,)).fetchone() == {'attempts':2,'status':'sent'}
    conn.commit()
    enable(conn)
    save(conn,[candidate()])
    conn.execute('UPDATE live_settings SET alerting_enabled_at=now()')
    conn.commit()
    assert outbox.dispatch_outbox_batch(conn,None) == 1
    assert len(sent) == 1
    assert conn.execute("SELECT count(*) n FROM live_outbox WHERE status='cancelled'").fetchone()['n'] == 1


def test_notification_ui_validation_test_queue_and_tenant_isolation(conn,monkeypatch):
    from fastapi.testclient import TestClient
    from auditor.web.app import create_app
    from auditor.config import Settings
    monkeypatch.setenv('AUDITOR_WEB_USER','test')
    monkeypatch.setenv('AUDITOR_WEB_PASSWORD','pw')
    monkeypatch.setenv('AUDITOR_WEB_SECRET','test-only-secret')
    with TestClient(create_app(Settings(DB,[],{},'','','',{},None))) as client:
        assert client.post('/admin/tenants/a/live/test-alert',follow_redirects=False).status_code == 303
        client.post('/login',data={'username':'test','password':'pw','next':'/'})
        assert 'Shadow mode' in client.get('/admin/tenants/a/live').text
        assert client.post('/admin/tenants/a/live/notifications',data={'alerting_enabled':'on'}).status_code == 422
        assert client.post('/admin/tenants/a/live/notifications',data={'alert_recipients':'invalid'}).status_code == 422
        assert client.post('/admin/tenants/a/live/notifications',data={'alert_recipients':'test@example.com'}).status_code == 200
        assert client.post('/admin/tenants/a/live/test-alert',headers={'origin':'https://evil.example'}).status_code == 403
        assert client.post('/admin/tenants/missing/live/test-alert').status_code == 404
        assert client.post('/admin/tenants/a/live/test-alert').status_code == 200
        page = client.get('/admin/tenants/a/live').text
        assert 'Pending' in page and 'test@example.com' in page
        assert 'test@example.com' not in client.get('/admin/tenants/b/live').text
        assert not conn.execute("SELECT alerting_enabled FROM live_settings WHERE tenant_id='a'").fetchone()['alerting_enabled']
        assert conn.execute('SELECT count(*) n FROM live_outbox').fetchone()['n'] == 1
        assert conn.execute("SELECT count(*) n FROM admin_audit_log WHERE action='live.test_alert'").fetchone()['n'] == 1
        conn.commit()
        assert client.post('/admin/tenants/a/live/notifications',data={'alerting_enabled':'on','alert_recipients':'test@example.com'}).status_code == 200
        opts = conn.execute("SELECT * FROM live_settings WHERE tenant_id='a'").fetchone()
        assert opts['alerting_enabled'] and opts['alerting_enabled_at'] is not None
        assert not opts['enabled']  # Notification settings do not silently enable collection.
