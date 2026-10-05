import datetime as dt

import pytest

from auditor.live.outbox import determine_alert, format_alert_email, parse_recipients, retry_delay

NOW = dt.datetime(2026,10,5,12,tzinfo=dt.timezone.utc)


def finding(count=500, **extra):
    return dict(rule_id='api_activity_burst', expected=False, details={'count':count,'limit':500}, **extra)


def test_initial_routine_escalation_and_expected():
    assert determine_alert(None, finding(), NOW) == ('initial','medium')
    old = dict(alert_count=1,last_alert_ts=NOW,last_alert_count=500,last_alert_severity='medium')
    assert determine_alert(old,finding(1000),NOW+dt.timedelta(minutes=14,seconds=59)) is None
    assert determine_alert(old,finding(999),NOW+dt.timedelta(minutes=15)) is None
    assert determine_alert(old,finding(1000),NOW+dt.timedelta(minutes=15)) == ('escalation','medium')
    assert determine_alert({**old,'last_alert_count':2000},finding(2500),NOW+dt.timedelta(minutes=15)) == ('escalation','high')
    assert determine_alert(None,{**finding(),'expected':True},NOW) is None


def test_rendering_escapes_values_and_links_directly_to_evidence():
    subject, text, html = format_alert_email('a',17,'api_activity_burst','<alice>',
        {'count':1000,'limit':500,'source_ips':['192.0.2.1'],'documents':[42]},
        NOW,NOW,'initial','medium','https://audit.example/')
    assert 'https://audit.example/t/a/live/findings/17' in text
    assert 'https://audit.example/t/a/live/findings/17' in html
    assert '&lt;alice&gt;' in html and '<alice>' not in html
    assert '192.0.2.1' in text and '42' in text
    assert 'Console messages only' in text and 'Console messages only' in html
    assert 'Security Alert' in subject


def test_recipients_and_retry_bounds():
    assert parse_recipients('a@example.com, b@example.com\na@example.com',[]) == ['a@example.com','b@example.com']
    assert parse_recipients('', ['fallback@example.com']) == ['fallback@example.com']
    with pytest.raises(ValueError):
        parse_recipients('invalid', ['fallback@example.com'])
    assert [retry_delay(n) for n in range(1,6)] == [30,60,120,240,480]
    assert retry_delay(100) == 3600
