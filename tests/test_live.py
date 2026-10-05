import datetime as dt
import pytest
from auditor.live.detection import normalize, detect, validate_approval
from auditor.live.worker import endpoint_for

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 5, 12, tzinfo=UTC)


def raw(key=1, oper=5, text='DocNo 27953.2 - completed', code=0, user='Alice'):
    return {'Key':key, 'Oper':str(oper), 'RetCode':str(code), 'User':user,
            'Node':{'IP':'192.0.2.10'}, 'TmpStmp':'20261005120000000', 'Text':text}


def event(i, **kwargs):
    a = normalize(raw(i, **kwargs))
    return {'id':i, 'activity':a, 'event_time':NOW + dt.timedelta(seconds=i)}


def approval(**overrides):
    p = dict(id=1, name='Nightly job', username='alice', network='192.0.2.0/24', kind='retrieval',
             starts_at=NOW, ends_at=NOW+dt.timedelta(hours=1), max_count=5)
    return {**p, **overrides}


def test_mapping_stages_unknowns_and_no_api_inference():
    a = normalize(raw(oper=-2147483643))
    assert (a['document'],a['stage'],a['outcome']) == (27953,'completed','success')
    assert a['client'] is None
    assert normalize(raw(oper=1,text='started'))['outcome'] == 'unknown'
    assert normalize(raw(text='DocNo 27953.2 - started'))['outcome'] == 'unknown'
    assert normalize(raw(code=123))['outcome'] == 'unknown'
    assert normalize(raw(oper=1,code=149,text='failed: The token has expired'))['outcome'] == 'unknown'
    assert normalize(raw(oper=1,code=27,text='failed: Invalid user name or password. - API 35.0.3'))['outcome'] == 'credential_failure'
    assert normalize(raw(oper=5,code=27,text='failed: Invalid user name or password.'))['outcome'] == 'unknown'
    bad=raw();bad['TmpStmp']='not a timestamp'
    assert normalize(bad)['time'] is None


def test_retrieval_counts_distinct_documents_not_versions_or_starts():
    es=[event(i,text=f'DocNo 100.{i} - completed') for i in range(1,5)]
    es += [event(6,text='DocNo 200 - started')]
    assert not detect(es,{e['id'] for e in es},[],retrieval_limit=2)
    es += [event(7,text='DocNo 200 - completed')]
    fs=detect(es,{7},[],retrieval_limit=2)
    assert fs[0]['details']['count'] == 2


def test_approval_exceeding_full_window_and_missing_context():
    es=[event(i,text=f'DocNo {i} - completed') for i in range(1,7)]
    fs=detect(es,{5,6},[approval()],retrieval_limit=3)
    assert fs[0]['expected'] and fs[0]['details']['count']==5
    assert not fs[-1]['expected'] and fs[-1]['details']['exceeded']
    assert fs[-1]['details']['count']==6
    es[0]['activity']['ip']=None
    fs=detect(es[:1],{1},[approval()],retrieval_limit=1)
    assert not fs[0]['expected']


def test_unapproved_partition_and_approval_expiry():
    es=[event(i,text=f'DocNo {i} - completed') for i in range(1,4)]
    for p in [approval(username='bob'), approval(network='203.0.113.0/24'),
              approval(ends_at=NOW),approval(kind='api_activity')]:
        assert not detect(es,{3},[p],retrieval_limit=3)[0]['expected']


def test_approvals_do_not_suppress_logins_or_add_limits():
    es=[event(i,oper=1,code=27,text='failed: Invalid user name or password.') for i in range(1,6)]
    fs=detect(es,{5},[approval()])
    assert fs[0]['rule_id']=='login_failures' and not fs[0]['expected']
    es=[event(i,text=f'DocNo {i} - completed') for i in range(1,7)]
    fs=detect(es,{6},[approval(),approval(id=2,max_count=999)],retrieval_limit=3)
    assert fs[0]['details']['exceeded'] and fs[0]['approval_id']==1


def test_rolling_login_spray_success_and_replay():
    es=[event(i,oper=1,code=27,text='failed: Invalid user name or password.',user=f'u{i}') for i in range(1,4)]
    # Shift across a clock-hour boundary: still one rolling window.
    es[0]['event_time']=NOW-dt.timedelta(minutes=1)
    assert detect(es,{3},[])[0]['rule_id']=='password_spray'
    es=[event(i,oper=1,code=27,text='failed: Invalid user name or password.') for i in (1,2)]
    es += [event(3,oper=1,text='API 35.0.3')]
    assert detect(es,{3},[])[0]['rule_id']=='success_after_failures'
    assert detect(es,set(),[])==[]


def test_api_requires_explicit_context():
    es=[event(i,text=f'DocNo {i} - completed') for i in range(1,4)]
    assert not detect(es,{3},[],api_limit=2)
    es=[event(i,oper=1,text='API 35.0.3') for i in range(1,4)]
    fs=detect(es,{3},[],api_limit=2)
    assert fs[0]['rule_id']=='api_activity_burst'


def test_validation():
    p=dict(name='job',username='Alice',network='192.0.2.1',kind='retrieval',reason='approved export',
           starts_at=NOW.isoformat(),ends_at=(NOW+dt.timedelta(hours=1)).isoformat(),max_count='100')
    assert validate_approval(p)['network']=='192.0.2.1/32'
    for overrides in [dict(network='*'),dict(max_count='0'),dict(starts_at='2026-10-05T12:00:00'),dict(kind='login')]:
        with pytest.raises(ValueError):validate_approval({**p,**overrides})
    assert endpoint_for('https://example.com/prefix/')=='https://example.com/prefix/TheXMLServer'
    with pytest.raises(ValueError):endpoint_for('http://example.com')


def test_approval_does_not_refresh_when_only_other_partition_changes():
    es=[event(i,text=f'DocNo {i} - completed') for i in range(1,4)]
    es.append(event(4,text='DocNo 4 - completed'))
    es[-1]['activity']['ip']='203.0.113.10'
    fs=detect(es,{4},[approval()],retrieval_limit=3)
    assert not fs


def test_protocol_empty_view_and_invalid_keys():
    from auditor.live.protocol import Client, ProtocolError
    from xml.etree.ElementTree import fromstring
    c=Client({'url':'https://example.com/TheXMLServer'},'fake')
    c.refresh_view=lambda *args:fromstring('<Msgs/>')
    assert c.poll(0)==[]
    c.refresh_view=lambda *args:fromstring('<Msgs><Elem><Key>bad</Key></Elem></Msgs>')
    with pytest.raises(ProtocolError):c.poll(0)
    c.refresh_view=lambda *args:fromstring('<UserData/>')
    with pytest.raises(ProtocolError):c.poll(0)
