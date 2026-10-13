import importlib
import pytest
import httpx
from fastapi.testclient import TestClient
from tests.authenticator import Authenticator

CERT='By=proxy;URI=urn:zta:device:device-a'

@pytest.fixture
def stack(tmp_path,monkeypatch):
    monkeypatch.setenv('SERVICE_KEY','test-key'); monkeypatch.setenv('STATE_DIR',str(tmp_path))
    import app.common
    importlib.reload(app.common)
    from app import identity, context, pe
    for module in (identity,context,pe): importlib.reload(module)
    services={'identity':identity.app,'context':context.app,'pe':pe.app}
    async def local_call(base,path,method='GET',data=None):
        name=base.split('//')[1].split(':')[0]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=services[name]),base_url=base) as client:
            r=await client.request(method,path,json=data,headers={'x-service-key':'test-key'})
            r.raise_for_status(); return r.json()
    monkeypatch.setattr(pe,'call',local_call)
    import app.pa
    importlib.reload(app.pa); monkeypatch.setattr(app.pa,'call',local_call)
    with TestClient(identity.app) as ic:
        a=Authenticator(); o=ic.post('/register/options').json()
        assert ic.post('/register/verify',json={'ceremony':o['ceremony'],'credential':a.register(o['publicKey'])}).status_code==200
        o=ic.post('/login/options').json()
        token=ic.post('/login/verify',json={'ceremony':o['ceremony'],'credential':a.login(o['publicKey'])}).json()['token']
    with TestClient(app.pa.app) as pc, TestClient(context.app,headers={'x-service-key':'test-key'}) as cc:
        yield pc,cc,token,app.pa

def create(pc,token,cert=CERT):
    return pc.post('/session',json={'path':'/api/salary','method':'GET'},headers={'authorization':'Bearer '+token,'x-forwarded-client-cert':cert})

def check(pc,sid,method='GET',cert=CERT,path='/api/salary'):
    return pc.request(method,'/check'+path,headers={'authorization':'Bearer '+sid,'x-forwarded-client-cert':cert})

def status(pc,sid):
    return pc.get('/status/'+sid,headers={'x-service-key':'test-key'}).json()

def test_request_actions_keep_policy_and_authorization_separate(stack):
    pc,cc,token,pa=stack
    sid=create(pc,token).json()['session_id']
    assert check(pc,sid).status_code==200
    allowed=status(pc,sid)['last_action']
    assert allowed['policy_evaluation']['decision']=='ALLOW'
    assert (allowed['pdp_decision'],allowed['pa_action'],allowed['pep_state'],allowed['http_status'])==('ALLOW','AUTHORIZE_REQUEST','FORWARD',200)
    mismatch=check(pc,sid,path='/api/profile')
    assert mismatch.status_code==403
    assert mismatch.json()['decision']['decision']=='ALLOW'
    assert mismatch.json()['reason']=='session_scope_mismatch'
    s=status(pc,sid); action=s['last_action']
    assert s['state']=='ACTIVE'
    assert action['policy_evaluation']['decision']=='ALLOW'
    assert (action['pdp_decision'],action['pa_action'],action['pep_state'],action['http_status'])==('DENY','DENY_REQUEST','BLOCKED',403)
    assert action['pa_reason']=='session_scope_mismatch'
    assert action['request']=={'method':'GET','path':'/api/profile'}
    events=cc.get('/events').json()
    denial=next(e for e in events if e.get('action_id')==action['action_id'] and e['kind']=='pa_action')
    request=next(e for e in events if e.get('action_id')==action['action_id'] and e['kind']=='request')
    assert denial['session_ref']==request['session_ref']==s['session_ref']
    assert denial['decision']=='ALLOW'  # The legacy field still means the PE result.
    import asyncio
    asyncio.run(pa.reevaluate_all())
    assert status(pc,sid)['last_action']==action
    assert status(pc,sid)['state']=='ACTIVE'
    assert check(pc,sid).status_code==200
    assert status(pc,sid)['last_action']['pdp_decision']=='ALLOW'

def test_policy_denial_is_not_reported_as_scope_mismatch(stack):
    pc,cc,token,pa=stack; sid=create(pc,token).json()['session_id']
    assert check(pc,sid,'POST').status_code==403
    action=status(pc,sid)['last_action']
    assert action['policy_evaluation']['decision']=='DENY'
    assert action['pa_reason']=='policy_denied'
    assert 'least_privilege' in action['policy_evaluation']['reasons']
    assert status(pc,sid)['state']=='ACTIVE'
    assert check(pc,sid).status_code==200

def test_background_and_manual_revoke_preserve_the_last_request(stack):
    pc,cc,token,pa=stack; sid=create(pc,token).json()['session_id']
    check(pc,sid,path='/api/profile')
    prior=status(pc,sid)['last_request_action']
    cc.post('/simulate',json={'action':'compromise'})
    import asyncio
    asyncio.run(pa.reevaluate_all())
    s=status(pc,sid); action=s['last_action']
    assert s['state']=='REVOKED' and s['last_request_action']==prior
    assert action['operation']=='reevaluation'
    assert action['policy_evaluation']['decision']=='REVOKE'
    assert action['pdp_decision']=='REVOKE' and action['http_status'] is None
    assert check(pc,sid).status_code==403
    assert status(pc,sid)['last_action']['policy_evaluation'] is None
    cc.post('/simulate',json={'action':'reset'})
    sid=create(pc,token).json()['session_id']
    pc.post('/revoke',json={'session_id':sid},headers={'x-service-key':'test-key'})
    action=status(pc,sid)['last_action']
    assert action['operation']=='administrator'
    assert action['policy_evaluation'] is None
    assert action['pa_reason']=='administrator_revocation'

def test_fail_closed_records_no_fabricated_pe_result(stack,monkeypatch):
    pc,cc,token,pa=stack; sid=create(pc,token).json()['session_id']
    original=pa.call
    async def down(base,*args,**kwargs):
        if base==pa.url('pe'): raise httpx.ConnectError('PE offline')
        return await original(base,*args,**kwargs)
    monkeypatch.setattr(pa,'call',down)
    assert check(pc,sid).status_code==403
    s=status(pc,sid); action=s['last_action']
    assert s['state']=='REVOKED'
    assert action['policy_evaluation'] is None
    assert action['pa_reason']=='control_plane_unavailable'
    assert action['pep_state']=='BLOCKED' and action['http_status']==403

def test_device_denial_does_not_resurrect_concurrent_revoke(stack,monkeypatch):
    pc,cc,token,pa=stack; sid=create(pc,token).json()['session_id']
    original=pa.log
    async def revoke_during_request(value):
        if value['kind'] in ('request','request_rejected'):
            await pa.revoke(pa.load(sid),{'decision':'REVOKE','reasons':['administrator_revocation']},
                            operation='administrator',from_pe=False)
        await original(value)
    monkeypatch.setattr(pa,'log',revoke_during_request)
    assert check(pc,sid,cert='URI=urn:zta:device:device-b').status_code==403
    assert status(pc,sid)['state']=='REVOKED'

def test_background_fail_closed_then_request_reports_session_revoked(stack,monkeypatch):
    pc,cc,token,pa=stack; sid=create(pc,token).json()['session_id']
    original=pa.call
    async def down(base,*args,**kwargs):
        if base==pa.url('pe'): raise httpx.ConnectError('PE offline')
        return await original(base,*args,**kwargs)
    monkeypatch.setattr(pa,'call',down)
    import asyncio
    asyncio.run(pa.reevaluate_all())
    assert status(pc,sid)['last_action']['pa_reason']=='control_plane_unavailable'
    assert check(pc,sid).status_code==403
    s=status(pc,sid)
    assert s['state']=='REVOKED' and s['last']['reasons']==['control_plane_unavailable']
    assert s['last_action']['pa_reason']=='session_revoked'
    assert s['last_action']['policy_evaluation'] is None and s['last_action']['pep_state']=='BLOCKED'

def test_wrong_device_attempts_do_not_trigger_authenticated_request_rate(stack):
    pc,cc,token,pa=stack; sid=create(pc,token).json()['session_id']
    for _ in range(12):
        assert check(pc,sid,cert='URI=urn:zta:device:device-b').status_code==403
    assert cc.get('/snapshot').json()['context']['request_count_10s']==0
    assert check(pc,sid).status_code==200

def test_denied_session_has_explicit_policy_and_authorization(stack):
    pc,cc,token,pa=stack
    cc.put('/policy',json={'threshold':60,'grants':{'alice':[]}})
    response=create(pc,token)
    assert response.status_code==403
    action=response.json()['authorization']
    assert action['subject']=='alice'
    assert action['policy_evaluation']['decision']=='DENY'
    assert action['pa_action']=='DENY_SESSION' and action['pdp_decision']=='DENY'
    assert action['operation']=='session' and action['http_status']==403
    assert pc.get('/sessions',headers={'x-service-key':'test-key'}).json()==[]
    event=next(e for e in cc.get('/events').json() if e.get('pa_action')=='DENY_SESSION')
    assert event['subject']=='alice'

def test_session_cert_binding_and_least_privilege(stack):
    pc,cc,token,pa=stack
    assert create(pc,token,'').status_code==403
    assert create(pc,'invented').status_code==403
    sid=create(pc,token).json()['session_id']
    assert check(pc,sid).status_code==200
    assert check(pc,sid,'POST').status_code==403
    assert check(pc,sid,cert='URI=urn:zta:device:device-b').status_code==403
    assert check(pc,sid).status_code==200

@pytest.mark.parametrize('action',['compromise','high-risk-ip','abnormal'])
def test_continuous_revoke(stack,action):
    pc,cc,token,pa=stack; sid=create(pc,token).json()['session_id']
    assert check(pc,sid).status_code==200
    cc.post('/simulate',json={'action':action})
    import asyncio
    asyncio.run(pa.reevaluate_all())
    r=pc.get('/status/'+sid,headers={'x-service-key':'test-key'})
    assert r.json()['state']=='REVOKED'
    assert r.json()['last']['decision']=='REVOKE'
    assert check(pc,sid).status_code==403

def test_policy_change_revokes(stack):
    pc,cc,token,pa=stack; sid=create(pc,token).json()['session_id']
    cc.put('/policy',json={'threshold':60,'grants':{'alice':[]}})
    import asyncio
    asyncio.run(pa.reevaluate_all())
    assert check(pc,sid).status_code==403

def test_outdated_and_manual_revoke(stack):
    pc,cc,token,pa=stack; sid=create(pc,token).json()['session_id']
    cc.post('/simulate',json={'action':'outdated'})
    assert check(pc,sid).status_code==200
    r=pc.post('/revoke',json={'session_id':sid},headers={'x-service-key':'test-key'})
    assert r.status_code==200 and check(pc,sid).status_code==403

def test_fail_closed(stack,monkeypatch):
    pc,cc,token,pa=stack; sid=create(pc,token).json()['session_id']
    async def down(*args,**kwargs): raise httpx.ConnectError('PE offline')
    monkeypatch.setattr(pa,'call',down)
    assert check(pc,sid).status_code==403

def test_actual_request_rate_triggers_revoke(stack):
    pc,cc,token,pa=stack; sid=create(pc,token).json()['session_id']
    codes=[check(pc,sid).status_code for _ in range(14)]
    assert 403 in codes

def test_logs_do_not_contain_bearer_secrets(stack):
    pc,cc,token,pa=stack; sid=create(pc,token).json()['session_id']
    assert check(pc,sid).status_code==200
    events=cc.get('/events').text
    assert token not in events and sid not in events
