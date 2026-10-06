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

def check(pc,sid,method='GET',cert=CERT):
    return pc.request(method,'/check/api/salary',headers={'authorization':'Bearer '+sid,'x-forwarded-client-cert':cert})

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
