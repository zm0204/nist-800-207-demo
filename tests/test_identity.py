import importlib
import time
import pytest
from fastapi.testclient import TestClient
from tests.authenticator import Authenticator

@pytest.fixture
def identity(tmp_path,monkeypatch):
    monkeypatch.setenv('SERVICE_KEY','test-key'); monkeypatch.setenv('STATE_DIR',str(tmp_path))
    import app.common
    importlib.reload(app.common)
    import app.identity
    importlib.reload(app.identity)
    with TestClient(app.identity.app) as client: yield client

def enroll(client,auth):
    opts=client.post('/register/options',json={}).json()
    reply=auth.register(opts['publicKey'])
    return client.post('/register/verify',json={'ceremony':opts['ceremony'],'credential':reply})

def test_real_webauthn_and_replay(identity):
    a=Authenticator(); assert enroll(identity,a).status_code==200
    opts=identity.post('/login/options',json={}).json()
    body={'ceremony':opts['ceremony'],'credential':a.login(opts['publicKey'])}
    r=identity.post('/login/verify',json=body)
    assert r.status_code==200
    token=r.json()['token']
    valid=identity.post('/introspect',json={'token':token},headers={'x-service-key':'test-key'})
    assert valid.json()['valid'] and valid.json()['subject']=='alice'
    assert identity.post('/login/verify',json=body).status_code==400
    assert identity.post('/introspect',json={'token':token}).status_code==403

@pytest.mark.parametrize('origin,uv',[('https://evil.example',True),('http://localhost:8080',False)])
def test_wrong_origin_and_no_uv(identity,origin,uv):
    a=Authenticator(); assert enroll(identity,a).status_code==200
    opts=identity.post('/login/options',json={}).json()
    r=identity.post('/login/verify',json={'ceremony':opts['ceremony'],'credential':a.login(opts['publicKey'],origin,uv)})
    assert r.status_code==400

def test_wrong_signature(identity):
    a=Authenticator(); assert enroll(identity,a).status_code==200
    opts=identity.post('/login/options',json={}).json()
    other=Authenticator(); other.id=a.id
    assert identity.post('/login/verify',json={'ceremony':opts['ceremony'],'credential':other.login(opts['publicKey'])}).status_code==400

def test_unknown_token(identity):
    assert identity.post('/introspect',json={'token':'invented'},headers={'x-service-key':'test-key'}).json()['valid'] is False

def test_no_reenrollment_takeover(identity):
    assert enroll(identity,Authenticator()).status_code==200
    assert identity.post('/register/options',json={}).status_code==409

def test_expired_challenge(identity):
    from app.common import db
    a=Authenticator();o=identity.post('/register/options').json()
    with db('identity') as c:c.execute('UPDATE challenge SET expires=0')
    assert identity.post('/register/verify',json={'ceremony':o['ceremony'],'credential':a.register(o['publicKey'])}).status_code==400

def test_expired_human_token(identity):
    from app.common import db
    a=Authenticator();assert enroll(identity,a).status_code==200
    o=identity.post('/login/options').json()
    token=identity.post('/login/verify',json={'ceremony':o['ceremony'],'credential':a.login(o['publicKey'])}).json()['token']
    with db('identity') as c:c.execute('UPDATE token SET expires=0')
    assert identity.post('/introspect',json={'token':token},headers={'x-service-key':'test-key'}).json()['valid'] is False
