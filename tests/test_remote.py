import importlib
import pytest
from fastapi.testclient import TestClient
from tests.authenticator import Authenticator

def prepare(tmp_path, monkeypatch):
    monkeypatch.setenv('SERVICE_KEY','test-key')
    monkeypatch.setenv('STATE_DIR',str(tmp_path))
    monkeypatch.setenv('WEBAUTHN_ORIGIN','https://demo.example.com')
    monkeypatch.setenv('RP_ID','demo.example.com')
    monkeypatch.setenv('STREAM_ENABLED','false')
    import app.common
    importlib.reload(app.common)

def test_remote_host_origin_and_stream(tmp_path,monkeypatch):
    prepare(tmp_path,monkeypatch)
    import app.dashboard
    importlib.reload(app.dashboard)
    c=TestClient(app.dashboard.app,base_url='https://demo.example.com')
    assert c.get('/').status_code==200
    assert c.get('/',headers={'host':'evil.example'}).status_code==400
    assert c.post('/simulate',json={'action':'reset'},headers={'origin':'https://evil.example'}).status_code==403
    assert c.get('/client-config').json()['stream_enabled'] is False
    assert c.post('/agent/stream',json={'session_id':'x'}).status_code==409

@pytest.mark.parametrize('origin,rp',[('http://demo.example.com','demo.example.com'),('https://demo.example.com','example.com'),('https://demo.example.com/path','demo.example.com')])
def test_invalid_remote_configuration(tmp_path,monkeypatch,origin,rp):
    prepare(tmp_path,monkeypatch)
    monkeypatch.setenv('WEBAUTHN_ORIGIN',origin);monkeypatch.setenv('RP_ID',rp)
    import app.identity
    with pytest.raises(ValueError): importlib.reload(app.identity)

def test_real_remote_webauthn(tmp_path,monkeypatch):
    prepare(tmp_path,monkeypatch)
    import app.identity
    importlib.reload(app.identity)
    c=TestClient(app.identity.app)
    a=Authenticator();o=c.post('/register/options',json={}).json()
    assert o['publicKey']['rp']['id']=='demo.example.com'
    assert c.post('/register/verify',json={'ceremony':o['ceremony'],'credential':a.register(o['publicKey'],'https://demo.example.com')}).status_code==200
    o=c.post('/login/options',json={}).json()
    assert c.post('/login/verify',json={'ceremony':o['ceremony'],'credential':a.login(o['publicKey'],'https://demo.example.com')}).status_code==200
