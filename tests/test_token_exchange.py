import time

from tests.test_pa import stack, create, CERT
from tests.test_user_tokens import keys


def exchange(pc, sid, **data):
    return pc.post('/token/exchange', json=data, headers={
        'authorization': 'Bearer '+sid, 'x-forwarded-client-cert': CERT})


def test_exchange_requires_active_device_bound_session(stack, keys):
    pc, cc, human, pa = stack
    tokens, _ = keys
    sid = create(pc, human).json()['session_id']
    r = exchange(pc, sid)
    assert r.status_code == 200, r.text
    claims = tokens.verify(r.json()['access_token'])
    assert claims['sub'] == 'alice' and claims['role'] == 'employee'
    assert claims['device_id'] == 'device-a'
    assert claims['exp']-claims['iat'] <= 120
    assert claims['scope'] == 'salary:read'
    assert human not in r.text and sid not in r.text
    assert exchange(pc, sid, role='admin').status_code == 422
    assert exchange(pc, human).status_code == 403
    assert pc.post('/token/exchange', json={}, headers={'authorization': 'Bearer '+sid}).status_code == 403
    pc.post('/revoke', json={'session_id': sid}, headers={'x-service-key': 'test-key'})
    assert exchange(pc, sid).status_code == 403


def test_exchange_rechecks_live_risk_and_scope(stack, keys):
    pc, cc, human, _ = stack
    sid = create(pc, human).json()['session_id']
    assert exchange(pc, sid, scope='salary:write').status_code == 403
    cc.post('/simulate', json={'action': 'compromise'})
    assert exchange(pc, sid).status_code == 403


def test_exchange_jwks_is_public_and_no_signing_key_is_generated(stack, keys, monkeypatch, tmp_path):
    pc, cc, human, _ = stack
    assert pc.get('/.well-known/jwks.json').json() == keys[0].public_jwks()
    sid = create(pc, human).json()['session_id']
    monkeypatch.setenv('USER_SIGNING_KEY_FILE', str(tmp_path/'absent'))
    assert exchange(pc, sid).status_code == 503
    assert not (tmp_path/'absent').exists()


def test_hr_write_scope_requires_fresh_same_subject_webauthn(stack, keys):
    import hashlib
    from fastapi.testclient import TestClient
    from tests.authenticator import Authenticator
    from app import identity
    from app.common import db
    pc, cc, alice_human, _ = stack
    cc.put('/policy', json={'threshold': 60, 'grants': {'alice': ['GET /api/salary'], 'bob': ['GET /api/salary']}})
    auth = Authenticator()
    with TestClient(identity.app) as client:
        invitation = client.post('/enrollment/invite', json={'subject': 'bob'}, headers={'x-service-key': 'test-key'}).json()
        o = client.post('/register/options', json={'invitation': invitation['invitation']}).json()
        assert client.post('/register/verify', json={'ceremony': o['ceremony'], 'credential': auth.register(o['publicKey'])}).status_code == 200
        def login():
            o = client.post('/login/options', json={'subject': 'bob'}).json()
            return client.post('/login/verify', json={'ceremony': o['ceremony'], 'credential': auth.login(o['publicKey'])}).json()['token']
        bob_human = login()
        sid = create(pc, bob_human).json()['session_id']
        with db('identity') as c:
            c.execute('UPDATE token SET auth_time=? WHERE hash=?', (int(time.time())-120, hashlib.sha256(bob_human.encode()).hexdigest()))
        assert exchange(pc, sid, scope='salary:write').status_code == 403
        assert exchange(pc, sid, scope='salary:write', step_up_token=alice_human).status_code == 403
        fresh = login()
        r = exchange(pc, sid, scope='salary:write', step_up_token=fresh)
        assert r.status_code == 200
        claims = keys[0].verify(r.json()['access_token'])
        assert claims['sub'] == 'bob' and claims['role'] == 'hr' and claims['scope'] == 'salary:write'
        assert 0 < r.json()['expires_in'] <= 30
        with db('identity') as c:
            c.execute('UPDATE token SET auth_time=? WHERE hash=?', (int(time.time())-120, hashlib.sha256(fresh.encode()).hexdigest()))
        stale = exchange(pc, sid, scope='salary:write', step_up_token=fresh)
        assert stale.status_code == 403 and stale.json()['detail'] == 'step_up_required'
