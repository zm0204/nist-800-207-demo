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
