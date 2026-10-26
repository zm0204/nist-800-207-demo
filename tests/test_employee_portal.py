import time
import httpx
import pytest
from fastapi.testclient import TestClient
from tests.test_identity import identity, enroll
from tests.authenticator import Authenticator


@pytest.fixture
def portal(identity, monkeypatch):
    from scripts.security_inspector import SecurityOperator, create_app
    op = SecurityOperator()
    monkeypatch.setattr(op, 'identity', lambda operation, body: identity.post('/'+operation, json=body), raising=False)
    def control(service, path, method='GET', body=None):
        assert (service, path, method) == ('identity', '/introspect', 'POST')
        return identity.post(path, json=body, headers={'x-service-key': 'test-key'}).json()
    monkeypatch.setattr(op, 'control', control)
    app = create_app(op)
    with TestClient(app, base_url='http://localhost:18081') as client:
        yield client, op, identity


def login(client, identity, subject='alice'):
    auth = Authenticator()
    if subject == 'alice':
        assert enroll(identity, auth).status_code == 200
    else:
        invite = identity.post('/enrollment/invite', json={'subject': subject}, headers={'x-service-key': 'test-key'}).json()
        opts = identity.post('/register/options', json={'invitation': invite['invitation']}).json()
        assert identity.post('/register/verify', json={'ceremony': opts['ceremony'], 'credential': auth.register(opts['publicKey'])}).status_code == 200
    csrf = client.get('/api/portal/session').json()['csrf']
    h = {'x-portal-csrf': csrf}
    opts = client.post('/api/portal/login/options', json={'subject': subject}, headers=h).json()
    response = client.post('/api/portal/login/verify', json={'ceremony': opts['ceremony'], 'credential': auth.login(opts['publicKey'])}, headers=h)
    assert response.status_code == 200, response.text
    assert response.json()['subject'] == subject
    assert 'token' not in response.json()
    return {'x-portal-csrf': response.json()['csrf']}


def wait(client, job):
    for _ in range(100):
        result = client.get('/api/portal/jobs/'+job['id'])
        if result.json()['state'] != 'running':
            return result.json()['result']
        time.sleep(.01)
    pytest.fail('portal job did not finish')


def test_employee_and_public_csrf_cannot_authorize_management(portal):
    c, op, identity = portal
    h = login(c, identity)
    assert c.get('/api/console/session').status_code == 403
    for path, body in [('/api/inspector/invite', {'subject': 'bob'}),
                       ('/api/inspector/recover', {'subject': 'bob'}),
                       ('/api/inspector/experiments', {'attack': 'intruder'}),
                       ('/api/agent/exchange', {'scope': 'salary:write'}),
                       ('/api/identity/register/options', {})]:
        assert c.post(path, json=body, headers={**h, 'x-mesh-console': h['x-portal-csrf']}).status_code == 403
    assert c.get('/api/inspector/status').status_code == 403
    assert c.post('/api/portal/access', json={'resource': 'salary', 'owner': 'bob', 'attack': 'intruder'}, headers=h).status_code == 422


def test_real_passkey_required_and_login_subject_cannot_be_spoofed(portal):
    c, op, identity = portal
    csrf = c.get('/api/portal/session').json()['csrf']
    assert c.post('/api/portal/access', json={'resource': 'salary', 'owner': 'alice'}, headers={'x-portal-csrf': csrf}).status_code == 401
    auth = Authenticator()
    assert enroll(identity, auth).status_code == 200
    opts = c.post('/api/portal/login/options', json={'subject': 'alice'}, headers={'x-portal-csrf': csrf}).json()
    bad = c.post('/api/portal/login/verify', json={'ceremony': opts['ceremony'], 'credential': auth.login(opts['publicKey'], uv=False)}, headers={'x-portal-csrf': csrf})
    assert bad.status_code == 400
    assert c.get('/api/portal/session').json()['subject'] is None


def test_normal_access_uses_server_credentials_and_cache_never_echoes_secrets(portal, monkeypatch):
    from app.inspection import inspect_attempt
    c, op, identity = portal
    h = login(c, identity)
    calls = []
    def agent(path, body, token, method='POST', headers=None):
        calls.append((path, body, token))
        if path == '/session':
            assert body == {'path': '/api/salary', 'method': 'GET'}
            return httpx.Response(200, json={'session_id': 'private-session'})
        assert path == '/token/exchange' and token == 'private-session'
        return httpx.Response(200, json={'access_token': 'private-jwt'})
    def perform(spec, **ids):
        assert spec.token == 'private-jwt' and spec.attack == 'normal' and spec.owner == 'bob'
        result = inspect_attempt(ids['attempt_id'], [{'attempt_id': ids['attempt_id'], 'kind': 'resource_pe_decision', 'decision': 'DENY', 'reason': 'resource_ownership_denied', 'claims': {'sub': 'alice', 'sid': 'sensitive'}}], [], [])
        result.update(responses=[{'status': 403, 'data': {'detail': 'denied'}}], request={'resource': 'salary', 'owner': 'bob', 'method': 'GET'})
        return result
    monkeypatch.setattr(op, 'agent', agent)
    monkeypatch.setattr(op, 'perform', perform)
    job = c.post('/api/portal/access', json={'resource': 'salary', 'owner': 'bob'}, headers=h)
    assert job.status_code == 202
    result = wait(c, job.json())
    assert result['subject'] == 'alice' and result['responses'][0]['status'] == 403
    summary = c.get('/api/observer/attempts').json()
    assert summary['alice']['attempt_id'] == result['attempt_id'] and summary['bob'] is None
    detail = c.get('/api/observer/attempts/'+result['attempt_id'])
    for secret in ('private-session', 'private-jwt', 'sensitive'):
        assert secret not in detail.text
    assert len(calls) == 2
    for _ in range(3):
        assert c.get('/api/observer/attempts').status_code == 200
    assert len(calls) == 2


def test_pa_exchange_rejection_stays_at_pa_and_queries_journal(portal, monkeypatch):
    from app.inspection import inspect_attempt
    c, op, identity = portal
    h = login(c, identity)
    monkeypatch.setattr(op, 'agent', lambda path, *args, **kwargs: httpx.Response(200, json={'session_id': 'private'}) if path == '/session' else httpx.Response(403, json={'detail': 'session_scope_exceeded'}))
    monkeypatch.setattr(op, 'evidence', lambda attempt, *args: inspect_attempt(attempt, [], [], []))
    result = wait(c, c.post('/api/portal/access', json={'resource': 'salary', 'owner': 'alice'}, headers=h).json())
    assert result['denial_point'] == 'token_exchange'
    assert result['reason'] == 'session_scope_exceeded'
    stages = {s['component']: s for s in result['stages']}
    assert stages['external_pe']['status'] == 'NOT_OBSERVED'
    assert stages['resource']['status'] == 'NOT_REACHED'
    assert stages['token_exchange']['status'] == 'VERIFIED_BLOCK'


def test_transport_failure_has_attempt_and_no_fake_403(portal, monkeypatch):
    from app.inspection import inspect_attempt
    c, op, identity = portal
    h = login(c, identity)
    def unavailable(*args, **kwargs):
        raise httpx.ConnectError('private internal address')
    monkeypatch.setattr(op, 'agent', unavailable)
    monkeypatch.setattr(op, 'evidence', lambda attempt, *args: inspect_attempt(attempt, [], [], None))
    result = wait(c, c.post('/api/portal/access', json={'resource': 'profile', 'owner': 'alice'}, headers=h).json())
    assert result['attempt_id'] and result['responses'][0]['status'] == 0
    assert result['reason'] == 'ConnectError' and result['denial_point'] is None
    assert not result['execution_query_observed']


def test_projection_keeps_native_unknown_after_custom_deny_and_filters_claims():
    from app.inspection import inspect_attempt
    from app.employee_portal import public_attempt
    raw = inspect_attempt('a', [{'attempt_id': 'a', 'kind': 'resource_pe_decision', 'decision': 'DENY', 'reason': 'resource_ownership_denied', 'claims': {'sub': 'alice', 'sid': 'secret'}}],
                          [{'attempt_id': 'a', 'component': 'salary', 'response_code_details': 'ext_authz_denied'}], [])
    raw.update(request={'resource': 'salary', 'owner': 'bob', 'method': 'GET'})
    result = public_attempt(raw, 'alice')
    stages = {s['component']: s for s in result['stages']}
    assert stages['native_deny']['status'] == stages['native_allow']['status'] == 'NOT_OBSERVED'
    assert result['denial_point'] == 'external_pe'
    assert result['execution_count'] == 0
    assert 'secret' not in str(result)


def test_native_block_is_not_misattributed_to_deny_rule():
    from app.inspection import inspect_attempt
    from app.employee_portal import public_attempt
    raw = inspect_attempt('a', [{'attempt_id': 'a', 'kind': 'resource_pe_decision', 'decision': 'ALLOW'}],
                          [{'attempt_id': 'a', 'component': 'salary', 'response_code_details': 'rbac_access_denied_matched_policy[none]'}], [])
    raw.update(request={'resource': 'salary', 'owner': 'alice', 'method': 'GET'})
    result = public_attempt(raw, 'alice')
    stages = {s['component']: s for s in result['stages']}
    assert stages['native_policy']['status'] == 'VERIFIED_BLOCK'
    assert stages['native_deny']['status'] == 'NOT_OBSERVED'
    assert result['denial_point'] == 'native_policy'


def test_observer_hides_resource_data_and_user_cannot_read_another_job(portal, monkeypatch):
    from app.inspection import inspect_attempt
    c, op, identity = portal
    h = login(c, identity)
    monkeypatch.setattr(op, 'agent', lambda path, *a, **k: httpx.Response(200, json={'session_id': 's'} if path == '/session' else {'access_token': 't'}))
    def perform(spec, **ids):
        raw = inspect_attempt(ids['attempt_id'], [], [], [{'subject': 'alice'}])
        raw.update(request={'resource': 'salary', 'owner': 'alice'}, responses=[{'status': 200, 'data': {'amount': 50000}}])
        return raw
    monkeypatch.setattr(op, 'perform', perform)
    job = c.post('/api/portal/access', json={'resource': 'salary', 'owner': 'alice'}, headers=h).json()
    result = wait(c, job)
    assert result['responses'][0]['data']['amount'] == 50000
    assert '50000' not in c.get('/api/observer/attempts/'+result['attempt_id']).text
    h = login(c, identity, 'bob')
    assert c.get('/api/portal/jobs/'+job['id']).status_code == 404
    assert c.get('/api/observer/attempts').json()['alice']['attempt_id'] == result['attempt_id']


def test_pages_exist_without_exposing_operator_capability(portal):
    c, _, _ = portal
    for path in ('/', '/portal', '/observer', '/about', '/inspector'):
        response = c.get(path)
        assert response.status_code == 200
        assert c.app.state.operator_key not in response.text
    assert c.get('/api/observer/attempts').json() == {'alice': None, 'bob': None}


def test_cached_revoked_pa_session_has_no_fabricated_current_pass(portal, monkeypatch):
    from app.inspection import inspect_attempt
    c, op, identity = portal
    h = login(c, identity)
    exchanges = 0
    def agent(path, *args, **kwargs):
        nonlocal exchanges
        if path == '/session':
            return httpx.Response(200, json={'session_id': 'private-session'})
        exchanges += 1
        return httpx.Response(200, json={'access_token': 'jwt'}) if exchanges == 1 else httpx.Response(403, json={'detail': 'active_device_bound_session_required'})
    def perform(spec, **ids):
        raw = inspect_attempt(ids['attempt_id'], [], [], [])
        raw.update(request={'resource': 'salary', 'owner': 'alice'}, responses=[{'status': 200}])
        return raw
    monkeypatch.setattr(op, 'agent', agent)
    monkeypatch.setattr(op, 'perform', perform)
    monkeypatch.setattr(op, 'evidence', lambda attempt: inspect_attempt(attempt, [], [], []))
    wait(c, c.post('/api/portal/access', json={'resource':'salary','owner':'alice'}, headers=h).json())
    result = wait(c, c.post('/api/portal/access', json={'resource':'salary','owner':'alice'}, headers=h).json())
    assert result['denial_point'] == 'token_exchange'
    assert next(s for s in result['stages'] if s['component'] == 'pa_session')['status'] == 'NOT_OBSERVED'


def test_logout_is_idempotent_after_session_expiry(portal):
    c, _, identity = portal
    h = login(c, identity)
    c.cookies.clear()
    assert c.post('/api/portal/logout', json={}, headers=h).status_code == 200
    assert c.get('/api/portal/session').json()['subject'] is None
