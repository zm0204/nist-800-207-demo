import json
import time
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    from scripts.security_inspector import SecurityOperator, create_app
    operator = SecurityOperator()
    monkeypatch.setattr(operator, 'perform', lambda spec: {'attempt_id': 'test-attempt'})
    with TestClient(create_app(operator), base_url='http://localhost:18081') as c:
        yield c


def headers(client):
    return {'x-mesh-console': client.get('/api/console/session').json()['token']}


def test_local_operator_boundary_and_resource_allowlist(client):
    assert client.get('/', headers={'Host': 'evil.example'}).status_code == 400
    assert client.post('/api/inspector/experiments', json={}).status_code == 403
    h = headers(client)
    assert client.post('/api/inspector/experiments', json={}, headers={**h, 'Origin': 'https://evil.example'}).status_code == 403
    assert client.post('/api/inspector/experiments', json={'owner': '../../admin'}, headers=h).status_code == 400
    assert client.post('/api/inspector/experiments', json={'command': 'delete cluster'}, headers=h).status_code == 422


def test_job_result_never_echoes_bearer_token(client):
    job = client.post('/api/inspector/experiments', json={'token': 'secret-test-token'}, headers=headers(client)).json()
    for _ in range(50):
        result = client.get('/api/inspector/jobs/'+job['id'])
        if result.json()['state'] != 'running':
            break
        time.sleep(.01)
    assert result.json()['state'] == 'done'
    assert 'secret-test-token' not in result.text


def test_html_defaults_to_demo_and_provides_unknown_states(client):
    html = client.get('/')
    assert 'Zero Trust Security Inspector' in html.text
    assert 'id="inspector-panel" hidden' in html.text
    assert 'NOT_OBSERVED / UNKNOWN' in html.text
    assert "frame-ancestors 'none'" in html.headers['content-security-policy']


def test_missing_jwt_experiment_omits_empty_authorization_header(monkeypatch):
    import httpx
    from scripts.security_inspector import SecurityOperator, Experiment
    operator = SecurityOperator()
    seen = []
    def agent(path, body, token, method='POST', headers=None):
        seen.append(headers)
        return httpx.Response(401, text='JWT required')
    monkeypatch.setattr(operator, 'agent', agent)
    monkeypatch.setattr(operator, 'evidence', lambda *args: {'attempt_id': args[0]})
    result = operator.perform(Experiment(attack='missing-jwt'))
    assert result['responses'][0]['status'] == 401
    assert len(seen) == 1 and 'authorization' not in seen[0]


def test_evidence_reread_accepts_only_attempt_identifiers(client):
    assert client.get('/api/inspector/evidence/invalid-id').status_code == 400
