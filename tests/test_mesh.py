"""Contracts for the opt-in mesh; no device/session shortcuts."""
import importlib
import json

import httpx
import pytest
from fastapi.testclient import TestClient

SOURCE = 'spiffe://cluster.local/ns/zta-207a/sa/frontend'
TARGET = 'spiffe://cluster.local/ns/zta-207a/sa/salary'
POLICY = {'version': 1, 'grants': [
    {'source': SOURCE, 'destination': TARGET, 'method': 'GET', 'path': '/api/salary'}]}


def test_resources_are_independently_deployable():
    from app.mesh_salary import app as salary
    from app.mesh_profile import app as profile
    with TestClient(salary) as s, TestClient(profile) as p:
        assert s.get('/api/salary').json()['amount'] == 50000
        assert p.get('/api/profile').json()['role'] == 'employee'
        assert s.get('/api/profile').status_code == 404
        assert p.get('/api/salary').status_code == 404
        assert s.post('/api/salary').status_code == 405


@pytest.mark.asyncio
async def test_frontend_uses_fixed_upstream_and_does_not_forward_identity_headers(monkeypatch):
    from app import mesh_frontend
    seen = []
    def backend(request):
        seen.append(request)
        return httpx.Response(200, json={'resource': 'salary', 'amount': 50000})
    monkeypatch.setattr(mesh_frontend, 'backend_transport', httpx.MockTransport(backend))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mesh_frontend.app), base_url='http://frontend') as client:
        r = await client.get('/api/salary?url=http://evil', headers={'x-zta-subject': 'admin', 'authorization': 'Bearer forged'})
        assert r.status_code == 200 and r.json()['amount'] == 50000
        assert str(seen[0].url) == 'http://salary:8000/api/salary'
        assert 'authorization' not in seen[0].headers and 'x-zta-subject' not in seen[0].headers
        assert (await client.get('/api/unknown')).status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize('status', [403, 503])
async def test_frontend_does_not_hide_backend_denials(monkeypatch, status):
    from app import mesh_frontend
    monkeypatch.setattr(mesh_frontend, 'backend_transport', httpx.MockTransport(lambda r: httpx.Response(status, text='denied')))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mesh_frontend.app), base_url='http://frontend') as client:
        assert (await client.get('/api/salary')).status_code == status


@pytest.mark.asyncio
async def test_frontend_returns_503_on_connection_failure(monkeypatch):
    from app import mesh_frontend
    def broken(request):
        raise httpx.ConnectError('offline', request=request)
    monkeypatch.setattr(mesh_frontend, 'backend_transport', httpx.MockTransport(broken))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mesh_frontend.app), base_url='http://frontend') as client:
        assert (await client.get('/api/profile')).status_code == 503


@pytest.mark.parametrize('change', [
    {'source': 'spiffe://cluster.local/ns/zta-207a/sa/intruder'},
    {'source': ''}, {'destination': ''}, {'method': 'POST'},
    {'path': '/api/profile'}, {'path': '/api/%73alary'}, {'path': '//api/salary'},
])
def test_service_policy_rejects_wrong_identity_method_or_path(change):
    from app.service_trust import evaluate_service
    args = dict(source=SOURCE, destination=TARGET, method='GET', path='/api/salary')
    args.update(change)
    assert evaluate_service(POLICY, **args)['decision'] == 'DENY'


def test_service_policy_allows_query_and_revocation():
    from app.service_trust import evaluate_service
    assert evaluate_service(POLICY, SOURCE, TARGET, 'GET', '/api/salary?trace=1')['decision'] == 'ALLOW'
    assert evaluate_service({'version': 2, 'grants': []}, SOURCE, TARGET, 'GET', '/api/salary')['decision'] == 'DENY'


@pytest.fixture
def mesh_pe(tmp_path, monkeypatch):
    monkeypatch.setenv('SERVICE_KEY', 'test-key')
    policy_file = tmp_path / 'policy.json'
    policy_file.write_text(json.dumps(POLICY))
    monkeypatch.setenv('SERVICE_POLICY_FILE', str(policy_file))
    from app import common, pe
    importlib.reload(common)
    importlib.reload(pe)
    events = []
    async def audit(base, path, method='GET', data=None):
        assert path == '/event' and method == 'POST'
        events.append(data)
        return {'ok': True}
    monkeypatch.setattr(pe, 'call', audit)
    with TestClient(pe.app, headers={'x-service-key': 'test-key'}) as client:
        yield client, policy_file, events, pe


def service_body():
    return dict(source=SOURCE, destination=TARGET, method='GET', path='/api/salary')


def test_pe_workload_decision_is_audited_and_policy_reload_revokes(mesh_pe):
    client, policy_file, events, _ = mesh_pe
    r = client.post('/evaluate-service', json=service_body())
    assert r.status_code == 200 and r.json()['decision'] == 'ALLOW'
    assert events[0]['kind'] == 'service_pe_decision'
    assert events[0]['source'] == SOURCE and events[0]['destination'] == TARGET
    policy_file.write_text(json.dumps({'version': 2, 'grants': []}))
    r = client.post('/evaluate-service', json=service_body())
    assert r.json()['decision'] == 'DENY' and r.json()['policy_version'] == 2
    assert client.post('/evaluate-service', json=service_body(), headers={'x-service-key': 'bad'}).status_code == 403


@pytest.mark.parametrize('content', ['not json', '{}', '{"version":1,"grants":[{}]}'])
def test_pe_missing_or_malformed_policy_fails_closed(mesh_pe, content):
    client, policy_file, _, _ = mesh_pe
    policy_file.write_text(content)
    assert client.post('/evaluate-service', json=service_body()).status_code == 503
    policy_file.unlink()
    assert client.post('/evaluate-service', json=service_body()).status_code == 503


def test_pe_audit_outage_fails_closed(mesh_pe, monkeypatch):
    client, _, _, pe = mesh_pe
    async def offline(*args, **kwargs):
        raise httpx.ConnectError('audit unavailable')
    monkeypatch.setattr(pe, 'call', offline)
    assert client.post('/evaluate-service', json=service_body()).status_code == 503
