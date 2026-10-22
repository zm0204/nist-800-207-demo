import httpx
import pytest
from fastapi.testclient import TestClient

from tests.test_user_tokens import keys, claims


@pytest.mark.parametrize('name', ['salary', 'profile'])
def test_resources_verify_jwt_and_ownership(keys, name):
    from app import mesh_salary, mesh_profile
    app = {'salary': mesh_salary.app, 'profile': mesh_profile.app}[name]
    token = keys[0].issue({**claims(), 'scope': name+':read'})
    with TestClient(app) as client:
        path = '/api/'+name+'/alice'
        assert client.get(path).status_code == 401
        assert client.get(path, headers={'x-user-id': 'alice', 'x-role': 'admin'}).status_code == 401
        assert client.get(path, headers={'authorization': 'Bearer invented'}).status_code == 401
        r = client.get(path, headers={'authorization': 'Bearer '+token})
        assert r.status_code == 200 and r.json()['subject'] == 'alice'
        assert client.get('/api/'+name+'/bob', headers={'authorization': 'Bearer '+token}).status_code == 403
        wrong = keys[0].issue({**claims(), 'scope': 'other:read'})
        assert client.get(path, headers={'authorization': 'Bearer '+wrong}).status_code == 403


@pytest.mark.asyncio
async def test_frontend_forwards_only_user_token_and_correlation(keys, monkeypatch):
    from app import mesh_frontend
    seen = []
    def upstream(request):
        seen.append(request)
        return httpx.Response(200, json={'subject': 'alice'})
    monkeypatch.setattr(mesh_frontend, 'backend_transport', httpx.MockTransport(upstream))
    token = keys[0].issue(claims())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mesh_frontend.app), base_url='http://frontend') as client:
        assert (await client.get('/api/salary/alice')).status_code == 401
        r = await client.get('/api/salary/alice?url=http://evil', headers={
            'authorization': 'Bearer '+token, 'x-user-id': 'admin', 'x-role': 'hr',
            'x-forwarded-client-cert': 'forged', 'x-attempt-id': 'abc', 'x-request-id': 'def'})
    assert r.status_code == 200
    assert str(seen[0].url) == 'http://salary:8000/api/salary/alice'
    assert seen[0].headers['authorization'] == 'Bearer '+token
    assert 'x-role' not in seen[0].headers and 'x-forwarded-client-cert' not in seen[0].headers
    assert seen[0].headers['x-attempt-id'] == 'abc'


def test_sensitive_execution_is_recorded_only_after_authorization(keys):
    from app.mesh_salary import app
    from app.resource_evidence import executions
    from uuid import uuid4
    attempt = str(uuid4())
    payload = {**claims(), 'sub': 'bob', 'role': 'hr', 'scope': 'salary:write'}
    headers = {'authorization': 'Bearer '+keys[0].issue(payload), 'x-attempt-id': attempt}
    with TestClient(app) as client:
        assert client.post('/api/salary/alice/adjust', json={'amount': 60000}, headers=headers).status_code == 200
        assert len(executions(attempt)) == 1
        denied = str(uuid4())
        headers['x-attempt-id'] = denied
        headers['authorization'] = 'Bearer '+keys[0].issue({**payload, 'sub': 'alice', 'role': 'employee'})
        assert client.post('/api/salary/bob/adjust', json={'amount': 999999}, headers=headers).status_code == 403
        assert executions(denied) == []
