import importlib
import json

import httpx
import pytest
from fastapi.testclient import TestClient
from tests.test_user_tokens import keys, claims


@pytest.fixture
def resource_pe(keys, tmp_path, monkeypatch):
    monkeypatch.setenv('SERVICE_KEY', 'test-key')
    monkeypatch.setenv('STATE_DIR', str(tmp_path))
    from app import common, pe
    importlib.reload(common)
    importlib.reload(pe)
    events = []
    async def controls(base, path, method='GET', data=None):
        if path == '/credential-context':
            return {'valid': True}
        if path == '/snapshot':
            return {'device': {'id': 'device-a', 'managed': True, 'compromised': False}, 'context': {}}
        assert path == '/event'
        events.append(data)
        return {'ok': True}
    monkeypatch.setattr(pe, 'call', controls)
    with TestClient(pe.app, headers={'x-service-key': 'test-key'}) as client:
        yield client, pe, events, controls


def body(keys, sub='alice', path='/api/salary/alice'):
    from uuid import uuid4
    payload = {**claims(), 'sub': sub, 'role': 'hr' if sub == 'bob' else 'employee'}
    return dict(source='spiffe://cluster.local/ns/zta-identity/sa/frontend',
                destination='spiffe://cluster.local/ns/zta-identity/sa/salary', method='GET',
                path=path, token=keys[0].issue(payload), attempt_id=str(uuid4()), request_id=str(uuid4()))


def test_real_pe_verifies_tokens_and_audits_ownership(resource_pe, keys):
    client, _, events, _ = resource_pe
    assert client.post('/evaluate-resource', json=body(keys)).json()['decision'] == 'ALLOW'
    assert client.post('/evaluate-resource', json=body(keys, path='/api/salary/bob')).json()['reason'] == 'resource_ownership_denied'
    forged = body(keys)
    forged['token'] = 'forged'
    assert client.post('/evaluate-resource', json=forged).json()['decision'] == 'DENY'
    assert events[0]['kind'] == 'resource_pe_decision'
    assert all('token' not in e and 'authorization' not in e for e in events)


def test_rate_is_subject_bound_persistent_and_step_up_does_not_reset(resource_pe, keys):
    client, _, _, _ = resource_pe
    results = [client.post('/evaluate-resource', json=body(keys, 'bob')).json() for _ in range(8)]
    assert results[0]['decision'] == 'ALLOW'
    assert results[-1]['reason'] == 'behavioral_quarantine'
    # Every body has a newly signed token and a different JTI/attempt.
    assert client.post('/evaluate-resource', json=body(keys, 'bob')).json()['decision'] == 'DENY'
    assert client.get('/resource-state/bob').json()['quarantined'] is True
    from app import hr_state
    importlib.reload(hr_state)
    assert hr_state.get_state('bob')['quarantined'] is True
    assert client.post('/evaluate-resource', json=body(keys)).json()['decision'] == 'ALLOW'


@pytest.mark.parametrize('failure', ['/event', '/credential-context', '/snapshot'])
def test_dependency_outage_cannot_allow(resource_pe, keys, monkeypatch, failure):
    client, pe, _, controls = resource_pe
    async def down(base, path, method='GET', data=None):
        if path == failure:
            raise httpx.ConnectError('offline')
        return await controls(base, path, method, data)
    monkeypatch.setattr(pe, 'call', down)
    assert client.post('/evaluate-resource', json=body(keys)).status_code == 503
