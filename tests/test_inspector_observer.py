import copy
import time

import pytest
from fastapi.testclient import TestClient

from app.inspection import inspect_attempt
from scripts.security_inspector import SecurityOperator, create_app


def evidence(attempt='attack', subject='alice', source='intruder', *, claims=True, logs=True, journal=True):
    audit = {'attempt_id': attempt, 'kind': 'resource_pe_decision', 'decision': 'ALLOW',
             'source': 'spiffe://cluster.local/ns/zta-identity/sa/'+source,
             'destination': 'spiffe://cluster.local/ns/zta-identity/sa/salary',
             'method': 'GET', 'path': '/api/salary/alice',
             'claims': {'sub': subject, 'sid': 'secret-sid', 'jti': 'secret-jti'}}
    if not claims:
        audit.pop('claims')
    raw = inspect_attempt(attempt, [audit], [{'attempt_id': attempt, 'component': 'salary',
        'response_code': 403, 'response_code_details': 'rbac_access_denied_matched_policy[none]'}] if logs else [], [] if journal else None)
    raw.update(request_id='request-'+attempt, request={'resource': 'salary', 'owner': 'alice', 'method': 'GET', 'attack': 'intruder'},
               responses=[{'status': 403, 'text': 'not public', 'data': {'token': 'secret-response'}}])
    return raw


def operator_headers(client):
    key = {'x-operator-key': client.app.state.operator_key}
    return {**key, 'x-mesh-console': client.get('/api/console/session', headers=key).json()['token']}


def perform(client, token='private-jwt'):
    response = client.post('/api/inspector/experiments', headers=operator_headers(client),
                           json={'token': token, 'attack': 'intruder', 'owner': 'alice'})
    assert response.status_code == 202
    for _ in range(100):
        job = client.get('/api/inspector/jobs/'+response.json()['id'], headers=operator_headers(client)).json()
        if job['state'] != 'running':
            assert job['state'] == 'done', job
            return job
        time.sleep(.01)
    pytest.fail('Inspector job timeout')


def test_authorized_intruder_updates_verified_jwt_subject_only_and_scrubs_secrets(monkeypatch):
    operator = SecurityOperator()
    raw = evidence('bob-initial', 'bob')
    monkeypatch.setattr(operator, 'perform', lambda spec, **ids: copy.deepcopy(raw))
    with TestClient(create_app(operator), base_url='http://localhost:18091') as client:
        perform(client)
        bob = client.get('/api/observer/attempts').json()['bob']
        assert bob and bob['attempt_id'] == 'bob-initial'
        raw = evidence()
        job = perform(client)
        summary = client.get('/api/observer/attempts').json()
        assert summary['alice']['attempt_id'] == job['result']['attempt_id'] == 'attack'
        assert summary['bob'] == bob
        detail = client.get('/api/observer/attempts/attack')
        for secret in ('private-jwt', 'secret-sid', 'secret-jti', 'secret-response', 'not public', '"claims":'):
            assert secret not in detail.text
        value = detail.json()
        assert value['subject'] == 'alice' and value['origin'] == 'inspector'
        assert value['caller']['service_account'] == 'intruder'
        stages = {s['component']: s for s in value['stages']}
        assert stages['jwt_identity']['status'] == 'VERIFIED_PASS'
        assert stages['native_policy']['status'] == 'VERIFIED_BLOCK'
        assert stages['native_deny']['status'] == 'NOT_OBSERVED'
        assert stages['resource']['status'] == 'NOT_REACHED'
        assert value['execution_query_observed'] and value['execution_count'] == 0


@pytest.mark.parametrize('change', ['no_claims', 'unverified_subject', 'wrong_attempt', 'wrong_path', 'wrong_method', 'wrong_source', 'wrong_destination', 'conflicting_subjects'])
def test_unverified_or_mismatched_audit_cannot_inject_an_employee_snapshot(monkeypatch, change):
    raw = evidence(claims=change != 'no_claims')
    audit = next(s for s in raw['stages'] if s['component'] == 'external_pe')['evidence'][0]
    if change == 'unverified_subject':
        audit['claims']['sub'] = 'carol'
    for key, value in {'wrong_attempt': ('attempt_id', 'other'), 'wrong_path': ('path', '/api/salary/bob'),
                       'wrong_method': ('method', 'POST'), 'wrong_source': ('source', 'header:alice'),
                       'wrong_destination': ('destination', 'spiffe://cluster.local/ns/zta-identity/sa/profile')}.items():
        if change == key:
            audit[value[0]] = value[1]
    if change == 'conflicting_subjects':
        another = copy.deepcopy(audit)
        another['claims']['sub'] = 'bob'
        next(s for s in raw['stages'] if s['component'] == 'external_pe')['evidence'].append(another)
    operator = SecurityOperator()
    monkeypatch.setattr(operator, 'perform', lambda spec, **ids: raw)
    with TestClient(create_app(operator), base_url='http://localhost:18091') as client:
        perform(client, token='eyJ.unverified-alice.signature')
        assert client.get('/api/observer/attempts').json() == {'alice': None, 'bob': None}


def test_http403_without_logs_or_journal_does_not_prove_backend_was_skipped(monkeypatch):
    operator = SecurityOperator()
    monkeypatch.setattr(operator, 'perform', lambda spec, **ids: evidence(logs=False, journal=False))
    with TestClient(create_app(operator), base_url='http://localhost:18091') as client:
        perform(client)
        detail = client.get('/api/observer/attempts/attack').json()
        stages = {s['component']: s for s in detail['stages']}
        assert stages['native_allow']['status'] == stages['native_deny']['status'] == 'NOT_OBSERVED'
        assert stages['resource']['status'] == 'NOT_OBSERVED'
        assert detail['execution_count'] is None and not detail['execution_query_observed']


def test_public_employee_cannot_publish_or_submit_attack(monkeypatch):
    operator = SecurityOperator()
    calls = []
    monkeypatch.setattr(operator, 'perform', lambda spec: calls.append(spec))
    with TestClient(create_app(operator), base_url='http://localhost:18091') as client:
        csrf = client.get('/api/portal/session').json()['csrf']
        for route in ('/api/observer/attempts', '/api/observer/attempts/attack', '/api/inspector/experiments'):
            assert client.post(route, json=evidence(), headers={'x-portal-csrf': csrf, 'x-mesh-console': csrf}).status_code in (403, 405)
        assert not calls
        assert client.get('/api/observer/attempts').json() == {'alice': None, 'bob': None}
