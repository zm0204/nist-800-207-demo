"""Operator UI contracts: fixed actions, real outcomes and loopback trust boundary."""
import json
import subprocess
import threading
import time
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest


def console_module():
    from scripts import mesh_console
    return mesh_console


@pytest.fixture
def operator():
    module = console_module()
    return module.MeshOperator(SimpleNamespace(
        kubectl='kubectl', kind='kind', istioctl='istioctl',
        kubeconfig=str(module.ROOT / '.tmp/mesh-kubeconfig')))


@pytest.fixture
def client(operator):
    with TestClient(console_module().create_app(operator), base_url='http://localhost:18081') as c:
        yield c


def token_headers(client):
    return {'x-mesh-console': client.get('/api/console/session').json()['token']}


def wait_job(client, job_id):
    for _ in range(100):
        job = client.get('/api/console/runs/' + job_id).json()
        if job['state'] != 'running':
            return job
        time.sleep(.01)
    pytest.fail('Console job did not complete')


def test_operator_entry_serves_html_and_local_assets(client):
    response = client.get('/')
    assert response.status_code == 200
    assert response.headers['content-type'].startswith('text/html')
    assert client.get('/assets/console.js').status_code == 200
    assert "frame-ancestors 'none'" in response.headers['content-security-policy']


@pytest.mark.parametrize('name', ['salary', 'full-verify'])
def test_actions_require_operator_session_token(client, name):
    assert client.post('/api/console/runs', json={'scenario': name}).status_code == 403


def test_console_rejects_cross_origin_and_rebinding_requests(client):
    assert client.get('/api/console/session', headers={'Origin': 'https://evil.example'}).status_code == 403
    assert client.get('/api/console/session', headers={'Host': 'evil.example'}).status_code == 400
    assert client.post('/api/console/runs', json={'scenario': 'salary'},
                       headers={**token_headers(client), 'Origin': 'http://localhost:9999'}).status_code == 403


def test_console_has_no_arbitrary_command_or_target_input(client):
    headers = token_headers(client)
    assert client.post('/api/console/runs', headers=headers,
                       json={'scenario': 'shell'}).status_code == 404
    assert client.post('/api/console/runs', headers=headers,
                       json={'scenario': 'salary', 'target': 'http://evil', 'command': 'delete pods'}).status_code == 422


def test_denied_request_can_pass_expected_negative_scenario(operator, monkeypatch):
    seen = []
    def request(caller, target, path, method='GET', headers=None):
        seen.append((caller, target, path, method, headers))
        return {'status': 403, 'data': None}
    monkeypatch.setattr(operator, 'request', request)
    result = operator.execute('wrong-identity')
    assert seen == [('intruder', 'salary', '/api/salary', 'GET', {})]
    assert result['passed'] is True and result['response']['status'] == 403
    assert result['request']['caller'] == 'intruder'


def test_unexpected_allow_is_a_failed_security_check(operator, monkeypatch):
    monkeypatch.setattr(operator, 'request', lambda *a, **k: {'status': 200, 'data': {'resource': 'salary'}})
    assert operator.execute('wrong-identity')['passed'] is False


def test_wrong_backend_payload_does_not_pass_positive_check(operator, monkeypatch):
    monkeypatch.setattr(operator, 'request', lambda *a, **k: {'status': 200, 'data': {'resource': 'profile'}})
    assert operator.execute('salary')['passed'] is False


def test_cluster_failure_stays_unavailable_without_leaking_errors(operator, monkeypatch):
    def offline(*a, **k):
        raise RuntimeError('private credential should never enter UI')
    monkeypatch.setattr(operator, 'kubectl', offline)
    state = operator.status()
    assert state['available'] is False and state['workloads'] == []
    assert 'private credential' not in json.dumps(state)


def test_runtime_status_uses_observed_readiness_and_native_sidecars(operator, monkeypatch):
    data = {'items': [
        {'kind': 'Deployment', 'metadata': {'name': 'salary'},
         'spec': {'replicas': 1}, 'status': {'availableReplicas': 0, 'readyReplicas': 0}},
        {'kind': 'Pod', 'metadata': {'name': 'salary-1', 'labels': {'app': 'salary'}},
         'spec': {'serviceAccountName': 'salary', 'containers': [{'name': 'app'}],
                  'initContainers': [{'name': 'istio-proxy', 'restartPolicy': 'Always'}]},
         'status': {'phase': 'Running'}},
        {'kind': 'PeerAuthentication', 'metadata': {'name': 'strict-mtls'},
         'spec': {'mtls': {'mode': 'STRICT'}}},
        {'kind': 'AuthorizationPolicy', 'metadata': {'name': 'default-deny'}, 'spec': {}},
    ]}
    monkeypatch.setattr(operator, 'kubectl', lambda *a, **k: json.dumps(data))
    state = operator.status()
    assert state['available'] is True
    assert state['workloads'][0]['ready'] == 0 and state['workloads'][0]['sidecar'] is True
    assert state['security']['mtls'] == 'STRICT' and state['security']['external_authz'] is False


def test_full_verify_rejects_stale_success_evidence(operator, monkeypatch, tmp_path):
    evidence = tmp_path / 'mesh-external.json'
    evidence.write_text(json.dumps({'started_at': '2020-01-01T00:00:00+00:00',
                                    'passed': True, 'external_authz': True, 'checks': []}))
    monkeypatch.setattr(operator, 'evidence_path', evidence)
    monkeypatch.setattr(operator, 'snapshot', lambda: {})
    monkeypatch.setattr(operator, 'restore', lambda value: None)
    monkeypatch.setattr(operator, 'command', lambda *a, **k: SimpleNamespace(returncode=0, stdout=''))
    with pytest.raises(RuntimeError):
        operator.execute('full-verify')


def test_certificate_view_only_returns_public_identity_metadata(operator, monkeypatch):
    import base64
    from tests.test_mesh_evidence import certificate
    pod = {'metadata': {'name': 'salary-1', 'labels': {'app': 'salary'}},
           'status': {'phase': 'Running'}, 'spec': {'serviceAccountName': 'salary',
           'containers': [{'name': 'app'}, {'name': 'istio-proxy'}]}}
    monkeypatch.setattr(operator, 'kubectl', lambda *a, **k: json.dumps({'items': [pod]}))
    secret = {'dynamicActiveSecrets': [{'secret': {'tlsCertificate': {
        'certificateChain': {'inlineBytes': base64.b64encode(certificate()).decode()},
        'privateKey': {'inlineBytes': 'DO_NOT_RETURN_PRIVATE_KEY'}}}}]}
    monkeypatch.setattr(operator, 'command', lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps(secret)))
    result = operator.certificates()
    assert result[0]['uri'] == 'spiffe://cluster.local/ns/zta-207a/sa/salary'
    assert 'DO_NOT_RETURN_PRIVATE_KEY' not in json.dumps(result)


def test_one_run_at_a_time_and_failures_release_lock(client, operator, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    def slow(name):
        entered.set()
        release.wait(2)
        raise RuntimeError('untrusted secret detail')
    monkeypatch.setattr(operator, 'execute', slow)
    headers = token_headers(client)
    try:
        response = client.post('/api/console/runs', json={'scenario': 'salary'}, headers=headers)
        assert response.status_code == 202 and entered.wait(1)
        assert client.post('/api/console/runs', json={'scenario': 'profile'}, headers=headers).status_code == 409
    finally:
        release.set()
    job = wait_job(client, response.json()['id'])
    assert job['state'] == 'error' and 'untrusted secret' not in json.dumps(job)
    second = client.post('/api/console/runs', json={'scenario': 'profile'}, headers=headers)
    assert second.status_code == 202
    wait_job(client, second.json()['id'])


def test_run_history_records_actual_result(client, operator, monkeypatch):
    monkeypatch.setattr(operator, 'request', lambda *a, **k: {'status': 403, 'data': None})
    response = client.post('/api/console/runs', json={'scenario': 'wrong-identity'}, headers=token_headers(client))
    job = wait_job(client, response.json()['id'])
    assert job['state'] == 'done' and job['result']['passed'] is True
    assert job['result']['response']['status'] == 403
    assert client.get('/api/console/runs').json()['runs'][0]['id'] == job['id']


def test_legacy_links_do_not_submit_workload_operations(client, operator, monkeypatch):
    def unexpected(name):
        pytest.fail('GET navigation must not execute a workload operation')
    monkeypatch.setattr(operator, 'execute', unexpected)
    response = client.get('/api/salary', headers={'sec-fetch-site': 'same-site'}, follow_redirects=False)
    assert response.status_code == 307
    assert response.headers['location'] == '/?scenario=salary#experiment'
    assert client.get('/api/console/runs').json()['runs'] == []


def test_verifier_timeout_restores_policy_replicas_and_temporary_deny(operator, monkeypatch):
    original = {'service-policy.json': '{"version":1,"grants":[]}'}
    cluster = dict(policy=dict(original), replicas={'context': 1, 'pe': 1, 'mesh-authz': 1}, deny=False)
    def kube(*args, **kwargs):
        if args[:2] == ('get', 'configmap'):
            return json.dumps({'data': dict(cluster['policy'])})
        if args[:2] == ('get', 'deployments'):
            return json.dumps({'items': [{'metadata': {'name': name}, 'spec': {'replicas': count}}
                                         for name, count in cluster['replicas'].items()]})
        if args[:2] == ('get', 'authorizationpolicy'):
            return ''
        if args[:2] == ('patch', 'configmap'):
            cluster['policy'] = json.loads(args[args.index('-p') + 1])['data']
        elif args[:2] == ('delete', 'authorizationpolicy'):
            cluster['deny'] = False
        elif args[0] == 'scale':
            cluster['replicas'][args[1].split('/')[1]] = int(args[2].split('=')[1])
        return ''
    def timeout(*args, **kwargs):
        cluster.update(policy={'service-policy.json': 'revoked'}, deny=True)
        cluster['replicas']['pe'] = 0
        raise subprocess.TimeoutExpired('verifier', 600)
    monkeypatch.setattr(operator, 'kubectl', kube)
    monkeypatch.setattr(operator, 'command', timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        operator.execute('full-verify')
    assert cluster == dict(policy=original, replicas={'context': 1, 'pe': 1, 'mesh-authz': 1}, deny=False)


def test_incomplete_recovery_blocks_further_actions(client, operator, monkeypatch):
    def failed_recovery(name):
        raise console_module().RecoveryError()
    monkeypatch.setattr(operator, 'execute', failed_recovery)
    headers = token_headers(client)
    response = client.post('/api/console/runs', json={'scenario': 'full-verify'}, headers=headers)
    job = wait_job(client, response.json()['id'])
    assert job['state'] == 'error' and job['recovery_required'] is True
    assert client.get('/api/console/runs').json()['blocked'] is True
    assert client.post('/api/console/runs', json={'scenario': 'salary'}, headers=headers).status_code == 409
