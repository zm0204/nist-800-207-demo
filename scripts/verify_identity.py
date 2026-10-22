"""Real isolated Kubernetes / Istio / device-mTLS / WebAuthn verification.

The software authenticator lives ONLY in the test harness. It signs real WebAuthn
ceremonies and persists its test credential under ignored .tmp/identity. Browser
hardware authentication remains a separate manual acceptance check.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
import hashlib
import ssl

import httpx
import jwt
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.authenticator import Authenticator, b64
from scripts.security_inspector import SecurityOperator, Experiment, forwards
from scripts.identity_deploy import STATE, k


class User:
    def __init__(self, subject, operator):
        self.subject, self.operator = subject, operator
        self.path = STATE / ('test-authenticator-'+subject+'.json')
        self.auth = Authenticator()
        if self.path.exists():
            import base64
            data = json.loads(self.path.read_text())
            self.auth.key = serialization.load_pem_private_key(data['key'].encode(), password=None)
            self.auth.id = base64.urlsafe_b64decode(data['id']+'==')
            self.auth.counter = data['counter']
        else:
            invitation = operator.control('identity', '/enrollment/invite', 'POST', {'subject': subject})
            options = self.post('/register/options', {'invitation': invitation['invitation']})
            self.post('/register/verify', {'ceremony': options['ceremony'],
                'credential': self.auth.register(options['publicKey'], origin='http://localhost:18081')})
            self.save()
        self.human = self.login()

    def save(self):
        value = json.dumps({'key': self.auth.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
            'id': b64(self.auth.id), 'counter': self.auth.counter})
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        self.path.write_text(value)

    def post(self, path, body):
        with httpx.Client(trust_env=False, timeout=10) as client:
            r = client.post('http://127.0.0.1:18082'+path, json=body)
            r.raise_for_status()
            return r.json()

    def login(self):
        o = self.post('/login/options', {'subject': self.subject})
        response = self.auth.login(o['publicKey'], origin='http://localhost:18081')
        self.save()
        return self.post('/login/verify', {'ceremony': o['ceremony'], 'credential': response})['token']

    def token(self, resource='salary', write=False):
        session = self.operator.agent('/session', {'path': '/api/'+resource, 'method': 'GET'}, self.human)
        session.raise_for_status()
        self.sid = session.json()['session_id']
        response = self.operator.agent('/token/exchange', {'scope': 'salary:write' if write else None}, self.sid)
        response.raise_for_status()
        return response.json()['access_token']


def run():
    artifacts = ROOT / 'artifacts'
    artifacts.mkdir(exist_ok=True)
    result = {'started_at': datetime.now(timezone.utc).isoformat(), 'checks': [],
        'environment': 'kind-zta-identity / zta-identity', 'passed': False,
        'authenticator': 'test-only software authenticator; real server verification'}
    from scripts.identity_deploy import run as command
    result['revision'] = command(['git', 'rev-parse', 'HEAD'], quiet=True)
    digest = hashlib.sha256()
    for pattern in ('app/*.py', 'scripts/*.py', 'mesh/*.yaml', 'mesh/*.json', 'console/*', 'requirements*.txt', 'Dockerfile*'):
        for path in sorted(ROOT.glob(pattern)):
            digest.update(str(path.relative_to(ROOT)).encode())
            digest.update(path.read_bytes())
    result['source_digest_sha256'] = digest.hexdigest()
    result['image_id'] = command(['docker', 'image', 'inspect', 'zta-identity:local', '--format', '{{.Id}}'], quiet=True)
    operator = SecurityOperator()
    def check(name, token, statuses, *, reason=None, no_execution=False, **kwargs):
        evidence = operator.perform(Experiment(token=token, **kwargs))
        codes = [r['status'] for r in evidence['responses']]
        assert all(c in statuses for c in codes), (name, codes, evidence['responses'])
        if no_execution:
            assert evidence['execution_query_observed'] and evidence['executions'] == [], (name, evidence)
        else:
            assert evidence['executions'], (name, evidence)
        if reason:
            events = next(s for s in evidence['stages'] if s['component'] == 'external_pe')['evidence']
            assert any(e.get('reason') == reason for e in events), (name, evidence)
        result['checks'].append({'name': name, 'passed': True, **evidence})
        print('PASS '+name+' '+str(codes), flush=True)
        return evidence
    try:
        with forwards():
            alice, bob = User('alice', operator), User('bob', operator)
            for with_cert in (False, True):
                tls = ssl.create_default_context(cafile=str(STATE/'certs/service-ca.crt'))
                if with_cert:
                    tls.load_cert_chain(STATE/'certs/device-b.crt', STATE/'certs/device-b.key')
                name = 'Different device plus forged XFCC cannot create Session' if with_cert else 'Device gateway rejects absent client certificate'
                try:
                    with httpx.Client(verify=tls, timeout=5, trust_env=False) as c:
                        r = c.post('https://localhost:18443/session', json={'path': '/api/salary', 'method': 'GET'},
                            headers={'authorization': 'Bearer '+alice.human, 'x-forwarded-client-cert': 'URI=urn:zta:device:device-a'})
                    assert with_cert and r.status_code == 403
                    observed = {'status': r.status_code}
                except httpx.HTTPError as exc:
                    assert not with_cert
                    observed = {'transport_error': type(exc).__name__, 'backend_trace': 'NOT_OBSERVED'}
                result['checks'].append({'name': name, 'passed': True, 'client_observation': observed})
                print('PASS '+name, flush=True)
            check('Alice reads own salary', alice.token(), [200])
            check('Alice reads own profile', alice.token('profile'), [200], resource='profile')
            check('Alice cannot read Bob salary', alice.token(), [403], owner='bob', no_execution=True, reason='resource_ownership_denied')
            check('Compromised frontend cannot override ownership', alice.token(), [403], owner='bob', attack='direct-frontend', no_execution=True, reason='resource_ownership_denied')
            independent = check('Intruder with legal user JWT blocked by workload policy', alice.token(), [403], attack='intruder', no_execution=True)
            assert any(e.get('decision') == 'ALLOW' for s in independent['stages'] if s['component'] == 'external_pe' for e in s['evidence'])
            check('Forged identity headers do not replace mTLS identity', alice.token(), [403], attack='forged-headers', no_execution=True)
            check('Missing user JWT', '', [403, 401], attack='missing-jwt', no_execution=True)
            check('Invalid JWT signature', '', [401], attack='invalid-jwt', no_execution=True)
            check('Receiving sidecar independently rejects invalid JWT', 'invalid-signature', [401], attack='direct-frontend', no_execution=True)
            good = alice.token()
            payload = jwt.decode(good, options={'verify_signature': False})
            private = serialization.load_pem_private_key((STATE/'signing.pem').read_bytes(), password=None)
            for name, changes in [('Expired JWT', {'exp': 1}), ('Wrong audience JWT', {'aud': 'evil'}), ('Wrong issuer JWT', {'iss': 'https://evil.example'})]:
                token = jwt.encode({**payload, **changes}, private, algorithm='RS256', headers=jwt.get_unverified_header(good))
                check(name, token, [401, 403], no_execution=True)
            check('Plaintext caller cannot reach resource', good, [0, 503], attack='plaintext', no_execution=True)
            check('Bob accesses assigned employee', bob.token(), [200])
            check('Bob cannot access out-of-scope employee', bob.token(), [403], owner='carol', no_execution=True, reason='resource_ownership_denied')
            bob.human = bob.login()
            check('Sensitive salary adjustment with fresh WebAuthn and short scope', bob.token(write=True), [200], operation='adjust')
            # One batch is one attempt, with a unique HTTP request ID per read.
            burst = operator.perform(Experiment(token=bob.token(), attack='hr-burst'))
            codes = [r['status'] for r in burst['responses']]
            assert 403 in codes, codes
            assert operator.control('pe', '/resource-state/bob')['quarantined'] is True
            result['checks'].append({'name': 'HR rate feedback creates persistent quarantine', 'passed': True, **burst})
            print('PASS HR rate feedback '+str(codes), flush=True)
            bob.human = bob.login()
            check('New login/JWT cannot bypass quarantine', bob.token(), [403], no_execution=True, reason='behavioral_quarantine')
            check('Fresh step-up cannot bypass quarantine', bob.token(write=True), [403], operation='adjust', no_execution=True, reason='behavioral_quarantine')
            # Restore only the explicit subject risk injected by this test.
            operator.control('pe', '/resource-state/bob', 'PUT', {})
            check('PE unavailable fails closed without resource execution', alice.token(), [403, 503], attack='pe-outage', no_execution=True)
            alice.human = alice.login()
            check('PE recovery restores valid access', alice.token(), [200])
            for attack in ('authz-outage', 'audit-outage'):
                alice.human = alice.login()
                check(attack+' fails closed without execution', alice.token(), [403, 503], attack=attack, no_execution=True)
            alice.human = alice.login()
            token = alice.token()
            operator.control('context', '/simulate', 'POST', {'action': 'compromise'})
            try:
                check('Live device risk blocks existing JWT', token, [403], no_execution=True)
            finally:
                operator.control('context', '/simulate', 'POST', {'action': 'reset'})
            result['certificates'] = operator.certificates()
            assert any(c['workload'] == 'salary' for c in result['certificates'])
            policies = json.loads(k('get', 'authorizationpolicy', 'backend-external-decision', '-o', 'json', quiet=True))
            assert policies['spec']['rules'] == [{'to': [{'operation': {'ports': ['8000']}}]}]
            result['custom_coverage'] = policies['spec']
            result['passed'] = True
    finally:
        result['finished_at'] = datetime.now(timezone.utc).isoformat()
        (artifacts/'identity-e2e.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(f"Verified {len(result['checks'])} real integration checks", flush=True)


if __name__ == '__main__':
    run()
