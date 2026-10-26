"""Dedicated P0 acceptance environment. Never targets an existing demonstration cluster."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def configure():
    from scripts import identity_deploy as deployment
    deployment.CLUSTER = 'zta-portal-p0'
    deployment.CONTEXT = 'kind-zta-portal-p0'
    deployment.IMAGE = 'zta-portal-p0:local'
    deployment.STATE = ROOT/'.tmp/portal-p0'
    deployment.KUBECONFIG = deployment.STATE/'kubeconfig'
    original = deployment.render
    def render(jwks):
        docs = original(jwks)
        identity = next(d for d in docs if d['kind'] == 'Deployment' and d['metadata']['name'] == 'identity')
        for entry in identity['spec']['template']['spec']['containers'][0]['env']:
            if entry['name'] == 'WEBAUTHN_ORIGIN':
                entry['value'] = 'http://localhost:18091'
        return docs
    deployment.render = render
    os.environ['ZTA_IDENTITY_PORT'] = '19082'
    os.environ['ZTA_GATEWAY_PORT'] = '19443'
    return deployment


def verify(deployment):
    from cryptography.hazmat.primitives import serialization
    import httpx
    from scripts.security_inspector import SecurityOperator
    from tests.authenticator import Authenticator, b64
    import base64
    operator = SecurityOperator()
    report = {'started_at': datetime.now(timezone.utc).isoformat(), 'environment': deployment.CONTEXT,
              'passed': False, 'checks': [], 'authenticator': 'software test authenticator; real WebAuthn server verification'}
    def check(name, condition, **evidence):
        report['checks'].append({'name': name, 'passed': bool(condition), **evidence})
        assert condition, name
        print('PASS '+name, flush=True)
    users = []
    try:
        with httpx.Client(base_url='http://localhost:18091', trust_env=False, timeout=20) as client:
            for subject, owner, expected in [('alice','alice',200), ('alice','bob',403), ('alice','carol',403),
                                             ('bob','bob',200), ('bob','alice',200), ('bob','carol',403)]:
                if not users or users[-1] != subject:
                    path = deployment.STATE/('portal-authenticator-'+subject+'.json')
                    auth = Authenticator()
                    if path.exists():
                        saved = json.loads(path.read_text())
                        auth.key = serialization.load_pem_private_key(saved['key'].encode(), password=None)
                        auth.id = base64.urlsafe_b64decode(saved['id']+'==')
                        auth.counter = saved['counter']
                    else:
                        invite = operator.control('identity', '/enrollment/invite', 'POST', {'subject': subject})
                        opts = operator.identity('register/options', {'invitation': invite['invitation']}).json()
                        response = operator.identity('register/verify', {'ceremony': opts['ceremony'], 'credential': auth.register(opts['publicKey'], origin='http://localhost:18091')})
                        assert response.status_code == 200, response.text
                    session = client.get('/api/portal/session').json()
                    h = {'x-portal-csrf': session['csrf']}
                    opts = client.post('/api/portal/login/options', json={'subject': subject}, headers=h).json()
                    credential = auth.login(opts['publicKey'], origin='http://localhost:18091')
                    data = {'id': b64(auth.id), 'counter': auth.counter,
                            'key': auth.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()}
                    if not path.exists():
                        fd = os.open(path, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
                        os.close(fd)
                    path.write_text(json.dumps(data))
                    login = client.post('/api/portal/login/verify', json={'ceremony': opts['ceremony'], 'credential': credential}, headers=h)
                    check(subject+' real Passkey login', login.status_code == 200, status=login.status_code)
                    h = {'x-portal-csrf': login.json()['csrf']}
                    users.append(subject)
                resources = ('salary', 'profile')
                for resource in resources:
                    job = client.post('/api/portal/access', json={'resource': resource, 'owner': owner}, headers=h)
                    assert job.status_code == 202, job.text
                    deadline = time.monotonic()+90
                    while time.monotonic() < deadline:
                        result = client.get('/api/portal/jobs/'+job.json()['id']).json()
                        if result['state'] != 'running':
                            break
                        time.sleep(.3)
                    assert result['state'] == 'done', result
                    attempt = result['result']
                    check(subject+' '+resource+' '+owner, attempt['responses'][0]['status'] == expected,
                          evidence=attempt)
                    check('Journal queried for '+attempt['attempt_id'], attempt['execution_query_observed'] and
                          (attempt['execution_count'] > 0 if expected == 200 else attempt['execution_count'] == 0))
                    if expected == 403:
                        check('CUSTOM denial and Native ALLOW unobserved', attempt['denial_point'] == 'external_pe' and
                              next(s for s in attempt['stages'] if s['component'] == 'native_allow')['status'] == 'NOT_OBSERVED')
            summaries = client.get('/api/observer/attempts').json()
            check('Both employee snapshots retained', bool(summaries['alice']) and bool(summaries['bob']))
            for endpoint in ('/api/console/session', '/api/inspector/status'):
                check('Employee denied '+endpoint, client.get(endpoint).status_code == 403)
            for endpoint, body in [('/api/inspector/invite', {'subject':'alice'}), ('/api/inspector/recover', {'subject':'bob'}), ('/api/inspector/experiments', {'attack':'pe-outage'})]:
                check('Employee denied '+endpoint, client.post(endpoint, json=body, headers=h).status_code == 403)
            # Save current real snapshots for a separately running browser Observer.
            report['snapshots'] = {s: client.get('/api/observer/attempts/'+v['attempt_id']).json() for s,v in summaries.items()}
        report['passed'] = True
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        destination = ROOT/'artifacts/portal-p0-e2e.json'
        destination.parent.mkdir(exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['deploy', 'serve', 'verify'])
    args = parser.parse_args()
    deployment = configure()
    if args.action == 'deploy':
        deployment.up()
    elif args.action == 'verify':
        verify(deployment)
    else:
        from scripts.security_inspector import main as serve
        sys.argv = [sys.argv[0], '--port', '18091']
        serve()


if __name__ == '__main__':
    main()
