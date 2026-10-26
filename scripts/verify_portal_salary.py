"""Actual salary-write acceptance against ONLY the dedicated P0 environment."""
from datetime import datetime, timezone
import base64
import hashlib
import json
from pathlib import Path
import sys
import time

import httpx
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.portal_demo import configure
from tests.authenticator import Authenticator


def run():
    deployment = configure()
    report = {'started_at': datetime.now(timezone.utc).isoformat(), 'environment': deployment.CONTEXT,
              'passed': False, 'checks': [], 'authenticator': 'test-only software authenticator; real server signature verification'}
    digest = hashlib.sha256()
    for pattern in ('app/*.py', 'console/*', 'scripts/*.py'):
        for path in sorted(ROOT.glob(pattern)):
            digest.update(path.relative_to(ROOT).as_posix().encode())
            digest.update(path.read_bytes())
    report['source_digest_sha256'] = digest.hexdigest()
    def check(name, condition, **evidence):
        report['checks'].append({'name': name, 'passed': bool(condition), **evidence})
        assert condition, name
        print('PASS '+name, flush=True)
    try:
        with httpx.Client(base_url='http://localhost:18091', trust_env=False, timeout=20) as client:
            def passkey(subject, *, step_up=False):
                path = deployment.STATE/('portal-authenticator-'+subject+'.json')
                if not path.exists():
                    raise RuntimeError('Run portal_demo.py verify first; never enroll on another environment')
                saved = json.loads(path.read_text())
                auth = Authenticator()
                auth.key = serialization.load_pem_private_key(saved['key'].encode(), password=None)
                auth.id = base64.urlsafe_b64decode(saved['id']+'==')
                auth.counter = saved['counter']
                session = client.get('/api/portal/session').json()
                h = {'x-portal-csrf': session['csrf']}
                prefix = '/api/portal/step-up' if step_up else '/api/portal/login'
                options = client.post(prefix+'/options', json={} if step_up else {'subject':subject}, headers=h)
                assert options.status_code == 200, options.text
                opts = options.json()
                credential = auth.login(opts['publicKey'], origin='http://localhost:18091')
                saved['counter'] = auth.counter
                path.write_text(json.dumps(saved))
                response = client.post(prefix+'/verify', json={'ceremony':opts['ceremony'],'credential':credential}, headers=h)
                check(subject+(' Step-Up' if step_up else ' login'), response.status_code == 200, status=response.status_code)
                return h if step_up else {'x-portal-csrf': response.json()['csrf']}
            def job(endpoint, body, h):
                response = client.post(endpoint, json=body, headers=h)
                assert response.status_code == 202, response.text
                deadline = time.monotonic()+90
                while time.monotonic()<deadline:
                    state = client.get('/api/portal/jobs/'+response.json()['id']).json()
                    if state['state'] != 'running':
                        assert state['state'] == 'done', state
                        return state['result']
                    time.sleep(.3)
                raise TimeoutError('Salary attempt did not finish')
            h = passkey('alice')
            passkey('alice', step_up=True)
            denied = job('/api/portal/salary/adjust', {'owner':'alice','amount':60000}, h)
            check('Alice actual salary-write denial at PA exchange', denied['responses'][0]['status'] == 403 and
                  denied['denial_point'] == 'token_exchange' and denied['reason'] == 'session_scope_exceeded', evidence=denied)
            check('Alice no invented PE denial and journal queried', denied['execution_query_observed'] and denied['execution_count'] == 0 and
                  next(s for s in denied['stages'] if s['component']=='external_pe')['status']=='NOT_OBSERVED')
            h = passkey('bob')
            passkey('bob', step_up=True)
            denied = job('/api/portal/salary/adjust', {'owner':'carol','amount':60000}, h)
            check('Bob Carol write rejected by PE', denied['responses'][0]['status'] == 403 and denied['denial_point']=='external_pe' and
                  denied['execution_query_observed'] and denied['execution_count']==0, evidence=denied)
            passkey('bob', step_up=True)
            changed = job('/api/portal/salary/adjust', {'owner':'alice','amount':60000}, h)
            check('Bob Alice actual salary mutation', changed['responses'][0]['status']==200 and
                  changed['responses'][0]['data']['amount']==60000 and changed['execution_count']>0, evidence=changed)
            read = job('/api/portal/access', {'resource':'salary','owner':'alice'}, h)
            check('Read-after-write returns persisted 60000', read['responses'][0]['status']==200 and
                  read['responses'][0]['data']['amount']==60000, evidence=read)
            # Finish on an actual write, leaving Alice's PA denial and Bob's successful full flow visible.
            passkey('bob', step_up=True)
            changed = job('/api/portal/salary/adjust', {'owner':'alice','amount':60000}, h)
            check('Repeated write requires another genuine Step-Up', changed['responses'][0]['status']==200, evidence=changed)
        report['passed'] = True
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        destination = ROOT/'artifacts/portal-salary-e2e.json'
        destination.parent.mkdir(exist_ok=True)
        destination.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')


if __name__ == '__main__':
    run()
