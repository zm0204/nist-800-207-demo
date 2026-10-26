"""Read-only resource scenarios against ONLY the existing dedicated Portal cluster.

Uses existing test credentials with genuine server WebAuthn verification. Never
enrolls a credential, changes policies/risk, writes salary, or clears state.
"""
import base64
from datetime import datetime, timezone
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
    assert deployment.CONTEXT == 'kind-zta-portal-p0'
    report = {'started_at': datetime.now(timezone.utc).isoformat(), 'environment': deployment.CONTEXT,
              'passed': False, 'checks': [], 'snapshots': {},
              'authenticator': 'existing test-only credential; actual server signature and UV verification'}
    def check(name, condition):
        report['checks'].append({'name': name, 'passed': bool(condition)})
        assert condition, name
        print('PASS '+name, flush=True)
    try:
        with httpx.Client(base_url='http://localhost:18091', trust_env=False, timeout=20) as client:
            key = {'x-operator-key': (deployment.STATE/'operator.key').read_text()}
            admin = {**key, 'x-mesh-console': client.get('/api/console/session', headers=key).json()['token']}
            def ceremony(subject, *, inspector=False):
                path = deployment.STATE/('portal-authenticator-'+subject+'.json')
                saved = json.loads(path.read_text())
                auth = Authenticator()
                auth.key = serialization.load_pem_private_key(saved['key'].encode(), password=None)
                auth.id = base64.urlsafe_b64decode(saved['id']+'==')
                auth.counter = saved['counter']
                csrf = {'x-portal-csrf': client.get('/api/portal/session').json()['csrf']}
                prefix, headers = ('/api/identity/login', admin) if inspector else ('/api/portal/login', csrf)
                options = client.post(prefix+'/options', json={'subject': subject}, headers=headers)
                options.raise_for_status()
                opts = options.json()
                credential = auth.login(opts['publicKey'], origin='http://localhost:18091')
                saved['counter'] = auth.counter
                path.write_text(json.dumps(saved))
                response = client.post(prefix+'/verify', json={'ceremony': opts['ceremony'], 'credential': credential}, headers=headers)
                response.raise_for_status()
                return response.json()['token'] if inspector else {'x-portal-csrf': response.json()['csrf']}
            def job(endpoint, body, headers, inspector=False):
                response = client.post(endpoint, json=body, headers=headers)
                response.raise_for_status()
                check('job accepted', response.status_code == 202)
                route = '/api/inspector/jobs/' if inspector else '/api/portal/jobs/'
                deadline = time.monotonic()+90
                while time.monotonic() < deadline:
                    state = client.get(route+response.json()['id'], headers=admin if inspector else {}).json()
                    if state['state'] != 'running':
                        assert state['state'] == 'done', state.get('error')
                        return state['result']
                    time.sleep(.2)
                raise TimeoutError('Attempt did not finish')
            def latest(subject):
                summary = client.get('/api/observer/attempts').json()[subject]
                return client.get('/api/observer/attempts/'+summary['attempt_id']).json() if summary else None
            def stage(snapshot, component):
                return next(s for s in snapshot['stages'] if s['component'] == component)
            bob_h = ceremony('bob')
            job('/api/portal/access', {'resource': 'salary', 'owner': 'alice'}, bob_h)
            bob = latest('bob')
            check('Bob normal request reaches actual app', bob['responses'][0]['status'] == 200 and
                  stage(bob, 'resource')['status'] == 'VERIFIED_PASS' and bob['execution_query_observed'] and bob['execution_count'] > 0)
            report['snapshots']['bob_normal'] = bob
            alice_h = ceremony('alice')
            job('/api/portal/access', {'resource': 'salary', 'owner': 'alice'}, alice_h)
            alice = latest('alice')
            check('Alice normal request has real PE, receiver and Journal success', alice['responses'][0]['status'] == 200 and
                  stage(alice, 'external_pe')['status'] == stage(alice, 'salary')['status'] == stage(alice, 'resource')['status'] == 'VERIFIED_PASS')
            report['snapshots']['alice_normal'] = alice
            job('/api/portal/access', {'resource': 'salary', 'owner': 'bob'}, alice_h)
            denied = latest('alice')
            check('Alice forbidden request PE DENY leaves Native unobserved and app unexecuted', denied['responses'][0]['status'] == 403 and
                  stage(denied, 'external_pe')['status'] == 'VERIFIED_BLOCK' and stage(denied, 'native_allow')['status'] == 'NOT_OBSERVED' and
                  denied['execution_query_observed'] and denied['execution_count'] == 0 and stage(denied, 'resource')['status'] == 'NOT_REACHED')
            report['snapshots']['alice_forbidden'] = denied
            human = ceremony('alice', inspector=True)
            session = client.post('/api/agent/session', json={'resource': 'salary', 'human_token': human}, headers=admin)
            session.raise_for_status()
            exchange = client.post('/api/agent/exchange', json={'session_id': session.json()['session_id']}, headers=admin)
            exchange.raise_for_status()
            token = exchange.json()['access_token']
            def intruder():
                result = job('/api/inspector/experiments', {'token': token, 'resource': 'salary', 'owner': 'alice', 'attack': 'intruder'}, admin, True)
                snapshot = latest('alice')
                check('Inspector publishes exact correlated attempt to Alice', snapshot['attempt_id'] == result['attempt_id'] and snapshot['subject'] == 'alice' and snapshot['origin'] == 'inspector')
                return snapshot
            attack = intruder()
            check('Intruder workload identity remains separate from valid Alice JWT', attack['caller']['principal'] ==
                  'spiffe://cluster.local/ns/zta-identity/sa/intruder' and stage(attack, 'jwt_identity')['status'] == 'VERIFIED_PASS')
            check('Intruder actual PE ALLOW and native refusal', attack['responses'][0]['status'] == 403 and
                  stage(attack, 'external_pe')['status'] == 'VERIFIED_PASS' and stage(attack, 'native_policy')['status'] == 'VERIFIED_BLOCK')
            check('Intruder receiver evidence plus queried empty Journal proves app not reached', attack['execution_query_observed'] and
                  attack['execution_count'] == 0 and stage(attack, 'resource')['status'] == 'NOT_REACHED' and
                  any('rbac_access_denied' in e.get('response_code_details', '') for e in stage(attack, 'salary')['evidence']))
            check('Bob snapshot unchanged across Alice normal, denied and Intruder events', latest('bob') == bob)
            report['snapshots']['alice_intruder'] = attack
            job('/api/portal/access', {'resource': 'profile', 'owner': 'alice'}, alice_h)
            normal_again = latest('alice')
            check('Next normal Alice request replaces attack without affecting Bob', 'caller' not in normal_again and
                  normal_again['responses'][0]['status'] == 200 and latest('bob') == bob)
            report['snapshots']['alice_normal_again'] = normal_again
            check('Observer cannot submit events', client.post('/api/observer/attempts', json={'subject': 'bob'}).status_code == 405)
            check('Employee cannot submit Inspector attack', client.post('/api/inspector/experiments', json={'attack': 'intruder'}, headers=alice_h).status_code == 403)
            for snapshot in report['snapshots'].values():
                text = json.dumps(snapshot)
                check('Public evidence omits credentials and raw claims', all(secret not in text for secret in (token, human, admin['x-operator-key'], session.json()['session_id'], '"claims":', '"sid":', '"jti":')))
            # Leave the requested attack and Bob's independent normal flow visible.
            intruder()
        report['passed'] = True
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        destination = ROOT/'artifacts/inspector-observer-e2e.json'
        destination.parent.mkdir(exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    run()
