"""Reproducible, isolated kind + Istio demo. Requires Docker, kind, kubectl, istioctl.

Every Kubernetes command uses both a dedicated kubeconfig and explicit context.
No credentials, private keys or raw Envoy secret dumps are written to evidence.
"""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

from cryptography import x509

ROOT = Path(__file__).resolve().parents[1]
NS = CLUSTER = 'zta-207a'
CONTEXT = 'kind-' + CLUSTER
IMAGE = 'zta-207a:local'
ISTIO_VERSION = '1.31.1'
KIND_VERSION = 'v0.33.0'
NODE_IMAGE = 'kindest/node:v1.35.0'

HTTP_PROBE = '''import json,sys,httpx
p=json.loads(sys.argv[1])
try:
    r=httpx.request(p['method'],p['url'],headers=p['headers'],timeout=4,trust_env=False)
    try: data=r.json()
    except ValueError: data=None
    print(json.dumps({'status':r.status_code,'data':data}))
except httpx.HTTPError as e:
    print(json.dumps({'status':0,'error':type(e).__name__}))
'''


def run(args, *, data=None, quiet=False, check=True, timeout=900):
    if not quiet:
        print('+ ' + ' '.join(str(a) for a in args), flush=True)
    p = subprocess.run([str(a) for a in args], input=data, text=True,
                       encoding='utf-8', capture_output=True, cwd=ROOT, timeout=timeout)
    if p.returncode and check:
        raise RuntimeError(f'{args[0]} failed ({p.returncode}): {p.stderr[-4000:]} {p.stdout[-2000:]}')
    if not quiet and p.stdout.strip():
        print(p.stdout.strip(), flush=True)
    return p.stdout.strip()


class Demo:
    def __init__(self, args):
        self.args = args
        self.kubeconfig = Path(args.kubeconfig).resolve()
        self.kube = [args.kubectl, '--kubeconfig', str(self.kubeconfig), '--context', CONTEXT]
        self.istio = [args.istioctl, '--kubeconfig', str(self.kubeconfig), '--context', CONTEXT]

    def k(self, *args, **kwargs):
        return run(self.kube + list(args), **kwargs)

    def apply(self, value):
        return self.k('apply', '-f', '-', data=json.dumps(value), quiet=True)

    def rollout(self, name):
        self.k('-n', NS, 'rollout', 'status', 'deployment/' + name, '--timeout=180s')

    def configmap(self, policy):
        self.apply({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'service-policy', 'namespace': NS},
                    'data': {'service-policy.json': json.dumps(policy)}})
        # Trigger kubelet to refresh projected volumes promptly, without restarting PE.
        pods = json.loads(self.k('-n', NS, 'get', 'pods', '-l', 'app=pe', '-o', 'json', quiet=True))
        for pod in pods['items']:
            self.k('-n', NS, 'annotate', 'pod', pod['metadata']['name'],
                   'policy-refresh=' + str(time.time_ns()), '--overwrite', quiet=True)

    def up(self):
        version = run([self.args.kind, 'version'], quiet=True)
        if KIND_VERSION not in version:
            raise RuntimeError(f'Expected kind {KIND_VERSION}; got {version}')
        version = json.loads(run([self.args.istioctl, 'version', '--remote=false', '-o', 'json'], quiet=True))
        if version['clientVersion']['version'] != ISTIO_VERSION:
            raise RuntimeError('Use istioctl ' + ISTIO_VERSION)
        self.kubeconfig.parent.mkdir(parents=True, exist_ok=True)
        clusters = run([self.args.kind, 'get', 'clusters'], quiet=True).splitlines()
        if CLUSTER not in clusters:
            run([self.args.kind, 'create', 'cluster', '--name', CLUSTER, '--image', NODE_IMAGE,
                 '--config', 'mesh/kind.yaml', '--kubeconfig', self.kubeconfig, '--wait', '180s'])
        else:
            run([self.args.kind, 'export', 'kubeconfig', '--name', CLUSTER, '--kubeconfig', self.kubeconfig])
        run(['docker', 'build', '-f', 'Dockerfile.mesh', '-t', IMAGE, '.'])
        run([self.args.kind, 'load', 'docker-image', IMAGE, '--name', CLUSTER])
        run(self.istio + ['install', '-y', '-f', 'mesh/istio.yaml', '--verify'])
        # Establish default-deny before scheduling application workloads.
        self.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {
            'name': NS, 'labels': {'istio-injection': 'enabled'}}})
        self.k('apply', '-f', 'mesh/security.yaml')
        self.k('apply', '-f', 'mesh/workloads.yaml')
        for name in ('frontend', 'salary', 'profile', 'probe', 'intruder', 'plaintext'):
            self.k('-n', NS, 'rollout', 'restart', 'deployment/' + name, quiet=True)
            self.rollout(name)
        if self.args.external_authz:
            self.enable_external()
        run(self.istio + ['analyze', '-n', NS])

    def enable_external(self):
        # Reuse a cluster-local random key on repeat setup; never display it.
        existing = self.k('-n', NS, 'get', 'secret', 'mesh-control', '--ignore-not-found', '-o', 'name', quiet=True)
        if not existing:
            self.apply({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'mesh-control', 'namespace': NS},
                        'type': 'Opaque', 'stringData': {'service-key': secrets.token_urlsafe(48)}})
        self.configmap(json.loads((ROOT / 'mesh/service-policy.json').read_text()))
        self.k('apply', '-f', 'mesh/ext-authz-workloads.yaml')
        # Install supporting ALLOW policies before activating backend CUSTOM.
        self.k('apply', '-f', 'mesh/ext-authz-policies.yaml')
        for name in ('context', 'pe', 'mesh-authz'):
            self.k('-n', NS, 'rollout', 'restart', 'deployment/' + name, quiet=True)
            self.rollout(name)

    def request(self, caller, target, path, method='GET', headers=None):
        value = {'url': f'http://{target}:8000{path}', 'method': method, 'headers': headers or {}}
        return json.loads(self.k('-n', NS, 'exec', 'deployment/' + caller, '-c', 'app', '--',
                                 'python', '-c', HTTP_PROBE, json.dumps(value), quiet=True))

    def expect(self, checks, name, caller, target, path, statuses, *, method='GET', headers=None, resource=None, wait=45):
        deadline = time.monotonic() + wait
        while True:
            result = self.request(caller, target, path, method, headers)
            passed = result['status'] in statuses
            if resource:
                passed = passed and isinstance(result.get('data'), dict) and result['data'].get('resource') == resource
            if passed or time.monotonic() >= deadline:
                break
            time.sleep(1)
        checks.append({'name': name, 'passed': passed, 'expected_status': statuses, 'result': result})
        print(('PASS ' if passed else 'FAIL ') + name + ': ' + str(result['status']), flush=True)
        if not passed:
            raise AssertionError(name + ': ' + json.dumps(result))

    def certificates(self):
        pods = json.loads(self.k('-n', NS, 'get', 'pods', '-o', 'json', quiet=True))['items']
        result = []
        for pod in pods:
            name = pod['metadata']['name']
            app = pod['metadata']['labels']['app']
            if app == 'plaintext':
                if any(c['name'] == 'istio-proxy' for c in pod['spec']['containers']):
                    raise AssertionError('Plaintext negative client unexpectedly has sidecar')
                continue
            if not any(c['name'] == 'istio-proxy' for c in pod['spec']['containers']):
                raise AssertionError(name + ' has no sidecar')
            raw = json.loads(run(self.istio + ['proxy-config', 'secret', name, '-n', NS, '-o', 'json'], quiet=True))
            # Consume only the public certificate; do not persist the raw secret dump.
            chains = [s['secret']['tlsCertificate']['certificateChain']['inlineBytes']
                      for s in raw['dynamicActiveSecrets'] if 'tlsCertificate' in s.get('secret', {})]
            if not chains:
                raise AssertionError('No active workload certificate on ' + name)
            cert = x509.load_pem_x509_certificate(base64.b64decode(chains[0]))
            uris = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
            expected = 'spiffe://cluster.local/ns/' + NS + '/sa/' + pod['spec']['serviceAccountName']
            if expected not in uris or cert.not_valid_after_utc <= datetime.now(timezone.utc):
                raise AssertionError('Missing/expired workload identity on ' + name)
            result.append({'app': app, 'pod': name, 'uri': expected,
                           'not_after': cert.not_valid_after_utc.isoformat(), 'sidecar': True})
        return result

    def verify(self):
        evidence = {'started_at': datetime.now(timezone.utc).isoformat(), 'context': CONTEXT,
                    'external_authz': self.args.external_authz, 'checks': [], 'passed': False}
        checks = evidence['checks']
        output = ROOT / 'artifacts' / ('mesh-external.json' if self.args.external_authz else 'mesh-base.json')
        try:
            evidence['kubernetes'] = json.loads(self.k('version', '-o', 'json', quiet=True))['serverVersion']['gitVersion']
            evidence['revision'] = run(['git', 'rev-parse', 'HEAD'], quiet=True)
            evidence['certificates'] = self.certificates()
            for name in ('salary', 'profile'):
                self.expect(checks, 'authorized chain to ' + name, 'probe', 'frontend', '/api/' + name, [200], resource=name)
            self.expect(checks, 'query preserves allowed path', 'frontend', 'salary', '/api/salary?trace=1', [200], resource='salary')
            self.expect(checks, 'wrong workload identity', 'intruder', 'salary', '/api/salary', [403])
            self.expect(checks, 'probe cannot bypass frontend', 'probe', 'salary', '/api/salary', [403])
            self.expect(checks, 'wrong method', 'frontend', 'salary', '/api/salary', [403], method='POST')
            self.expect(checks, 'wrong path', 'frontend', 'salary', '/api/profile', [403])
            self.expect(checks, 'health route has no implicit grant', 'intruder', 'salary', '/health', [403])
            self.expect(checks, 'forged identity headers', 'intruder', 'salary', '/api/salary', [403], headers={
                'x-forwarded-client-cert': 'URI=spiffe://cluster.local/ns/zta-207a/sa/frontend',
                'x-zta-subject': 'alice', 'x-zta-session': 'invented'})
            self.expect(checks, 'plaintext rejected by STRICT mTLS', 'plaintext', 'salary', '/api/salary', [0, 503])
            ip = json.loads(self.k('-n', NS, 'get', 'pods', '-l', 'app=salary', '-o', 'json', quiet=True))['items'][0]['status']['podIP']
            self.expect(checks, 'direct Pod IP cannot bypass PEP', 'intruder', ip, '/api/salary', [0, 403, 503])
            deny = {'apiVersion': 'security.istio.io/v1', 'kind': 'AuthorizationPolicy',
                    'metadata': {'name': 'temporary-revoke', 'namespace': NS},
                    'spec': {'selector': {'matchLabels': {'app': 'salary'}}, 'action': 'DENY', 'rules': [{}]}}
            try:
                self.apply(deny)
                self.expect(checks, 'native policy revocation', 'frontend', 'salary', '/api/salary', [403])
            finally:
                self.k('-n', NS, 'delete', 'authorizationpolicy', 'temporary-revoke', '--ignore-not-found', quiet=True)
            self.expect(checks, 'native policy restored', 'frontend', 'salary', '/api/salary', [200], resource='salary')
            if self.args.external_authz:
                self.verify_external(checks)
            evidence['passed'] = True
        finally:
            evidence['finished_at'] = datetime.now(timezone.utc).isoformat()
            output.parent.mkdir(exist_ok=True)
            output.write_text(json.dumps(evidence, indent=2), encoding='utf-8')
            print('Evidence: ' + str(output), flush=True)

    def verify_external(self, checks):
        self.expect(checks, 'client cannot forge gRPC PE inputs', 'probe', 'pe', '/evaluate-service', [403], method='POST')
        policy = json.loads((ROOT / 'mesh/service-policy.json').read_text())
        try:
            self.configmap({'version': 2, 'grants': []})
            self.expect(checks, 'PE policy reload revokes without restart', 'frontend', 'salary', '/api/salary', [403], wait=150)
        finally:
            self.configmap(policy)
        self.expect(checks, 'PE policy restored', 'frontend', 'salary', '/api/salary', [200], resource='salary', wait=150)
        for target in ('mesh-authz', 'pe', 'context'):
            try:
                self.k('-n', NS, 'scale', 'deployment/' + target, '--replicas=0', quiet=True)
                self.expect(checks, target + ' outage fails closed', 'frontend', 'salary', '/api/salary', [403, 503])
            finally:
                self.k('-n', NS, 'scale', 'deployment/' + target, '--replicas=1', quiet=True)
                self.rollout(target)
            self.expect(checks, target + ' restored', 'frontend', 'salary', '/api/salary', [200], resource='salary')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', default=os.environ.get('KIND', 'kind'))
    parser.add_argument('--istioctl', default=os.environ.get('ISTIOCTL', 'istioctl'))
    parser.add_argument('--kubectl', default=os.environ.get('KUBECTL', 'kubectl'))
    parser.add_argument('--kubeconfig', default=str(ROOT / '.tmp/mesh-kubeconfig'))
    parser.add_argument('--external-authz', action='store_true')
    parser.add_argument('action', choices=('up', 'verify', 'status', 'down'))
    args = parser.parse_args()
    demo = Demo(args)
    if args.action == 'up':
        demo.up()
    elif args.action == 'verify':
        demo.verify()
    elif args.action == 'status':
        demo.k('-n', NS, 'get', 'pods,svc,peerauthentication,authorizationpolicy')
    elif args.action == 'down':
        # Deletes ONLY this fixed-name disposable cluster. Opt-in command, never automatic.
        run([args.kind, 'delete', 'cluster', '--name', CLUSTER, '--kubeconfig', demo.kubeconfig])


if __name__ == '__main__':
    main()
