"""Deploy the identity prototype in its own kind cluster; never clean user data."""
import argparse
import copy
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
NS = CLUSTER = 'zta-identity'
CONTEXT = 'kind-' + CLUSTER
IMAGE = 'zta-identity:local'
STATE = ROOT / '.tmp/identity'
KUBECONFIG = STATE / 'kubeconfig'


def tool(name):
    local = ROOT.parent / '.tools' / ('istioctl/istioctl.exe' if name == 'istioctl' else name+'.exe')
    return str(local) if local.exists() else shutil.which(name) or name


def run(args, data=None, timeout=900, quiet=False):
    p = subprocess.run([str(a) for a in args], input=data, text=True, encoding='utf-8',
                       errors='replace', capture_output=True, cwd=ROOT, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f'{Path(str(args[0])).name} failed: {p.stderr[-2000:]} {p.stdout[-1000:]}')
    if not quiet and p.stdout.strip():
        print(p.stdout.strip(), flush=True)
    return p.stdout.strip()


def k(*args, **kwargs):
    return run([tool('kubectl'), '--kubeconfig', KUBECONFIG, '--context', CONTEXT,
                '--request-timeout=20s', '-n', NS, *args], **kwargs)


def load(name):
    return list(yaml.safe_load_all((ROOT / name).read_text(encoding='utf-8')))


def allow(name, app, source, paths, methods=('POST',), port='8000'):
    return {'apiVersion': 'security.istio.io/v1', 'kind': 'AuthorizationPolicy',
            'metadata': {'name': name, 'namespace': NS}, 'spec': {
        'selector': {'matchLabels': {'app': app}}, 'action': 'ALLOW', 'rules': [{
            'from': [{'source': {'principals': ['cluster.local/ns/'+NS+'/sa/'+s for s in source]}}],
            'to': [{'operation': {'ports': [port], 'methods': list(methods), 'paths': paths}}]}]}}


def render(jwks):
    public = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'user-jwks', 'namespace': NS},
              'data': {'jwks.json': json.dumps(jwks)}}
    docs = load('mesh/workloads.yaml') + load('mesh/ext-authz-workloads.yaml')
    docs = json.loads(json.dumps(docs).replace('zta-207a', NS))
    template = next(d for d in docs if d['kind'] == 'Deployment' and d['metadata']['name'] == 'context')
    for name in ('identity', 'pa'):
        d = copy.deepcopy(template)
        d['metadata']['name'] = name
        d['spec']['selector']['matchLabels']['app'] = name
        pod = d['spec']['template']
        pod['metadata']['labels'] = {'app': name}
        pod['spec']['serviceAccountName'] = name
        pod['spec']['containers'][0]['command'][1] = 'app.'+name+':app'
        docs += [d, {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': name, 'namespace': NS},
                     'automountServiceAccountToken': False},
                 {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': name, 'namespace': NS},
                  'spec': {'selector': {'app': name}, 'ports': [{'name': 'http', 'port': 8000, 'targetPort': 8000}]}}]
    for d in docs:
        if d['kind'] != 'Deployment':
            continue
        name = d['metadata']['name']
        pod = d['spec']['template']
        spec = pod['spec']
        container = spec['containers'][0]
        container['image'] = IMAGE
        env = container.setdefault('env', [])
        env += [{'name': 'IDENTITY_MODE', 'value': '1'}]
        # PE now owns dynamic policy; the old service-policy file is unused.
        env[:] = [e for e in env if e['name'] != 'SERVICE_POLICY_FILE']
        spec['volumes'] = [v for v in spec.get('volumes', []) if v['name'] not in ('policy', 'state')]
        container['volumeMounts'] = [v for v in container.get('volumeMounts', []) if v['name'] not in ('policy', 'state')]
        if name in ('frontend', 'salary', 'profile', 'pe'):
            env.append({'name': 'USER_JWKS_FILE', 'value': '/public/jwks.json'})
            spec['volumes'].append({'name': 'user-jwks', 'configMap': {'name': 'user-jwks'}})
            container['volumeMounts'].append({'name': 'user-jwks', 'mountPath': '/public', 'readOnly': True})
        if name in ('frontend', 'salary', 'profile'):
            pod['metadata']['labels']['identity-protected'] = 'true'
        if name in ('salary', 'profile', 'pe', 'pa', 'identity', 'context'):
            env.append({'name': 'STATE_DIR', 'value': '/state'})
            spec['securityContext'] = {'fsGroup': 10001}
            spec['volumes'].append({'name': 'state', 'persistentVolumeClaim': {'claimName': name+'-state'}})
            container['volumeMounts'].append({'name': 'state', 'mountPath': '/state'})
        if name == 'context':
            env.append({'name': 'HR_MODE', 'value': '1'})
        if name == 'identity':
            env.append({'name': 'WEBAUTHN_ORIGIN', 'value': 'http://localhost:18081'})
        if name == 'pa':
            env.append({'name': 'USER_SIGNING_KEY_FILE', 'value': '/signing/signing.pem'})
            spec['volumes'].append({'name': 'user-signing', 'secret': {'secretName': 'user-signing', 'defaultMode': 0o440}})
            container['volumeMounts'].append({'name': 'user-signing', 'mountPath': '/signing', 'readOnly': True})
    policies = load('mesh/identity-security.yaml')
    next(d for d in policies if d['kind'] == 'RequestAuthentication')['spec']['jwtRules'][0]['jwks'] = json.dumps(jwks)
    policies += [
        allow('backend-to-authz', 'mesh-authz', ['salary', 'profile'], ['*'], ('*',), '9000'),
        allow('authz-to-pe', 'pe', ['mesh-authz'], ['/evaluate-resource']),
        allow('pa-to-pe', 'pe', ['pa'], ['/evaluate']),
        allow('pe-to-pa', 'pa', ['pe'], ['/credential-context']),
        allow('gateway-to-pa', 'pa', ['device-gateway'], ['/session', '/token/exchange']),
        allow('pa-to-identity', 'identity', ['pa'], ['/introspect']),
        allow('controls-to-context', 'context', ['pa', 'pe'], ['/event', '/snapshot'], ('GET', 'POST')),
    ]
    # mTLS device gateway uses the existing SANITIZE_SET configuration, isolated PKI.
    envoy = load('envoy/envoy.yaml')[0]
    envoy['static_resources']['listeners'] = envoy['static_resources']['listeners'][:1]
    listener = envoy['static_resources']['listeners'][0]
    hcm = listener['filter_chains'][0]['filters'][0]['typed_config']
    hcm['http_filters'] = [f for f in hcm['http_filters'] if f['name'] == 'envoy.filters.http.router']
    hcm['http_filters'].insert(0, {'name': 'envoy.filters.http.jwt_authn', 'typed_config': {
        '@type': 'type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication',
        'providers': {'user': {'issuer': 'https://zta.example/identity', 'audiences': ['zta-hr'],
            'local_jwks': {'inline_string': json.dumps(jwks)}, 'forward': True,
            'from_headers': [{'name': 'Authorization', 'value_prefix': 'Bearer '}]}},
        'rules': [{'match': {'prefix': '/api/'}, 'requires': {'provider_name': 'user'}}]}})
    hcm['route_config']['virtual_hosts'][0]['routes'] = [
        {'match': {'path': p}, 'route': {'cluster': 'pa', 'host_rewrite_literal': 'pa:8000', 'timeout': '5s'}} for p in ('/session', '/token/exchange')]
    hcm['route_config']['virtual_hosts'][0]['routes'].append(
        {'match': {'prefix': '/api/'}, 'route': {'cluster': 'frontend', 'host_rewrite_literal': 'frontend:8000', 'timeout': '10s'}})
    envoy['static_resources']['clusters'] = envoy['static_resources']['clusters'][:1]
    frontend_cluster = copy.deepcopy(envoy['static_resources']['clusters'][0])
    frontend_cluster['name'] = frontend_cluster['load_assignment']['cluster_name'] = 'frontend'
    frontend_cluster['load_assignment']['endpoints'][0]['lb_endpoints'][0]['endpoint']['address']['socket_address']['address'] = 'frontend'
    envoy['static_resources']['clusters'].append(frontend_cluster)
    hcm['access_log'] = [{'name': 'envoy.access_loggers.stdout', 'typed_config': {
        '@type': 'type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog',
        'log_format': {'json_format': access_log_format()}}}]
    gateway = copy.deepcopy(template)
    gateway['metadata'] = {'name': 'device-gateway', 'namespace': NS}
    gateway['spec']['selector']['matchLabels'] = {'app': 'device-gateway'}
    pod = gateway['spec']['template']
    pod['metadata']['labels'] = {'app': 'device-gateway'}
    spec = pod['spec']
    spec['serviceAccountName'] = 'device-gateway'
    container = spec['containers'][0]
    container.update(image='envoyproxy/envoy:v1.33.2', command=['envoy', '-c', '/config/envoy.yaml', '--disable-hot-restart', '--log-level', 'warning'],
        env=[], ports=[{'containerPort': 8443, 'name': 'https'}],
        readinessProbe={'tcpSocket': {'port': 8443}, 'periodSeconds': 3},
        volumeMounts=[{'name': 'config', 'mountPath': '/config', 'readOnly': True},
                      {'name': 'certs', 'mountPath': '/certs', 'readOnly': True}])
    spec['volumes'] = [{'name': 'config', 'configMap': {'name': 'device-gateway'}},
                       {'name': 'certs', 'secret': {'secretName': 'device-gateway-pki', 'defaultMode': 0o440}}]
    spec['securityContext'] = {'fsGroup': 10001}
    docs += [gateway, {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': 'device-gateway', 'namespace': NS},
                       'automountServiceAccountToken': False},
             {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'device-gateway', 'namespace': NS},
              'spec': {'selector': {'app': 'device-gateway'}, 'ports': [{'name': 'https', 'port': 8443, 'targetPort': 8443}]}},
             {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'device-gateway', 'namespace': NS},
              'data': {'envoy.yaml': yaml.safe_dump(envoy)}}]
    for name in ('salary', 'profile', 'pe', 'pa', 'identity', 'context'):
        docs.append({'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {'name': name+'-state', 'namespace': NS},
                     'spec': {'accessModes': ['ReadWriteOnce'], 'resources': {'requests': {'storage': '100Mi'}}}})
    docs += [public, *policies]
    # The edge Envoy replaces XFCC from its verified device certificate. Preserve
    # that assertion only across the gateway→PA workload-authenticated hop. Istio
    # would otherwise replace it with the gateway's SPIFFE certificate. PA's
    # native policy permits /session and /token/exchange only from this gateway.
    for app, context in [('device-gateway', 'SIDECAR_OUTBOUND'), ('pa', 'SIDECAR_INBOUND')]:
        docs.append({'apiVersion': 'networking.istio.io/v1alpha3', 'kind': 'EnvoyFilter',
            'metadata': {'name': 'device-assertion-'+app, 'namespace': NS}, 'spec': {
                'workloadSelector': {'labels': {'app': app}}, 'configPatches': [{
                    'applyTo': 'NETWORK_FILTER', 'match': {'context': context, 'listener': {
                        'filterChain': {'filter': {'name': 'envoy.filters.network.http_connection_manager'}}}},
                    'patch': {'operation': 'MERGE', 'value': {'typed_config': {
                        '@type': 'type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',
                        'forward_client_cert_details': 'ALWAYS_FORWARD_ONLY'}}}}]}})
    return docs


def up():
    if 'v0.33.0' not in run([tool('kind'), 'version'], quiet=True):
        raise RuntimeError('Use pinned kind v0.33.0')
    version = json.loads(run([tool('istioctl'), 'version', '--remote=false', '-o', 'json'], quiet=True))
    if version['clientVersion']['version'] != '1.31.1':
        raise RuntimeError('Use pinned istioctl 1.31.1')
    STATE.mkdir(parents=True, exist_ok=True)
    clusters = run([tool('kind'), 'get', 'clusters'], quiet=True).splitlines()
    if CLUSTER not in clusters:
        run([tool('kind'), 'create', 'cluster', '--name', CLUSTER, '--image', 'kindest/node:v1.35.0',
             '--kubeconfig', KUBECONFIG, '--wait', '180s'])
    else:
        run([tool('kind'), 'export', 'kubeconfig', '--name', CLUSTER, '--kubeconfig', KUBECONFIG])
    run(['docker', 'build', '-f', 'Dockerfile.mesh', '-t', IMAGE, '.'])
    run([tool('kind'), 'load', 'docker-image', IMAGE, '--name', CLUSTER])
    istio = load('mesh/istio.yaml')[0]
    istio['spec']['meshConfig']['accessLogFormat'] = json.dumps(access_log_format())
    provider = istio['spec']['meshConfig']['extensionProviders'][0]
    provider['name'] = 'identity-pe'
    provider['envoyExtAuthzGrpc']['service'] = 'mesh-authz.'+NS+'.svc.cluster.local'
    run([tool('istioctl'), '--kubeconfig', KUBECONFIG, '--context', CONTEXT, 'install', '-y', '-f', '-'], data=yaml.safe_dump(istio))
    namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NS, 'labels': {'istio-injection': 'enabled'}}}
    k('apply', '-f', '-', data=json.dumps(namespace))
    from scripts.init import initialize
    initialize(STATE)
    signing = STATE / 'signing.pem'
    existing = k('get', 'secret', 'user-signing', '--ignore-not-found', '-o', 'name', quiet=True)
    if not signing.exists():
        if existing:
            raise RuntimeError('Signing key exists in cluster; restore local key before retrying. Refusing rotation.')
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        value = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        fd = os.open(signing, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value)
    from app.user_tokens import public_jwks
    os.environ['USER_SIGNING_KEY_FILE'] = str(signing)
    jwks = public_jwks()
    (STATE / 'jwks.json').write_text(json.dumps(jwks), encoding='utf-8')
    for name, values in [('user-signing', {'signing.pem': signing.read_text()}),
                         ('device-gateway-pki', {n: (STATE/'certs'/n).read_text() for n in ('pep.crt', 'pep.key', 'device-ca.crt')})]:
        if not k('get', 'secret', name, '--ignore-not-found', '-o', 'name', quiet=True):
            k('apply', '-f', '-', data=json.dumps({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name, 'namespace': NS}, 'stringData': values}), quiet=True)
    if not k('get', 'secret', 'mesh-control', '--ignore-not-found', '-o', 'name', quiet=True):
        k('apply', '-f', '-', data=json.dumps({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'mesh-control', 'namespace': NS},
          'stringData': {'service-key': secrets.token_urlsafe(48)}}), quiet=True)
    docs = render(jwks)
    # Default deny, JWT requirements and CUSTOM are installed before applications.
    docs.sort(key=lambda d: 0 if d['kind'] in ('AuthorizationPolicy', 'PeerAuthentication', 'RequestAuthentication') else 1)
    k('apply', '-f', '-', data=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': docs}))
    for name in ('context', 'identity', 'pe', 'pa', 'mesh-authz', 'salary', 'profile', 'frontend', 'probe', 'intruder', 'plaintext', 'device-gateway'):
        k('rollout', 'restart', 'deployment/'+name, quiet=True)
    for name in ('context', 'identity', 'pe', 'pa', 'mesh-authz', 'salary', 'profile', 'frontend', 'probe', 'intruder', 'plaintext', 'device-gateway'):
        k('rollout', 'status', 'deployment/'+name, '--timeout=180s')
    run([tool('istioctl'), '--kubeconfig', KUBECONFIG, '--context', CONTEXT, 'analyze', '-n', NS])


def access_log_format():
    return dict(request_id='%REQ(X-REQUEST-ID)%', attempt_id='%REQ(X-ATTEMPT-ID)%',
        path='%REQ(:PATH)%', method='%REQ(:METHOD)%', response_code='%RESPONSE_CODE%',
        response_code_details='%RESPONSE_CODE_DETAILS%', response_flags='%RESPONSE_FLAGS%',
        downstream_peer='%DOWNSTREAM_PEER_URI_SAN%', upstream_peer='%UPSTREAM_PEER_URI_SAN%',
        downstream_tls='%DOWNSTREAM_TLS_VERSION%', upstream_tls='%UPSTREAM_TLS_VERSION%',
        upstream_cluster='%UPSTREAM_CLUSTER%')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['up', 'status'])
    args = parser.parse_args()
    if args.action == 'up':
        up()
    else:
        k('get', 'pods,svc,authorizationpolicy,requestauthentication,pvc')
