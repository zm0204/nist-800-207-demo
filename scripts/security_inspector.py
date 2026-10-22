"""Loopback-only Security Inspector for the isolated identity-aware mesh."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import threading
import time
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict
from starlette.middleware.trustedhost import TrustedHostMiddleware
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.identity_deploy import k, tool, NS, CONTEXT, KUBECONFIG, STATE
from app.inspection import inspect_attempt

PROBE = """import json,sys,httpx
p=json.load(sys.stdin)
try:
 r=httpx.request(p['method'],p['url'],headers=p['headers'],json=p.get('body'),timeout=10,trust_env=False)
 try: data=r.json()
 except ValueError: data=None
 print(json.dumps({'status':r.status_code,'data':data,'text':r.text[:2048]}))
except httpx.HTTPError as e:
 print(json.dumps({'status':0,'error':type(e).__name__}))
"""
CONTROL = """import json,sys,httpx,os
p=json.load(sys.stdin)
r=httpx.request(p['method'],'http://127.0.0.1:8000'+p['path'],json=p.get('body'),headers={'x-service-key':os.environ['SERVICE_KEY']},timeout=10,trust_env=False)
r.raise_for_status()
print(r.text)
"""


@contextmanager
def forwards():
    # Reuse a running Inspector's forwards only after verifying our isolated
    # gateway's TLS certificate with its dedicated CA and device credential.
    try:
        tls = ssl.create_default_context(cafile=str(STATE/'certs/service-ca.crt'))
        tls.load_cert_chain(STATE/'certs/device-a.crt', STATE/'certs/device-a.key')
        with httpx.Client(verify=tls, timeout=1, trust_env=False) as client:
            gateway_ready = client.get('https://localhost:18443/health').status_code == 404
        identity_ready = httpx.get('http://127.0.0.1:18082/health', timeout=1, trust_env=False).status_code == 200
    except (httpx.HTTPError, OSError):
        gateway_ready = identity_ready = False
    if gateway_ready and identity_ready:
        yield
        return
    processes = []
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
    try:
        for service, local, remote in [('identity', 18082, 8000), ('device-gateway', 18443, 8443)]:
            p = subprocess.Popen([tool('kubectl'), '--kubeconfig', str(KUBECONFIG), '--context', CONTEXT,
                '-n', NS, 'port-forward', '--address=127.0.0.1', 'service/'+service, f'{local}:{remote}'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **options)
            processes.append(p)
        deadline = time.monotonic()+20
        while time.monotonic() < deadline:
            if any(p.poll() is not None for p in processes):
                raise RuntimeError('Port forward failed; check 18082 / 18443 and cluster readiness')
            try:
                if httpx.get('http://127.0.0.1:18082/health', timeout=1, trust_env=False).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(.25)
        else:
            raise RuntimeError('Identity port forward did not become ready')
        yield
    finally:
        for p in processes:
            p.terminate()
        for p in processes:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


class SecurityOperator:
    recovery_required = False
    def control(self, service, path, method='GET', body=None):
        return json.loads(k('exec', '-i', 'deployment/'+service, '-c', 'app', '--', 'python', '-c', CONTROL,
                            data=json.dumps({'path': path, 'method': method, 'body': body}), quiet=True))

    def agent(self, path, body, token, method='POST', headers=None):
        tls = ssl.create_default_context(cafile=str(STATE/'certs/service-ca.crt'))
        tls.load_cert_chain(STATE/'certs/device-a.crt', STATE/'certs/device-a.key')
        with httpx.Client(verify=tls, trust_env=False, timeout=15) as client:
            r = client.request(method, 'https://localhost:18443'+path, json=body,
                               headers=headers if headers is not None else {'authorization': 'Bearer '+token})
        return r

    def status(self):
        state = {'available': False, 'context': CONTEXT, 'namespace': NS, 'phase2': 'NOT_IMPLEMENTED'}
        try:
            data = json.loads(k('get', 'deployments,authorizationpolicies,requestauthentications,peerauthentications', '-o', 'json', quiet=True))['items']
            state.update(available=True, workloads=[{'name': d['metadata']['name'],
                'ready': d.get('status', {}).get('readyReplicas', 0), 'desired': d['spec'].get('replicas', 1)}
                for d in data if d['kind'] == 'Deployment'],
                policies=[d for d in data if d['kind'] != 'Deployment'])
        except Exception:
            state['error'] = '無法讀取隔離叢集；尚無即時安全證據。'
        return state

    def certificates(self):
        # Existing parser returns public SAN/validity only; never expose secret dumps.
        from scripts.mesh_demo import certificate_evidence, has_sidecar
        import base64
        pods = json.loads(k('get', 'pods', '-o', 'json', quiet=True))['items']
        result = []
        from scripts.identity_deploy import run
        for pod in pods:
            if pod['metadata'].get('deletionTimestamp') or not has_sidecar(pod) or pod['status'].get('phase') != 'Running':
                continue
            raw = json.loads(run([tool('istioctl'), '--kubeconfig', KUBECONFIG, '--context', CONTEXT,
                'proxy-config', 'secret', pod['metadata']['name'], '-n', NS, '-o', 'json'], quiet=True))
            for secret in raw.get('dynamicActiveSecrets', []):
                chain = secret.get('secret', {}).get('tlsCertificate', {}).get('certificateChain', {})
                if chain:
                    pem = base64.b64decode(chain['inlineBytes']) if 'inlineBytes' in chain else chain['inlineString'].encode()
                    principal = 'spiffe://cluster.local/ns/'+NS+'/sa/'+pod['spec']['serviceAccountName']
                    result.append({'workload': pod['metadata']['labels']['app'], **certificate_evidence(pem, principal)})
        return result

    def executions(self, attempt):
        code = 'import sys,json; from app.resource_evidence import executions; print(json.dumps(executions(json.load(sys.stdin)["attempt"])))'
        result = []
        for service in ('salary', 'profile'):
            result += json.loads(k('exec', '-i', 'deployment/'+service, '-c', 'app', '--', 'python', '-c', code,
                                   data=json.dumps({'attempt': attempt}), quiet=True))
        return result

    def evidence(self, attempt, wait_for=()):
        try:
            events = self.control('context', '/events?attempt_id='+attempt)
        except Exception:
            events = []
        deadline = time.monotonic()+3
        while True:
            logs = []
            for service in ('device-gateway', 'frontend', 'salary', 'profile'):
                try:
                    raw = k('logs', 'deployment/'+service, '-c', 'app' if service == 'device-gateway' else 'istio-proxy',
                            '--tail=300', quiet=True)
                    for line in raw.splitlines():
                        try:
                            event = json.loads(line)
                            if event.get('attempt_id') == attempt:
                                logs.append({'component': service, **event})
                        except (ValueError, AttributeError):
                            pass
                except Exception:
                    pass
            if set(wait_for) <= {e['component'] for e in logs} or time.monotonic() >= deadline:
                break
            time.sleep(.15)
        try:
            executions = self.executions(attempt)
        except Exception:
            executions = None
        return inspect_attempt(attempt, events, logs, executions)

    def perform(self, spec):
        if self.recovery_required:
            raise RuntimeError('Recovery required before further experiments')
        attempt, request_id = str(uuid4()), str(uuid4())
        path = '/api/'+spec.resource+'/'+spec.owner+('/adjust' if spec.operation == 'adjust' else '')
        headers = {'authorization': 'Bearer '+spec.token, 'x-attempt-id': attempt, 'x-request-id': request_id}
        if spec.attack == 'invalid-jwt':
            headers['authorization'] = 'Bearer invalid-signature'
        elif spec.attack == 'missing-jwt':
            headers.pop('authorization')
        elif spec.attack == 'forged-headers':
            headers.update({'x-user-id': 'bob', 'x-role': 'hr', 'x-forwarded-client-cert': 'URI=spiffe://cluster.local/ns/'+NS+'/sa/frontend'})
        method = 'POST' if spec.operation == 'adjust' else 'GET'
        body = {'amount': spec.amount} if method == 'POST' else None
        count = 8 if spec.attack == 'hr-burst' else 1
        responses = []
        fault_target = {'pe-outage': 'pe', 'authz-outage': 'mesh-authz', 'audit-outage': 'context'}.get(spec.attack)
        fault = fault_target is not None
        if fault:
            data = json.loads(k('get', 'deployment', fault_target, '-o', 'json', quiet=True))
            if data['spec'].get('replicas', 1) != 1:
                raise RuntimeError('PE must be healthy before fault injection')
        try:
            if fault:
                k('scale', 'deployment/'+fault_target, '--replicas=0', quiet=True)
                k('wait', '--for=delete', 'pod', '-l', 'app='+fault_target, '--timeout=60s', quiet=True)
            def send(_):
                request_headers = {**headers, 'x-request-id': str(uuid4())}
                payload = {'method': method, 'url': 'http://frontend:8000'+path, 'headers': request_headers, 'body': body}
                caller = 'probe'
                if spec.attack in ('intruder', 'forged-headers', 'plaintext'):
                    caller = 'plaintext' if spec.attack == 'plaintext' else 'intruder'
                    payload['url'] = 'http://'+spec.resource+':8000'+path
                if spec.attack == 'direct-frontend':
                    caller = 'frontend'
                    payload['url'] = 'http://'+spec.resource+':8000'+path
                if spec.attack in ('intruder', 'forged-headers', 'plaintext', 'direct-frontend'):
                    response = json.loads(k('exec', '-i', 'deployment/'+caller, '-c', 'app', '--', 'python', '-c', PROBE,
                                           data=json.dumps(payload), quiet=True))
                else:
                    r = self.agent(path, body, None, method, request_headers)
                    try:
                        data = r.json()
                    except ValueError:
                        data = None
                    response = {'status': r.status_code, 'data': data, 'text': r.text[:2048]}
                return response
            if count > 1:
                with ThreadPoolExecutor(max_workers=count) as burst:
                    responses = list(burst.map(send, range(count)))
            else:
                responses = [send(0)]
        finally:
            if fault:
                try:
                    k('scale', 'deployment/'+fault_target, '--replicas=1', quiet=True)
                    k('rollout', 'status', 'deployment/'+fault_target, '--timeout=120s', quiet=True)
                except Exception:
                    self.recovery_required = True
                    raise
        # Access log flush can lag the HTTP response. Bounded retry, no invented traces.
        wait_for = (() if spec.attack == 'plaintext' else (spec.resource,)
            if spec.attack in ('intruder', 'forged-headers', 'direct-frontend') else ('device-gateway',)
            if spec.attack in ('invalid-jwt', 'missing-jwt') else ('device-gateway', 'frontend', spec.resource))
        evidence = self.evidence(attempt, wait_for)
        evidence.update(responses=responses, request={'resource': spec.resource, 'owner': spec.owner,
            'method': method, 'attack': spec.attack}, observed_at=datetime.now(timezone.utc).isoformat())
        return evidence


class Experiment(BaseModel):
    model_config = ConfigDict(extra='forbid')
    token: str = ''
    resource: str = 'salary'
    owner: str = 'alice'
    operation: str = 'read'
    attack: str = 'normal'
    amount: int = 60000


def create_app(operator):
    app = FastAPI(title='Zero Trust Security Inspector', docs_url=None, redoc_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost', '127.0.0.1', 'testserver'])
    csrf = secrets.token_urlsafe(32)
    lock = threading.Lock()
    executor = ThreadPoolExecutor(max_workers=1)
    jobs = {}
    active = {'id': None}

    @app.middleware('http')
    async def boundary(request: Request, call_next):
        origin = request.headers.get('origin')
        if origin and origin != 'http://'+request.headers.get('host', '') or request.headers.get('sec-fetch-site') == 'cross-site':
            return JSONResponse({'detail': 'same_origin_required'}, 403)
        if request.method not in ('GET', 'HEAD'):
            if not secrets.compare_digest(request.headers.get('x-mesh-console', ''), csrf):
                return JSONResponse({'detail': 'local_operator_token_required'}, 403)
            if not request.headers.get('content-type', '').startswith('application/json'):
                return JSONResponse({'detail': 'application_json_required'}, 415)
        response = await call_next(request)
        response.headers.update({'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"})
        return response

    @app.get('/')
    def index():
        return FileResponse(ROOT/'console/index.html')
    app.mount('/assets', StaticFiles(directory=ROOT/'console'))

    @app.get('/api/console/session')
    def session():
        return {'token': csrf}

    @app.get('/api/inspector/status')
    def status():
        return operator.status()

    @app.get('/api/inspector/certificates')
    def certificates():
        try:
            return operator.certificates()
        except Exception:
            raise HTTPException(503, 'public_certificates_not_observed')

    @app.post('/api/identity/{operation:path}')
    def identity(operation: str, body: dict):
        if operation not in ('register/options', 'register/verify', 'login/options', 'login/verify'):
            raise HTTPException(404)
        with httpx.Client(trust_env=False, timeout=10) as client:
            r = client.post('http://127.0.0.1:18082/'+operation, json=body)
        return JSONResponse(r.json(), r.status_code)

    @app.post('/api/inspector/invite')
    def invite(body: dict):
        if body not in ({'subject': 'bob'}, {'subject': 'alice'}):
            raise HTTPException(400, 'only_preassigned_subjects_supported')
        return operator.control('identity', '/enrollment/invite', 'POST', body)

    @app.post('/api/inspector/recover')
    def recover(body: dict):
        if body not in ({'subject': 'bob'}, {'subject': 'alice'}):
            raise HTTPException(400, 'unknown_subject')
        if active['id']:
            raise HTTPException(409, 'experiment_in_progress')
        return operator.control('pe', '/resource-state/'+body['subject'], 'PUT', {})

    @app.post('/api/agent/session')
    def agent_session(body: dict):
        if body.get('resource') not in ('salary', 'profile'):
            raise HTTPException(400)
        r = operator.agent('/session', {'path': '/api/'+body['resource'], 'method': 'GET'}, body.get('human_token', ''))
        return JSONResponse(r.json(), r.status_code)

    @app.post('/api/agent/exchange')
    def exchange(body: dict):
        r = operator.agent('/token/exchange', {'scope': body.get('scope'), 'step_up_token': body.get('step_up_token')}, body.get('session_id', ''))
        return JSONResponse(r.json(), r.status_code)

    @app.get('/api/inspector/jobs/{job_id}')
    def job(job_id: str):
        with lock:
            if job_id not in jobs:
                raise HTTPException(404)
            return jobs[job_id]

    def finish(job_id, body):
        try:
            value = {'state': 'done', 'result': operator.perform(body)}
        except Exception:
            value = {'state': 'error', 'error': '操作未完成；沒有驗證結果。請檢查隔離叢集與 PE 恢復狀態。'}
        with lock:
            jobs[job_id].update(value)
            active['id'] = None

    @app.post('/api/inspector/experiments', status_code=202)
    def experiment(body: Experiment):
        if body.resource not in ('salary', 'profile') or body.owner not in ('alice', 'bob', 'carol') or body.operation not in ('read', 'adjust'):
            raise HTTPException(400, 'unsupported_resource_operation')
        if body.attack not in ('normal', 'intruder', 'forged-headers', 'invalid-jwt', 'missing-jwt', 'hr-burst', 'pe-outage', 'authz-outage', 'audit-outage', 'plaintext', 'direct-frontend'):
            raise HTTPException(400, 'unsupported_experiment')
        with lock:
            if active['id']:
                raise HTTPException(409, 'experiment_in_progress')
            job_id = str(uuid4())
            jobs[job_id] = {'id': job_id, 'state': 'running'}
            active['id'] = job_id
            while len(jobs) > 30:
                del jobs[next(iter(jobs))]
            executor.submit(finish, job_id, body)
            return jobs[job_id]

    return app


def main():
    with forwards():
        uvicorn.run(create_app(SecurityOperator()), host='127.0.0.1', port=18081, access_log=False)


if __name__ == '__main__':
    main()
