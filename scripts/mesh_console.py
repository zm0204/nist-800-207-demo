"""Loopback-only operator workbench. Kubernetes credentials stay on the host.

Run with the same user who owns the dedicated kind-zta-207a kubeconfig.
Only fixed demo requests and the existing verifier are exposed; no shell API.
"""
import argparse
import base64
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.mesh_demo import CONTEXT, NS, certificate_evidence, has_sidecar

ASSETS = ROOT / 'console'


def scenario(label, detail, caller, target, path, expected, method='GET', resource=None, headers=None):
    return dict(label=label, detail=detail, caller=caller, target=target, path=path,
                method=method, expected=expected, resource=resource, headers=headers or {})


SCENARIOS = {
    'salary': scenario('讀取薪資', 'probe 經 frontend 呼叫 salary；兩段服務呼叫都經過 sidecar。',
                       'probe', 'frontend', '/api/salary', [200], resource='salary'),
    'profile': scenario('讀取個人資料', '同一個 frontend，以另一條精確授權存取 profile。',
                        'probe', 'frontend', '/api/profile', [200], resource='profile'),
    'wrong-identity': scenario('換一個服務身分', 'intruder 也有合法 mesh 憑證，但沒有讀取 salary 的權限。',
                               'intruder', 'salary', '/api/salary', [403]),
    'bypass': scenario('跳過 frontend', 'probe 可以呼叫 frontend，不能直接存取 salary。',
                       'probe', 'salary', '/api/salary', [403]),
    'wrong-method': scenario('改成 POST', 'frontend 的權限只有 GET；換 HTTP 方法應被拒絕。',
                             'frontend', 'salary', '/api/salary', [403], method='POST'),
    'wrong-path': scenario('改變資源路徑', '對 salary 要求 profile 路徑，不符合精確的路徑政策。',
                           'frontend', 'salary', '/api/profile', [403]),
    'forged-headers': scenario('偽造身分標頭', 'intruder 宣稱自己是 frontend；真正的授權仍依 TLS 服務身分。',
                               'intruder', 'salary', '/api/salary', [403], headers={
                                   'x-forwarded-client-cert': 'URI=spiffe://cluster.local/ns/zta-207a/sa/frontend',
                                   'x-zta-subject': 'alice', 'x-zta-session': 'invented'}),
    'plaintext': scenario('不用 mTLS 連線', '從沒有 sidecar 的 plaintext client 呼叫 salary。',
                          'plaintext', 'salary', '/api/salary', [0, 503]),
}

PROBE = '''import json,sys,httpx
p=json.loads(sys.argv[1])
try:
    r=httpx.request(p['method'],p['url'],headers=p['headers'],timeout=5,trust_env=False)
    try: data=r.json()
    except ValueError: data=None
    print(json.dumps({'status':r.status_code,'data':data,'text':r.text[:2048]}))
except httpx.HTTPError as e:
    print(json.dumps({'status':0,'error':type(e).__name__}))
'''

AUDIT = '''import json,os,urllib.request
r=urllib.request.Request('http://localhost:8000/events',headers={'x-service-key':os.environ['SERVICE_KEY']})
events=json.load(urllib.request.urlopen(r,timeout=4))
keys=('event_id','timestamp','source','destination','method','path','decision','reason','policy_version')
print(json.dumps([{k:e[k] for k in keys if k in e} for e in events if e.get('kind')=='service_pe_decision'][:20]))
'''


def now():
    return datetime.now(timezone.utc).isoformat()


class RecoveryError(RuntimeError):
    """The dedicated demo could not be restored; do not start another operation."""


class MeshOperator:
    def __init__(self, args):
        self.args = args
        self.kube = [args.kubectl, '--kubeconfig', str(Path(args.kubeconfig).resolve()),
                     '--context', CONTEXT, '--request-timeout=8s', '-n', NS]
        self.evidence_path = ROOT / 'artifacts/mesh-external.json'

    def command(self, argv, timeout=30):
        options = dict(creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP) if os.name == 'nt' else dict(start_new_session=True)
        with subprocess.Popen([str(a) for a in argv], cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace', **options) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                # Stop kubectl children too, before the parent starts recovery.
                if os.name == 'nt':
                    subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=15)
                else:
                    os.killpg(process.pid, signal.SIGKILL)
                process.kill()
                process.communicate()
                raise
            return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)

    def kubectl(self, *args, timeout=30):
        result = self.command(self.kube + list(args), timeout=timeout)
        if result.returncode:
            # kubectl stderr can include host paths and credentials from plugins.
            raise RuntimeError('Kubernetes operation failed')
        return result.stdout

    def request(self, caller, target, path, method='GET', headers=None):
        payload = json.dumps(dict(url=f'http://{target}:8000{path}', method=method, headers=headers or {}))
        return json.loads(self.kubectl('exec', 'deployment/' + caller, '-c', 'app', '--',
                                       'python', '-c', PROBE, payload, timeout=20))

    def execute(self, name):
        if name == 'full-verify':
            return self.verify()
        spec = SCENARIOS[name]
        started = time.monotonic()
        result = self.request(spec['caller'], spec['target'], spec['path'],
                              method=spec['method'], headers=spec['headers'])
        passed = result['status'] in spec['expected']
        if spec['resource']:
            passed = passed and isinstance(result.get('data'), dict) and result['data'].get('resource') == spec['resource']
        return dict(passed=passed, response=result, elapsed_ms=round((time.monotonic()-started)*1000),
                    request={k: spec[k] for k in ('caller', 'target', 'path', 'method', 'headers')},
                    expected=spec['expected'])

    def verify(self):
        snapshot = self.snapshot()
        started = datetime.now(timezone.utc)
        try:
            result = self.command([sys.executable, ROOT / 'scripts/mesh_demo.py',
                                   '--kubectl', self.args.kubectl, '--kind', self.args.kind,
                                   '--istioctl', self.args.istioctl, '--kubeconfig', self.args.kubeconfig,
                                   '--external-authz', 'verify'], timeout=600)
            evidence = json.loads(self.evidence_path.read_text(encoding='utf-8'))
            if datetime.fromisoformat(evidence['started_at']) < started:
                raise RuntimeError('Verifier evidence predates this run')
            checks = evidence.get('checks', [])
            passed = (result.returncode == 0 and evidence.get('passed') is True and
                      evidence.get('external_authz') is True and len(checks) == 23 and
                      all(c.get('passed') is True for c in checks))
            return dict(passed=passed, checks=checks, certificates=evidence.get('certificates', []),
                        started_at=evidence['started_at'], finished_at=evidence.get('finished_at'),
                        revision=evidence.get('revision'), total=len(checks),
                        passed_count=sum(c.get('passed') is True for c in checks))
        finally:
            self.restore(snapshot)

    def snapshot(self):
        if self.kubectl('get', 'authorizationpolicy', 'temporary-revoke', '--ignore-not-found', '-o', 'name').strip():
            raise RuntimeError('A revocation test is already active')
        policy = json.loads(self.kubectl('get', 'configmap', 'service-policy', '-o', 'json'))['data']
        deployments = json.loads(self.kubectl('get', 'deployments', 'context', 'pe', 'mesh-authz', '-o', 'json'))['items']
        replicas = {d['metadata']['name']: d['spec'].get('replicas', 1) for d in deployments}
        if any(replicas.get(name) != 1 for name in ('context', 'pe', 'mesh-authz')):
            raise RuntimeError('External authorization dependencies must be running before testing')
        return dict(policy=policy, replicas=replicas)

    def restore(self, snapshot):
        errors = []
        actions = [
            ('patch', 'configmap', 'service-policy', '--type=merge', '-p', json.dumps({'data': snapshot['policy']})),
            ('delete', 'authorizationpolicy', 'temporary-revoke', '--ignore-not-found'),
            ('annotate', 'pods', '-l', 'app=pe', 'policy-refresh=' + str(time.time_ns()), '--overwrite'),
        ]
        actions += [('scale', 'deployment/' + name, '--replicas=' + str(count)) for name, count in snapshot['replicas'].items()]
        for args in actions:
            try:
                self.kubectl(*args, timeout=20)
            except Exception:
                errors.append(args[0])
        for name in snapshot['replicas']:
            try:
                self.kubectl('rollout', 'status', 'deployment/' + name, '--timeout=60s', timeout=70)
            except Exception:
                errors.append(name)
        if errors:
            raise RecoveryError()

    def status(self):
        state = dict(available=False, observed_at=now(), context=CONTEXT, namespace=NS,
                     workloads=[], security={}, policies=[])
        try:
            items = json.loads(self.kubectl('get', 'deployments,pods,peerauthentications,authorizationpolicies,destinationrules',
                                            '-o', 'json', timeout=15))['items']
            pods = [x for x in items if x['kind'] == 'Pod' and not x['metadata'].get('deletionTimestamp')]
            for deployment in sorted((x for x in items if x['kind'] == 'Deployment'), key=lambda x: x['metadata']['name']):
                name = deployment['metadata']['name']
                current = [p for p in pods if p['metadata'].get('labels', {}).get('app') == name]
                state['workloads'].append(dict(name=name, desired=deployment['spec'].get('replicas', 1),
                    ready=deployment.get('status', {}).get('readyReplicas', 0),
                    sidecar=bool(current) and all(has_sidecar(p) for p in current),
                    service_account=current[0]['spec'].get('serviceAccountName') if current else None))
            policies = [p for p in items if p['kind'] == 'AuthorizationPolicy']
            peers = [p for p in items if p['kind'] == 'PeerAuthentication' and p['metadata']['name'] == 'strict-mtls']
            state['security'] = dict(
                mtls=peers[0].get('spec', {}).get('mtls', {}).get('mode', 'UNKNOWN') if peers else 'UNKNOWN',
                default_deny=any(p['metadata']['name'] == 'default-deny' and p.get('spec', {}) == {} for p in policies),
                external_authz=any(p['metadata']['name'] == 'backend-external-decision' and p.get('spec', {}).get('action') == 'CUSTOM' for p in policies))
            state['policies'] = [dict(name=p['metadata']['name'], **p.get('spec', {})) for p in policies]
            state['available'] = True
        except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, KeyError):
            state['error'] = '無法讀取叢集。請確認 Docker Desktop 已啟動，且 zta-207a 叢集可連線。'
        return state

    def certificates(self):
        pods = json.loads(self.kubectl('get', 'pods', '-o', 'json', timeout=15))['items']
        result = []
        for pod in pods:
            if pod['metadata'].get('deletionTimestamp') or pod['status'].get('phase') != 'Running' or not has_sidecar(pod):
                continue
            raw = self.command([self.args.istioctl, '--kubeconfig', self.args.kubeconfig,
                                '--context', CONTEXT, 'proxy-config', 'secret',
                                pod['metadata']['name'], '-n', NS, '-o', 'json'], timeout=15)
            if raw.returncode:
                raise RuntimeError('Workload certificate unavailable')
            secrets_data = json.loads(raw.stdout)['dynamicActiveSecrets']
            chains = [entry['secret']['tlsCertificate']['certificateChain']['inlineBytes']
                      for entry in secrets_data if 'tlsCertificate' in entry.get('secret', {})]
            if not chains:
                raise RuntimeError('No active workload certificate')
            expected = f"spiffe://cluster.local/ns/{NS}/sa/{pod['spec']['serviceAccountName']}"
            result.append(dict(app=pod['metadata']['labels']['app'],
                               **certificate_evidence(base64.b64decode(chains[0]), expected)))
        if not result:
            raise RuntimeError('No injected workloads found')
        return result

    def audit(self):
        return json.loads(self.kubectl('exec', 'deployment/context', '-c', 'app', '--',
                                      'python', '-c', AUDIT, timeout=15))


class RunBody(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scenario: str = Field(min_length=1, max_length=40)


class Runs:
    def __init__(self, operator):
        self.operator = operator
        self.lock = threading.Lock()
        self.jobs = OrderedDict()
        self.active = None
        self.blocked = False
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='mesh-console')

    def submit(self, name):
        with self.lock:
            if self.blocked:
                raise HTTPException(409, '環境恢復未完成，操作已鎖定。請依部署說明檢查政策與 replicas。')
            if self.active:
                raise HTTPException(409, '有測試正在執行，完成後才能開始下一項。')
            job = dict(id=uuid4().hex, scenario=name, state='running', started_at=now(), result=None)
            self.jobs[job['id']] = job
            self.active = job['id']
            while len(self.jobs) > 40:
                self.jobs.popitem(last=False)
            self.executor.submit(self.finish, job['id'], name)
            return dict(job)

    def finish(self, job_id, name):
        try:
            result = self.operator.execute(name)
            outcome = dict(state='done', result=result)
        except RecoveryError:
            outcome = dict(state='error', recovery_required=True,
                           error='環境恢復未完成，後續操作已鎖定。請檢查政策與 replicas，再重新啟動控制程式。')
        except Exception:
            outcome = dict(state='error', error='測試未能完成。請檢查 Docker、叢集與工具路徑，再重新執行。')
        with self.lock:
            self.jobs[job_id].update(**outcome, finished_at=now())
            self.blocked = outcome.get('recovery_required', False)
            self.active = None

    def list(self):
        with self.lock:
            return dict(active=self.active, blocked=self.blocked, runs=[dict(j) for j in reversed(self.jobs.values())])

    def get(self, job_id):
        with self.lock:
            if job_id not in self.jobs:
                raise HTTPException(404, '找不到這次操作；伺服器重新啟動會清空操作紀錄。')
            return dict(self.jobs[job_id])


def create_app(operator):
    app = FastAPI(title='207A 本機實驗台', docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost', '127.0.0.1'])
    token = secrets.token_urlsafe(32)
    runs = Runs(operator)

    @app.middleware('http')
    async def boundary(request: Request, call_next):
        origin = request.headers.get('origin')
        if (origin and origin != 'http://' + request.headers.get('host', '')) or request.headers.get('sec-fetch-site') == 'cross-site':
            return JSONResponse({'detail': '僅接受本機同來源操作。'}, status_code=403)
        if request.method not in ('GET', 'HEAD') and not secrets.compare_digest(request.headers.get('x-mesh-console', ''), token):
            return JSONResponse({'detail': '請從實驗台頁面發起操作。'}, status_code=403)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        return response

    @app.get('/')
    def index():
        return FileResponse(ASSETS / 'index.html')

    app.mount('/assets', StaticFiles(directory=ASSETS), name='assets')

    @app.get('/api/console/session')
    def session():
        return dict(token=token, scenarios=[dict(id=k, **v) for k, v in SCENARIOS.items()])

    @app.get('/api/console/status')
    def status():
        return operator.status()

    @app.get('/api/console/certificates')
    def certificates():
        try:
            return dict(certificates=operator.certificates(), observed_at=now())
        except Exception:
            raise HTTPException(503, '無法取得有效憑證；請檢查 Istio 代理與 istioctl 路徑。')

    @app.get('/api/console/audit')
    def audit():
        try:
            return dict(events=operator.audit(), observed_at=now())
        except Exception:
            raise HTTPException(503, 'PE 稽核資料無法讀取；可能尚未啟用 external authorization。')

    @app.get('/api/console/runs')
    def list_runs():
        return runs.list()

    @app.get('/api/console/runs/{job_id}')
    def get_run(job_id: str):
        return runs.get(job_id)

    @app.post('/api/console/runs', status_code=202)
    def start_run(body: RunBody):
        if body.scenario not in SCENARIOS and body.scenario != 'full-verify':
            raise HTTPException(404, '未知情境。')
        return runs.submit(body.scenario)

    @app.get('/api/{resource}')
    def resource(resource: str):
        if resource not in ('salary', 'profile'):
            raise HTTPException(404)
        # Navigation is safe; only the authenticated POST button submits a request.
        return RedirectResponse('/?scenario=' + resource + '#experiment')

    return app


def default_tool(name):
    sibling = ROOT.parent / '.tools' / ('istioctl/istioctl.exe' if name == 'istioctl' else name + '.exe')
    return str(sibling) if sibling.exists() else shutil.which(name) or name


def main():
    # The default UI now runs the integrated identity-aware inspector. Legacy
    # MeshOperator/create_app remain importable for workload-only regressions.
    from scripts.security_inspector import main as inspector_main
    return inspector_main()

def legacy_main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubectl', default=default_tool('kubectl'))
    parser.add_argument('--kind', default=default_tool('kind'))
    parser.add_argument('--istioctl', default=default_tool('istioctl'))
    parser.add_argument('--kubeconfig', default=str(ROOT / '.tmp/mesh-kubeconfig'))
    parser.add_argument('--port', type=int, default=18081)
    args = parser.parse_args()
    # No host flag: this is a privileged local operator tool, not a public service.
    uvicorn.run(create_app(MeshOperator(args)), host='127.0.0.1', port=args.port, access_log=False)


if __name__ == '__main__':
    main()
