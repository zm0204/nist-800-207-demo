"""Real local HTTP/mTLS smoke test. DOES NOT replace an Envoy/Compose run."""
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import httpx

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tests.authenticator import Authenticator
from scripts.init import initialize

def port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]

def wait(url,key):
    end=time.monotonic()+20
    while time.monotonic()<end:
        try:
            if httpx.get(url+'/health',headers={'x-service-key':key},timeout=1,trust_env=False).status_code==200: return
        except httpx.HTTPError: pass
        time.sleep(.1)
    raise RuntimeError('service did not become healthy: '+url)

def run():
    processes=[]; logs=[]; checks=[]
    artifacts=ROOT/'artifacts';artifacts.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=artifacts) as scratch:
        root=Path(scratch); initialize(root)
        key=(root/'.env').read_text().splitlines()[0].split('=',1)[1]
        ports={name:port() for name in ['context','identity','pe','pa','dashboard','resource']}
        env={**os.environ,'SERVICE_KEY':key,'STATE_DIR':str(root/'state'),'CERT_DIR':str(root/'certs')}
        env.update({name.upper()+'_URL':f'http://127.0.0.1:{p}' for name,p in ports.items()})
        try:
            for name in ['context','identity','pe','pa','dashboard','resource']:
                log=open(root/(name+'.log'),'w',encoding='utf-8');logs.append(log)
                args=[sys.executable,'-m','uvicorn','app.'+name+':app','--host','127.0.0.1','--port',str(ports[name]),'--no-access-log']
                if name=='resource':
                    args+=['--ssl-keyfile',str(root/'certs/resource.key'),'--ssl-certfile',str(root/'certs/resource.crt'),
                           '--ssl-ca-certs',str(root/'certs/upstream-client-ca.crt'),'--ssl-cert-reqs','2']
                processes.append(subprocess.Popen(args,cwd=ROOT,env=env,stdout=log,stderr=log))
                if name!='resource': wait(env[name.upper()+'_URL'],key)
            with httpx.Client(timeout=5,trust_env=False) as c:
                dash=env['DASHBOARD_URL']; pa=env['PA_URL']; ctx=env['CONTEXT_URL']
                assert c.get(dash).status_code==200
                auth=Authenticator();opts=c.post(dash+'/identity/register/options',json={}).json()
                assert c.post(dash+'/identity/register/verify',json={'ceremony':opts['ceremony'],'credential':auth.register(opts['publicKey'])}).status_code==200
                opts=c.post(dash+'/identity/login/options',json={}).json()
                reply=c.post(dash+'/identity/login/verify',json={'ceremony':opts['ceremony'],'credential':auth.login(opts['publicKey'])})
                assert reply.status_code==200; human=reply.json()['token'];checks.append('Real HTTP WebAuthn via dashboard -> Identity')
                headers={'x-service-key':key}
                cert='URI=urn:zta:device:device-a'
                def reset(): assert c.post(ctx+'/simulate',json={'action':'reset'},headers=headers).status_code==200
                def session():
                    r=c.post(pa+'/session',json={'method':'GET','path':'/api/salary'},headers={'x-forwarded-client-cert':cert,'authorization':'Bearer '+human})
                    assert r.status_code==200,r.text; return r.json()['session_id']
                def access(sid,method='GET'):
                    return c.request(method,pa+'/check/api/salary',headers={'x-forwarded-client-cert':cert,'authorization':'Bearer '+sid})
                sid=session(); assert access(sid).status_code==200;checks.append('Normal access ALLOW via PE/PA (trusted PEP input injected by test)')
                assert access(sid,'POST').status_code==403;assert access(sid).status_code==200;checks.append('Least privilege DENY preserves valid scope')
                for action in ['compromise','high-risk-ip','abnormal']:
                    reset();sid=session();c.post(ctx+'/simulate',json={'action':action},headers=headers)
                    deadline=time.monotonic()+6
                    while time.monotonic()<deadline:
                        status=c.get(pa+'/status/'+sid,headers=headers).json()
                        if status['state']=='REVOKED':break
                        time.sleep(.15)
                    assert status['state']=='REVOKED',action
                    assert status['last']['decision']=='REVOKE'
                    assert access(sid).status_code==403;checks.append(action+': autonomous periodic REVOKE')
                reset();sid=session();c.post(ctx+'/simulate',json={'action':'outdated'},headers=headers)
                assert access(sid).status_code==200
                assert c.get(pa+'/status/'+sid,headers=headers).json()['last']['trust_score']==70;checks.append('Outdated OS trust=70 remains allowed')
                c.put(ctx+'/policy',json={'threshold':80,'grants':{'alice':['GET /api/salary']}},headers=headers)
                assert access(sid).status_code==403;checks.append('Dynamic policy threshold applies immediately')
                assert c.get(dash+'/view').status_code==200
                assert c.post(dash+'/simulate',json={'action':'reset'},headers={'Origin':'https://evil.example'}).status_code==403;checks.append('Dashboard rejects cross-origin mutation')
                # Resource is temporarily bound locally ONLY in this test. Test
                # cryptographic upstream protection separately from Docker port isolation.
                for client_name,allowed in [('device-a',False),('pep-upstream',True)]:
                    tls=ssl.create_default_context(cafile=str(root/'certs/service-ca.crt'))
                    tls.load_cert_chain(root/f'certs/{client_name}.crt',root/f'certs/{client_name}.key')
                    try:
                        with httpx.Client(verify=tls,trust_env=False,timeout=2) as rc:
                            r=rc.get(f'https://localhost:{ports["resource"]}/api/salary',headers={'x-zta-subject':'alice','x-zta-session':'test'})
                            assert allowed and r.status_code==200
                    except httpx.HTTPError:
                        assert not allowed
                checks.append('Real upstream TLS accepts PEP certificate and rejects device certificate despite forged headers')
            report={'mode':'local HTTP + TLS; Envoy and Docker NOT exercised','checks':checks,'passed':len(checks)}
            (artifacts/'local-smoke.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
            print(json.dumps(report,indent=2))
        except Exception:
            for name in ports:
                p=root/(name+'.log')
                if p.exists(): print(name+':\n'+p.read_text(encoding='utf-8')[-3000:])
            raise
        finally:
            for p in processes:p.terminate()
            for p in processes:
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait()
            for log in logs:log.close()

if __name__=='__main__':run()
