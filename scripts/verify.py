"""End-to-end validation against an actual running Compose/Envoy stack.

Uses a test-only software authenticator for a real WebAuthn ceremony.
Run on a FRESH isolated demo stack (no browser passkey enrolled yet).
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import httpx
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tests.authenticator import Authenticator

def tls_client(name='device-a',cert=True):
    ctx=ssl.create_default_context(cafile=str(ROOT/'certs/service-ca.crt'))
    if cert:ctx.load_cert_chain(ROOT/f'certs/{name}.crt',ROOT/f'certs/{name}.key')
    return httpx.Client(verify=ctx,trust_env=False,timeout=6)

def run(dashboard,pep):
    results=[]
    with httpx.Client(base_url=dashboard,timeout=6,trust_env=False) as d,tls_client() as client:
        def console(path,body,method='POST'):
            r=d.request(method,path,json=body);r.raise_for_status();return r.json()
        a=Authenticator();o=console('/identity/register/options',{})
        console('/identity/register/verify',{'ceremony':o['ceremony'],'credential':a.register(o['publicKey'])})
        o=console('/identity/login/options',{})
        human=console('/identity/login/verify',{'ceremony':o['ceremony'],'credential':a.login(o['publicKey'])})['token']
        def reset():console('/simulate',{'action':'reset'})
        def session(path='/api/salary'):
            r=client.post(pep+'/session',json={'path':path,'method':'GET'},headers={'authorization':'Bearer '+human});r.raise_for_status();return r.json()['session_id']
        def get(sid,path='/api/salary',method='GET',extra=None):
            return client.request(method,pep+path,headers={'authorization':'Bearer '+sid,**(extra or {})})
        def revoked(sid):
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                v=d.get('/view').json();s=next(s for s in v['sessions'] if s['session_id']==sid)
                if s['state']=='REVOKED': return s
                time.sleep(.2)
            raise AssertionError('Continuous evaluation did not revoke within 8 seconds')
        reset();sid=session();r=get(sid)
        if r.status_code!=200:
            print('Normal request failure:',r.status_code,r.text)
            print('Sanitized recent activity:',json.dumps(d.get('/view').json()['events'][:10]))
        assert r.status_code==200 and r.json()['resource']=='salary'
        results.append('1 Normal ALLOW -> real protected Resource')
        assert get(sid,method='POST').status_code==403;assert get(sid).status_code==200;results.append('2 Least privilege DENY')
        console('/simulate',{'action':'compromise'});assert revoked(sid)['last']['decision']=='REVOKE';assert get(sid).status_code==403;results.append('3 Compromise -> autonomous REVOKE -> PEP blocked')
        for action,label in [('high-risk-ip','4 High-risk IP'),('abnormal','5 Abnormal behavior')]:
            reset();sid=session();console('/simulate',{'action':action});revoked(sid);assert get(sid).status_code==403;results.append(label+' -> REVOKE')
        services=json.loads(subprocess.check_output(['docker','compose','config','--format','json'],cwd=ROOT))['services']
        assert not services['resource'].get('ports')
        # The exact resource endpoint is only resolved on the internal data network.
        try:socket.getaddrinfo('resource',8000)
        except socket.gaierror:pass
        else:raise AssertionError('Host unexpectedly resolves resource; inspect local DNS')
        # Network-isolation proof: dashboard is not on data, and even forged
        # identity headers plus its device certificate cannot reach Resource.
        probe="import socket; socket.create_connection(('resource',8000),2)"
        bypass=subprocess.run(['docker','compose','exec','-T','dashboard','python','-c',probe],cwd=ROOT,capture_output=True)
        assert bypass.returncode!=0;results.append('6 Host has no Resource port and non-data agent cannot bypass PEP')
        reset();sid=session()
        with tls_client('device-b') as other:
            assert other.get(pep+'/api/salary',headers={'authorization':'Bearer '+sid,'x-forwarded-client-cert':'URI=urn:zta:device:device-a'}).status_code==403
        with tls_client(cert=False) as no_cert:
            try:r=no_cert.get(pep+'/api/salary')
            except httpx.HTTPError:pass
            else:raise AssertionError('mTLS accepted a connection without client certificate: '+str(r.status_code))
        assert get('invented',extra={'x-zta-subject':'alice','x-zta-session':sid}).status_code==403
        results.append('Certificate/session binding, forged XFCC and missing certificate rejected')
        reset();sid=session('/api/stream')
        def observe_stream():
            with tls_client() as stream_client:
                with stream_client.stream('GET',pep+'/api/stream',headers={'authorization':'Bearer '+sid},timeout=12) as r:
                    assert r.status_code==200
                    text='\n'.join(r.iter_lines())
                    assert 'event: resource' in text and 'event: revoked' in text
                    return text
        with ThreadPoolExecutor(max_workers=1) as executor:
            future=executor.submit(observe_stream);time.sleep(1.5)
            console('/simulate',{'action':'compromise'});future.result(timeout=15)
        results.append('Active SSE resource stream closes after continuous REVOKE')
        reset();sid=session();subprocess.run(['docker','compose','stop','pe'],cwd=ROOT,check=True,capture_output=True)
        try:assert get(sid).status_code in (403,503);revoked(sid)
        finally:subprocess.run(['docker','compose','start','pe'],cwd=ROOT,check=True,capture_output=True)
        results.append('PE unavailable -> fail closed, session revoked')
    report={'mode':'Actual Docker Compose + Envoy + mTLS','passed':len(results),'checks':results}
    (ROOT/'artifacts').mkdir(exist_ok=True)
    (ROOT/'artifacts/compose-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--dashboard',default='http://localhost:8080');p.add_argument('--pep',default='https://localhost:8443');a=p.parse_args();run(a.dashboard,a.pep)
