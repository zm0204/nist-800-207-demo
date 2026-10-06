"""Policy Administrator: device-bound scoped sessions and continuous evaluation."""
import asyncio
import json
import re
import secrets
import time
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from app.common import db, call, url, protected

def initialize():
    with db('pa') as c:
        c.execute('CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, value TEXT)')
initialize()

def save(s):
    with db('pa') as c:
        c.execute('INSERT OR REPLACE INTO sessions VALUES (?,?)',(s['session_id'],json.dumps(s)))

def load(sid):
    with db('pa') as c: r=c.execute('SELECT value FROM sessions WHERE id=?',(sid,)).fetchone()
    if not r: raise HTTPException(403,'unknown_session')
    return json.loads(r[0])

def public(s): return {k:v for k,v in s.items() if k!='human_token'}

def bearer(request):
    raw=request.headers.get('authorization','')
    if not raw.startswith('Bearer '): raise HTTPException(403,'bearer_token_required')
    return raw[7:]

def device_identity(request):
    # Only Envoy can reach this endpoint from edge. Envoy SANITIZE_SET replaces
    # any client supplied XFCC with the certificate it actually verified.
    value=request.headers.get('x-forwarded-client-cert','')
    matches=re.findall(r'(?:^|;)URI="?(urn:zta:device:[a-z0-9-]+)"?(?:;|$)',value)
    if len(matches)!=1 or ',' in value: raise HTTPException(403,'verified_device_certificate_required')
    return matches[0].rsplit(':',1)[1]

async def log(value):
    await call(url('context'),'/event','POST',value)

async def decision(s,request=None,active=True):
    identity=await call(url('identity'),'/introspect','POST',{'token':s['human_token']})
    return await call(url('pe'),'/evaluate','POST',{'identity':identity,'device_id':s['device_id'],
                      'request':request or s['scope'],'active':active})

async def revoke(s,result):
    # Save before audit so a telemetry outage cannot retain authorization.
    latest=load(s['session_id'])
    latest.update(state='REVOKED',pa_action='REVOKE_SESSION',pep_state='BLOCKED',last=result,revoked_at=time.time())
    save(latest)
    try: await log({'kind':'pa_action',**public(latest)})
    except Exception: pass

async def reevaluate_all():
    with db('pa') as c: items=[json.loads(r[0]) for r in c.execute('SELECT value FROM sessions')]
    for s in items:
        if s['state']!='ACTIVE': continue
        try:
            result=await decision(s)
            if result['decision']!='ALLOW': await revoke(s,result)
            else:
                # Never resurrect a manual revoke that arrived while awaiting PE.
                latest=load(s['session_id'])
                if latest['state']=='ACTIVE': latest['last']=result; save(latest)
        except Exception:
            await revoke(s,{'decision':'REVOKE','trust_score':0,'risk_score':100,'reasons':['control_plane_unavailable']})

async def watch():
    while True:
        await asyncio.sleep(1)
        await reevaluate_all()

@asynccontextmanager
async def lifespan(app):
    # Persisted sessions must be evaluated before accepting traffic after restart.
    await reevaluate_all()
    task=asyncio.create_task(watch())
    yield
    task.cancel()
    try: await task
    except asyncio.CancelledError: pass

app=FastAPI(title='Policy Administrator',lifespan=lifespan)

class Scope(BaseModel):
    path:str='/api/salary'
    method:str='GET'

@app.get('/health',dependencies=[Depends(protected)])
def health(): return {'ok':True}

@app.post('/session')
async def session(body:Scope,request:Request):
    device=device_identity(request)
    s={'session_id':secrets.token_urlsafe(40),'human_token':bearer(request),'device_id':device,
       'scope':body.model_dump(),'created_at':time.time(),'state':'PENDING'}
    try:
        result=await decision(s,active=False)
        if result['decision']!='ALLOW':
            await log({'kind':'pa_action','pa_action':'DENY_SESSION','pep_state':'BLOCKED',**result})
            return JSONResponse({'decision':result,'pa_action':'DENY_SESSION'},status_code=403)
        s.update(subject=result['subject'],state='ACTIVE',last=result,pa_action='CREATE_SESSION',pep_state='AUTHORIZED')
        await log({'kind':'pa_action',**public(s)})
        save(s)
        return public(s)
    except Exception:
        raise HTTPException(503,'control_plane_unavailable_fail_closed')

@app.api_route('/check/{path:path}',methods=['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'])
async def check(path:str,request:Request):
    s=load(bearer(request))
    if device_identity(request)!=s['device_id']: raise HTTPException(403,'session_device_mismatch')
    if s['state']!='ACTIVE': raise HTTPException(403,'session_revoked')
    current={'method':request.method,'path':'/'+path}
    try:
        await log({'kind':'request','session_id':s['session_id'],'subject':s['subject'],
                   'device_id':s['device_id'],'request':current})
        # Evaluate authorized scope for health first, then requested scope.
        result=await decision(s)
        if result['decision']!='ALLOW':
            await revoke(s,result); raise HTTPException(403,'session_revoked')
        result=await decision(s,current,active=False)
        if result['decision']!='ALLOW' or current!=s['scope']:
            await log({'kind':'pa_action','pa_action':'DENY_REQUEST','pep_state':'BLOCKED',**result})
            return JSONResponse({'decision':result,'reason':'least_privilege_or_session_scope'},status_code=403)
        latest=load(s['session_id'])
        if latest['state']!='ACTIVE': raise HTTPException(403,'session_revoked')
        latest.update(last=result,pa_action='AUTHORIZE_REQUEST',pep_state='FORWARD'); save(latest)
        await log({'kind':'pa_action','session_id':s['session_id'],'pa_action':'AUTHORIZE_REQUEST','pep_state':'FORWARD'})
        return Response(status_code=200,headers={'x-zta-subject':s['subject'],'x-zta-session':s['session_id']})
    except HTTPException: raise
    except Exception:
        await revoke(s,{'decision':'REVOKE','trust_score':0,'reasons':['control_plane_unavailable']})
        raise HTTPException(403,'control_plane_unavailable_fail_closed')

@app.get('/sessions',dependencies=[Depends(protected)])
def sessions():
    with db('pa') as c: return [public(json.loads(r[0])) for r in c.execute('SELECT value FROM sessions')]

@app.get('/status/{sid}',dependencies=[Depends(protected)])
def status(sid:str): return public(load(sid))

class Revoke(BaseModel): session_id:str

@app.post('/revoke',dependencies=[Depends(protected)])
async def manual_revoke(body:Revoke):
    s=load(body.session_id)
    await revoke(s,{'decision':'REVOKE','trust_score':0,'reasons':['administrator_revocation']})
    return public(load(body.session_id))
