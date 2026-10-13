"""Policy Administrator: device-bound scoped sessions and continuous evaluation."""
import asyncio
import hashlib
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

def public(s):
    return {**{k:v for k,v in s.items() if k!='human_token'},
            'session_ref':hashlib.sha256(s['session_id'].encode()).hexdigest()[:16]}

def action_record(s,action,result,reason,operation,request=None,action_id=None,from_pe=True):
    # PE policy evaluation and PA authorization are separate facts. Synthetic
    # fail-closed/manual revocations must not be presented as PE decisions.
    return {'action_id':action_id or secrets.token_hex(12),'operation':operation,
            'session_ref':public(s)['session_ref'],'subject':s.get('subject') or (result or {}).get('subject'),
            'device_id':s['device_id'],'request':request or s['scope'],'scope':s['scope'],
            'policy_evaluation':result if from_pe else None,'pa_action':action,'pa_reason':reason,
            'pdp_decision':'REVOKE' if action=='REVOKE_SESSION' else 'DENY' if action.startswith('DENY') else 'ALLOW',
            'pep_state':{'CREATE_SESSION':'AUTHORIZED','AUTHORIZE_REQUEST':'FORWARD'}.get(action,'BLOCKED'),
            # This is the PA response, not an observed Resource HTTP response.
            'http_status':(200 if action in ('CREATE_SESSION','AUTHORIZE_REQUEST') else 403)
                          if operation in ('session','request') else None,'timestamp':time.time()}

def remember_action(s,record):
    s['last_action']=record
    if record['operation']=='request': s['last_request_action']=record

async def log_action(record,result=None):
    # Preserve legacy decision=PE result; pdp_decision is the composed outcome.
    await log({**(result or {}),**record,'kind':'pa_action'})

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

async def revoke(s,result,operation='reevaluation',request=None,action_id=None,from_pe=True):
    # Save before audit so a telemetry outage cannot retain authorization.
    latest=load(s['session_id'])
    latest.update(state='REVOKED',pa_action='REVOKE_SESSION',pep_state='BLOCKED',last=result,revoked_at=time.time())
    reason='policy_revoked' if from_pe else result['reasons'][0]
    record=action_record(latest,'REVOKE_SESSION',result,reason,operation,request,action_id,from_pe)
    remember_action(latest,record)
    save(latest)
    try: await log_action(record,result if from_pe else None)
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
            await revoke(s,{'decision':'REVOKE','trust_score':0,'risk_score':100,'reasons':['control_plane_unavailable']},from_pe=False)

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
            record=action_record(s,'DENY_SESSION',result,'policy_denied','session')
            await log_action(record,result)
            return JSONResponse({'decision':result,'pa_action':'DENY_SESSION','authorization':record},status_code=403)
        s.update(subject=result['subject'],state='ACTIVE',last=result,pa_action='CREATE_SESSION',pep_state='AUTHORIZED')
        record=action_record(s,'CREATE_SESSION',result,'required_conditions_met','session')
        remember_action(s,record)
        await log_action(record,result)
        save(s)
        return public(s)
    except Exception:
        raise HTTPException(503,'control_plane_unavailable_fail_closed')

@app.api_route('/check/{path:path}',methods=['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'])
async def check(path:str,request:Request):
    s=load(bearer(request))
    current={'method':request.method,'path':'/'+path}
    action_id=secrets.token_hex(12)
    try:
        reason=None
        try:
            if device_identity(request)!=s['device_id']: reason='session_device_mismatch'
        except HTTPException: reason='verified_device_certificate_required'
        if not reason and s['state']!='ACTIVE': reason='session_revoked'
        # Ineligible attempts remain auditable without inflating the authenticated
        # request-rate signal (which counts only kind=request).
        await log({'kind':'request_rejected' if reason else 'request','session_id':s['session_id'],
                   'subject':s['subject'],'device_id':s['device_id'],'request':current,'action_id':action_id})
        if reason:
            record=action_record(s,'DENY_REQUEST',None,reason,'request',current,action_id,from_pe=False)
            latest=load(s['session_id']); remember_action(latest,record); save(latest)
            await log_action(record)
            raise HTTPException(403,reason)
        # Evaluate authorized scope for health first, then requested scope.
        result=await decision(s)
        if result['decision']!='ALLOW':
            await revoke(s,result,'request',current,action_id); raise HTTPException(403,'session_revoked')
        result=await decision(s,current,active=False)
        if result['decision']!='ALLOW' or current!=s['scope']:
            reason='policy_denied' if result['decision']!='ALLOW' else 'session_scope_mismatch'
            record=action_record(s,'DENY_REQUEST',result,reason,'request',current,action_id)
            latest=load(s['session_id']); remember_action(latest,record); save(latest)
            await log_action(record,result)
            return JSONResponse({'decision':result,'reason':reason,'authorization':record},status_code=403)
        latest=load(s['session_id'])
        if latest['state']!='ACTIVE': raise HTTPException(403,'session_revoked')
        latest.update(last=result,pa_action='AUTHORIZE_REQUEST',pep_state='FORWARD')
        record=action_record(latest,'AUTHORIZE_REQUEST',result,'required_conditions_met','request',current,action_id)
        remember_action(latest,record); save(latest)
        await log_action(record,result)
        return Response(status_code=200,headers={'x-zta-subject':s['subject'],'x-zta-session':s['session_id']})
    except HTTPException: raise
    except Exception:
        await revoke(s,{'decision':'REVOKE','trust_score':0,'reasons':['control_plane_unavailable']},
                     'request',current,action_id,from_pe=False)
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
    await revoke(s,{'decision':'REVOKE','trust_score':0,'reasons':['administrator_revocation']},
                 operation='administrator',from_pe=False)
    return public(load(body.session_id))
