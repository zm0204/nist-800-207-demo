from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from app.common import call, url, protected
from app.trust import evaluate
import json
import os
from pathlib import Path
from pydantic import Field
from app.service_trust import evaluate_service
from app.user_tokens import verify
from app import hr_state

app=FastAPI(title='Policy Engine',dependencies=[Depends(protected)])

class Access(BaseModel):
    identity:dict
    device_id:str
    request:dict
    active:bool=False

@app.get('/health')
def health(): return {'ok':True}

@app.post('/evaluate')
async def decide(body:Access):
    try:
        snapshot=await call(url('context'),'/snapshot')
        snapshot['identity']=body.identity
        if body.device_id!=snapshot['device']['id']: snapshot['device']['managed']=False
        result=evaluate(snapshot,body.request,body.active)
        await call(url('context'),'/event','POST',{'kind':'pe_decision',**result})
        return result
    except Exception:
        raise HTTPException(503,'policy_inputs_or_audit_unavailable')


class ServiceAccess(BaseModel):
    source: str = Field(max_length=512)
    destination: str = Field(max_length=512)
    method: str = Field(max_length=16)
    path: str = Field(max_length=8192)


@app.post('/evaluate-service')
async def decide_service(body: ServiceAccess):
    # Opt-in only: the original Compose PE has no workload policy configured.
    # Read per request so projected ConfigMap policy changes need no restart.
    try:
        policy = json.loads(Path(os.environ['SERVICE_POLICY_FILE']).read_text(encoding='utf-8'))
        result = evaluate_service(policy, **body.model_dump())
        await call(url('context'), '/event', 'POST',
                   {'kind': 'service_pe_decision', 'source': body.source,
                    'destination': body.destination, 'method': body.method,
                    'path': body.path.split('?', 1)[0], **result})
        return result
    except Exception:
        raise HTTPException(503, 'service_policy_or_audit_unavailable')


class ResourceAccess(ServiceAccess):
    token: str = Field(max_length=8192)
    attempt_id: str = Field(default='', max_length=80, pattern=r'^[a-zA-Z0-9_.-]*$')
    request_id: str = Field(default='', max_length=80, pattern=r'^[a-zA-Z0-9_.-]*$')


@app.post('/evaluate-resource')
async def decide_resource(body: ResourceAccess):
    evidence = {k: v for k, v in body.model_dump().items() if k != 'token'}
    try:
        try:
            claims = verify(body.token)
        except ValueError:
            result = {'decision': 'DENY', 'reason': 'invalid_user_token'}
        else:
            evidence['claims'] = claims
            session = await call(url('pa'), '/credential-context', 'POST',
                {'sid': claims['sid'], 'subject': claims['sub'], 'device_id': claims['device_id']})
            snapshot = await call(url('context'), '/snapshot')
            device = snapshot['device']
            if not session.get('valid'):
                result = {'decision': 'DENY', 'reason': 'session_revoked_or_expired'}
            elif device['id'] != claims['device_id'] or not device.get('managed') or device.get('compromised'):
                result = {'decision': 'DENY', 'reason': 'device_risk_denied'}
            elif snapshot['context'].get('high_risk_ip') or snapshot['context'].get('abnormal'):
                result = {'decision': 'DENY', 'reason': 'context_risk_denied'}
            else:
                result = hr_state.decide(claims, body.path, body.method)
        await call(url('context'), '/event', 'POST', {'kind': 'resource_pe_decision', **evidence, **result})
        return result
    except Exception:
        raise HTTPException(503, 'resource_policy_inputs_or_audit_unavailable')


@app.get('/resource-state/{subject}')
def resource_state(subject: str):
    return hr_state.get_state(subject)


class RiskUpdate(BaseModel):
    subject_blocked: bool = False
    device_blocked: bool = False
    quarantined: bool = False


@app.put('/resource-state/{subject}')
async def update_resource_state(subject: str, body: RiskUpdate):
    # Explicit operator-only recovery, never called by login or token exchange.
    from app.hr_policy import DIRECTORY
    if subject not in DIRECTORY:
        raise HTTPException(404, 'unknown_subject')
    await call(url('context'), '/event', 'POST', {'kind': 'operator_risk_change', 'subject': subject, **body.model_dump()})
    return hr_state.set_state(subject, body.model_dump())
