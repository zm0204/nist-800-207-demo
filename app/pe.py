from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from app.common import call, url, protected
from app.trust import evaluate
import json
import os
from pathlib import Path
from pydantic import Field
from app.service_trust import evaluate_service

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
