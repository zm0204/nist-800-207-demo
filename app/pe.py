from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from app.common import call, url, protected
from app.trust import evaluate

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
