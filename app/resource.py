import asyncio
import json
import os
import ssl
import time
from pathlib import Path
import httpx
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.responses import StreamingResponse
from app.common import KEY

app=FastAPI(title='Protected Resource')

def pep_identity(x_zta_subject:str=Header(default=''),x_zta_session:str=Header(default='')):
    # This is only meaningful together with upstream mTLS (dedicated CA) and
    # the data-only Docker network. Headers alone are not authentication.
    if x_zta_subject!='alice' or not x_zta_session: raise HTTPException(403,'PEP authorization required')
    return x_zta_session

@app.get('/api/salary',dependencies=[Depends(pep_identity)])
def salary(): return {'resource':'salary','subject':'alice','currency':'TWD','amount':50000,'note':'Synthetic demo data'}

@app.get('/api/profile',dependencies=[Depends(pep_identity)])
def profile(): return {'resource':'profile','subject':'alice','role':'employee','data':'Synthetic demo profile'}

async def session_status(sid):
    root=Path(os.environ.get('CERT_DIR','/certs'))
    tls=ssl.create_default_context(cafile=str(root/'service-ca.crt'))
    tls.load_cert_chain(root/'resource-client.crt',root/'resource-client.key')
    async with httpx.AsyncClient(verify=tls,timeout=3,trust_env=False) as client:
        r=await client.get(os.environ.get('CALLBACK_URL','https://pep:9444')+'/status/'+sid,headers={'x-service-key':KEY})
        r.raise_for_status(); return r.json()

async def stream_events(sid,interval=1):
    while True:
        try:
            state=await session_status(sid)
            if state['state']!='ACTIVE':
                yield 'event: revoked\ndata: '+json.dumps({'state':'REVOKED'})+'\n\n'; return
        except Exception:
            yield 'event: revoked\ndata: '+json.dumps({'reason':'control_plane_unavailable'})+'\n\n'; return
        yield 'event: resource\ndata: '+json.dumps({'timestamp':time.time(),'resource':'live-demo','state':'ACTIVE'})+'\n\n'
        await asyncio.sleep(interval)

@app.get('/api/stream')
def stream(sid:str=Depends(pep_identity)):
    return StreamingResponse(stream_events(sid),media_type='text/event-stream',headers={'cache-control':'no-store'})
