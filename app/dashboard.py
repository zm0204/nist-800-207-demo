"""Local operator dashboard plus the demo device agent. Browser holds no device key."""
import os
import ssl
from pathlib import Path
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel
from app.common import call, url

app=FastAPI(title='800-207 Dashboard / Device Agent')
app.add_middleware(TrustedHostMiddleware,allowed_hosts=['localhost','127.0.0.1','testserver'])
STATIC=Path(__file__).resolve().parents[1]/'static'
app.mount('/static',StaticFiles(directory=STATIC),name='static')

@app.middleware('http')
async def local_console(request:Request,call_next):
    origin=request.headers.get('origin')
    expected=os.environ.get('WEBAUTHN_ORIGIN','http://localhost:8080')
    if origin and origin!=expected: return JSONResponse({'detail':'cross-origin console request rejected'},403)
    if request.method in ('POST','PUT','PATCH','DELETE') and not request.headers.get('content-type','').startswith('application/json'):
        return JSONResponse({'detail':'application/json required'},415)
    response=await call_next(request)
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    return response

@app.get('/')
def index(): return FileResponse(STATIC/'index.html')

@app.get('/health')
def health(): return {'ok':True}

@app.post('/identity/{operation:path}')
async def identity(operation:str,request:Request):
    if operation not in ('register/options','register/verify','login/options','login/verify'):
        raise HTTPException(404,'unsupported identity operation')
    async with httpx.AsyncClient(timeout=5,trust_env=False) as client:
        r=await client.post(url('identity')+'/'+operation,json=await request.json())
        return JSONResponse(r.json(),status_code=r.status_code)

def agent_client():
    root=Path(os.environ.get('CERT_DIR','/certs'))
    tls=ssl.create_default_context(cafile=str(root/'service-ca.crt'))
    tls.load_cert_chain(root/'device-a.crt',root/'device-a.key')
    return httpx.AsyncClient(verify=tls,timeout=10,trust_env=False)

PEP=os.environ.get('PEP_URL','https://pep:8443')

class Session(BaseModel):
    human_token:str
    path:str='/api/salary'

@app.post('/agent/session')
async def session(body:Session):
    if body.path not in ('/api/salary','/api/profile','/api/stream'): raise HTTPException(400,'unsupported scope')
    try:
        async with agent_client() as client:
            r=await client.post(PEP+'/session',json={'path':body.path,'method':'GET'},headers={'authorization':'Bearer '+body.human_token})
            return JSONResponse(r.json(),r.status_code)
    except Exception: raise HTTPException(503,'PEP connection failed')

class Access(BaseModel):
    session_id:str
    path:str='/api/salary'
    method:str='GET'

@app.post('/agent/request')
async def access(body:Access):
    if body.path not in ('/api/salary','/api/profile') or body.method not in ('GET','POST'):
        raise HTTPException(400,'unsupported request')
    try:
        async with agent_client() as client:
            r=await client.request(body.method,PEP+body.path,headers={'authorization':'Bearer '+body.session_id})
            try: result=r.json()
            except ValueError: result={'detail':r.text}
            return {'status':r.status_code,'resource_response':result}
    except Exception: raise HTTPException(503,'PEP connection failed')

@app.post('/agent/stream')
async def stream(body:Access):
    async def relay():
        async with agent_client() as client:
            async with client.stream('GET',PEP+'/api/stream',headers={'authorization':'Bearer '+body.session_id},timeout=None) as r:
                if r.status_code!=200:
                    yield f'event: denied\ndata: {{"status":{r.status_code}}}\n\n'; return
                async for chunk in r.aiter_bytes(): yield chunk
    return StreamingResponse(relay(),media_type='text/event-stream')

@app.get('/view')
async def view():
    try:
        snapshot=await call(url('context'),'/snapshot')
        sessions=await call(url('pa'),'/sessions')
        events=await call(url('context'),'/events')
        return {'snapshot':snapshot,'sessions':sessions,'events':events}
    except Exception: raise HTTPException(503,'control plane unavailable')

class Simulation(BaseModel): action:str

@app.post('/simulate')
async def simulate(body:Simulation): return await call(url('context'),'/simulate','POST',body.model_dump())

class Revoke(BaseModel): session_id:str

@app.post('/revoke')
async def revoke(body:Revoke): return await call(url('pa'),'/revoke','POST',body.model_dump())

@app.put('/policy')
async def policy(request:Request): return await call(url('context'),'/policy','PUT',await request.json())
