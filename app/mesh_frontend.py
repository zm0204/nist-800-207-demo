"""Service-only demo facade. It forwards no caller credentials or identity headers."""
import os

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response

app = FastAPI(title='207A Mesh Frontend')
backend_transport = None


@app.get('/health')
def health():
    return {'ok': True}


@app.get('/')
def index():
    return {'demo': 'SP 800-207A service identity', 'resources': ['/api/salary', '/api/profile'],
            'identity': 'Istio mTLS ServiceAccount identity',
            'note': 'Operator demo; end-user authentication remains in the original 207 stack'}


@app.get('/api/salary')
@app.get('/api/profile')
async def resource(request: Request):
    name = request.url.path.rsplit('/', 1)[1]
    base = os.environ.get(name.upper() + '_URL', f'http://{name}:8000')
    try:
        async with httpx.AsyncClient(timeout=4, trust_env=False, transport=backend_transport) as client:
            upstream = await client.get(base + '/api/' + name)
        return Response(upstream.content, status_code=upstream.status_code,
                        media_type=upstream.headers.get('content-type', 'text/plain'))
    except httpx.HTTPError:
        raise HTTPException(503, 'mesh_backend_unavailable')
