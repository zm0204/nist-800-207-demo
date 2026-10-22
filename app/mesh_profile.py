"""Synthetic profile service, independently deployable from salary."""
from fastapi import FastAPI, Request
from app.mesh_identity import resource_claims

app = FastAPI(title='207A Profile Service')


@app.get('/health')
def health():
    return {'ok': True}


@app.get('/api/profile')
def profile():
    return {'resource': 'profile', 'subject': 'alice', 'role': 'employee',
            'data': 'Synthetic demo profile; workload-only authorization'}


@app.get('/api/profile/{owner}')
def user_profile(owner: str, request: Request):
    resource_claims(request, 'profile', owner)
    return {'resource': 'profile', 'subject': owner, 'role': 'employee', 'synthetic': True}
