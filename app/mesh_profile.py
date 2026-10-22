"""Synthetic profile service, independently deployable from salary."""
from fastapi import FastAPI, Request, HTTPException
from app.mesh_identity import resource_claims
from app.resource_evidence import execute
import os

app = FastAPI(title='207A Profile Service')


@app.get('/health')
def health():
    return {'ok': True}


@app.get('/api/profile')
def profile():
    if os.environ.get('IDENTITY_MODE') == '1':
        raise HTTPException(410, 'use_identity_aware_resource_path')
    return {'resource': 'profile', 'subject': 'alice', 'role': 'employee',
            'data': 'Synthetic demo profile; workload-only authorization'}


@app.get('/api/profile/{owner}')
def user_profile(owner: str, request: Request):
    claims = resource_claims(request, 'profile', owner)
    execute(request, claims, 'profile', owner)
    return {'resource': 'profile', 'subject': owner, 'role': 'employee', 'synthetic': True}
