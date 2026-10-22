"""Synthetic salary service. Network authentication/authorization belongs to its sidecar."""
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from app.mesh_identity import resource_claims
from app.resource_evidence import execute
import os

app = FastAPI(title='207A Salary Service')


@app.get('/health')
def health():
    return {'ok': True}


@app.get('/api/salary')
def salary():
    if os.environ.get('IDENTITY_MODE') == '1':
        raise HTTPException(410, 'use_identity_aware_resource_path')
    return {'resource': 'salary', 'subject': 'alice', 'currency': 'TWD',
            'amount': 50000, 'note': 'Synthetic demo data; workload-only authorization'}


@app.get('/api/salary/{owner}')
def user_salary(owner: str, request: Request):
    claims = resource_claims(request, 'salary', owner)
    amount = execute(request, claims, 'salary', owner)
    return {'resource': 'salary', 'subject': owner, 'currency': 'TWD',
            'amount': amount, 'synthetic': True}


class Adjustment(BaseModel):
    model_config = ConfigDict(extra='forbid')
    amount: int = Field(strict=True, ge=0, le=10000000)


@app.post('/api/salary/{owner}/adjust')
def adjust_salary(owner: str, body: Adjustment, request: Request):
    claims = resource_claims(request, 'salary', owner, 'POST')
    amount = execute(request, claims, 'salary', owner, body.amount)
    return {'resource': 'salary', 'subject': owner, 'amount': amount, 'synthetic': True, 'adjusted': True}
