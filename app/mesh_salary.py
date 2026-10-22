"""Synthetic salary service. Network authentication/authorization belongs to its sidecar."""
from fastapi import FastAPI, Request
from app.mesh_identity import resource_claims

app = FastAPI(title='207A Salary Service')


@app.get('/health')
def health():
    return {'ok': True}


@app.get('/api/salary')
def salary():
    return {'resource': 'salary', 'subject': 'alice', 'currency': 'TWD',
            'amount': 50000, 'note': 'Synthetic demo data; workload-only authorization'}


@app.get('/api/salary/{owner}')
def user_salary(owner: str, request: Request):
    resource_claims(request, 'salary', owner)
    return {'resource': 'salary', 'subject': owner, 'currency': 'TWD',
            'amount': 50000, 'synthetic': True}
