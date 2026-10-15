"""Synthetic salary service. Network authentication/authorization belongs to its sidecar."""
from fastapi import FastAPI

app = FastAPI(title='207A Salary Service')


@app.get('/health')
def health():
    return {'ok': True}


@app.get('/api/salary')
def salary():
    return {'resource': 'salary', 'subject': 'alice', 'currency': 'TWD',
            'amount': 50000, 'note': 'Synthetic demo data; workload-only authorization'}
