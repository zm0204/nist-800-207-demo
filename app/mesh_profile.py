"""Synthetic profile service, independently deployable from salary."""
from fastapi import FastAPI

app = FastAPI(title='207A Profile Service')


@app.get('/health')
def health():
    return {'ok': True}


@app.get('/api/profile')
def profile():
    return {'resource': 'profile', 'subject': 'alice', 'role': 'employee',
            'data': 'Synthetic demo profile; workload-only authorization'}
