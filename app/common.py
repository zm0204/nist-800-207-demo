import os
import sqlite3
from pathlib import Path
from fastapi import Header, HTTPException
import httpx

KEY = os.environ.get('SERVICE_KEY', '')
if not KEY:
    raise RuntimeError('SERVICE_KEY required; run scripts/init.py and load .env')

def protected(x_service_key: str = Header(default='')):
    import secrets
    if not secrets.compare_digest(x_service_key, KEY):
        raise HTTPException(403, 'control_plane_service_key_required')

def db(name):
    root = Path(os.environ.get('STATE_DIR', '/state'))
    root.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(root / f'{name}.db', timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

async def call(base, path, method='GET', data=None):
    async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
        response = await client.request(method, base + path, json=data,
                                        headers={'x-service-key':KEY})
        response.raise_for_status()
        return response.json()

def url(name):
    return os.environ.get(name.upper() + '_URL', f'http://{name}:8000')
