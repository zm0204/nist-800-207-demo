"""Resource execution journal. Query through local exec, never a public API."""
import json
import os
import sqlite3
import time
from pathlib import Path
from app.mesh_identity import correlation


def connect():
    root = Path(os.environ['STATE_DIR'])
    root.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(root / 'executions.db', timeout=10)
    c.execute('CREATE TABLE IF NOT EXISTS executions(id INTEGER PRIMARY KEY, attempt TEXT, value TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS salary(owner TEXT PRIMARY KEY, amount INTEGER)')
    return c


def execute(request, claims, resource, owner, amount=None):
    ids = correlation(request)
    event = dict(kind='resource_execution', attempt_id=ids['x-attempt-id'],
                 request_id=ids['x-request-id'], subject=claims['sub'], owner=owner,
                 resource=resource, method=request.method, timestamp=time.time())
    with connect() as c:
        c.execute('BEGIN IMMEDIATE')
        if amount is not None:
            c.execute('INSERT OR REPLACE INTO salary VALUES (?,?)', (owner, amount))
        row = c.execute('SELECT amount FROM salary WHERE owner=?', (owner,)).fetchone()
        value = row[0] if row else 50000
        c.execute('INSERT INTO executions(attempt,value) VALUES (?,?)', (event['attempt_id'], json.dumps(event)))
    print(json.dumps(event), flush=True)
    return value


def executions(attempt):
    with connect() as c:
        return [json.loads(r[0]) for r in c.execute('SELECT value FROM executions WHERE attempt=?', (attempt,))]
