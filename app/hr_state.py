"""Transactional per-subject behavioral state, independent of token lifetime."""
import json
import time
from app.common import db
from app.hr_policy import evaluate_resource, WINDOW


def connect():
    c = db('hr-risk')
    c.execute('CREATE TABLE IF NOT EXISTS risk(subject TEXT PRIMARY KEY, value TEXT NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS reads(subject TEXT, ts REAL)')
    c.execute('CREATE INDEX IF NOT EXISTS reads_subject_ts ON reads(subject,ts)')
    return c


def get_state(subject):
    with connect() as c:
        row = c.execute('SELECT value FROM risk WHERE subject=?', (subject,)).fetchone()
    return json.loads(row[0]) if row else {}


def set_state(subject, state):
    with connect() as c:
        c.execute('BEGIN IMMEDIATE')
        c.execute('INSERT OR REPLACE INTO risk VALUES (?,?)', (subject, json.dumps(state)))
        if not state.get('quarantined'):
            c.execute('DELETE FROM reads WHERE subject=?', (subject,))
    return state


def decide(claims, path, method):
    with connect() as c:
        c.execute('BEGIN IMMEDIATE')
        subject = claims['sub']
        now = time.time()
        row = c.execute('SELECT value FROM risk WHERE subject=?', (subject,)).fetchone()
        state = json.loads(row[0]) if row else {}
        c.execute('DELETE FROM reads WHERE ts<?', (now-WINDOW,))
        count = c.execute('SELECT COUNT(*) FROM reads WHERE subject=?', (subject,)).fetchone()[0]
        result = evaluate_resource(claims, path, method, state, count)
        if result['reason'] == 'behavioral_quarantine':
            state.update(quarantined=True)
            c.execute('INSERT OR REPLACE INTO risk VALUES (?,?)', (subject, json.dumps(state)))
        if result['decision'] == 'ALLOW':
            c.execute('INSERT INTO reads VALUES (?,?)', (subject, now))
        return {**result, 'recent_requests': count, 'quarantined': state.get('quarantined', False)}
