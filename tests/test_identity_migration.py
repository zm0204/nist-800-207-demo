import hashlib
import importlib
import sqlite3
import time


def test_additive_migration_preserves_legacy_credentials_and_tokens(tmp_path, monkeypatch):
    path = tmp_path/'identity.db'
    with sqlite3.connect(path) as c:
        c.execute('CREATE TABLE credential(id TEXT PRIMARY KEY, public_key BLOB, counter INTEGER)')
        c.execute('INSERT INTO credential VALUES (?,?,?)', ('existing-id', b'existing-key', 42))
        c.execute('CREATE TABLE challenge(id TEXT PRIMARY KEY, kind TEXT, challenge BLOB, expires REAL)')
        c.execute('CREATE TABLE token(hash TEXT PRIMARY KEY, expires REAL)')
        c.execute('INSERT INTO token VALUES (?,?)', (hashlib.sha256(b'old-token').hexdigest(), time.time()+900))
    monkeypatch.setenv('STATE_DIR', str(tmp_path))
    monkeypatch.setenv('SERVICE_KEY', 'test-key')
    from app import common, identity
    importlib.reload(common)
    importlib.reload(identity)
    identity.initialize()
    with sqlite3.connect(path) as c:
        row = c.execute('SELECT id,public_key,counter,subject FROM credential').fetchone()
        assert row == ('existing-id', b'existing-key', 42, 'alice')
        assert c.execute('SELECT transports FROM credential').fetchone()[0] == '[]'
    result = identity.introspect(identity.Token(token='old-token'))
    assert result['valid'] and result['subject'] == 'alice'
    assert result['auth_time'] == 0  # Legacy login remains valid; exchange needs a fresh login.
