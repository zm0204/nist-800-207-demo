import importlib
from fastapi.testclient import TestClient

def client(tmp_path,monkeypatch):
    monkeypatch.setenv('SERVICE_KEY','test-key');monkeypatch.setenv('STATE_DIR',str(tmp_path))
    import app.common
    importlib.reload(app.common)
    import app.dashboard
    importlib.reload(app.dashboard)
    return TestClient(app.dashboard.app)

def test_untrusted_host_rejected(tmp_path,monkeypatch):
    c=client(tmp_path,monkeypatch)
    assert c.get('/',headers={'Host':'evil.example'}).status_code==400

def test_console_origin_and_csp(tmp_path,monkeypatch):
    c=client(tmp_path,monkeypatch)
    assert c.get('/').status_code==200
    assert "frame-ancestors 'none'" in c.get('/').headers['content-security-policy']
    assert c.post('/simulate',json={'action':'reset'},headers={'Origin':'https://evil.example'}).status_code==403
    assert c.post('/simulate',content='action=reset').status_code==415
