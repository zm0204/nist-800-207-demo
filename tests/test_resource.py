import importlib
import pytest

@pytest.fixture
def resource(tmp_path,monkeypatch):
    monkeypatch.setenv('SERVICE_KEY','test-key'); monkeypatch.setenv('STATE_DIR',str(tmp_path))
    import app.common
    importlib.reload(app.common)
    import app.resource
    importlib.reload(app.resource)
    return app.resource

async def test_stream_stops_on_revoke(resource,monkeypatch):
    states=iter(['ACTIVE','REVOKED'])
    async def status(sid): return {'state':next(states)}
    monkeypatch.setattr(resource,'session_status',status)
    items=[x async for x in resource.stream_events('sid',interval=0)]
    assert len(items)==2 and 'revoked' in items[-1]

async def test_stream_fail_closed(resource,monkeypatch):
    async def down(sid): raise RuntimeError('PA offline')
    monkeypatch.setattr(resource,'session_status',down)
    items=[x async for x in resource.stream_events('sid',interval=0)]
    assert len(items)==1 and 'control_plane_unavailable' in items[0]

def test_resource_requires_pep_identity(resource):
    from fastapi.testclient import TestClient
    c=TestClient(resource.app)
    assert c.get('/api/salary').status_code==403
    assert c.get('/api/salary',headers={'x-zta-subject':'alice','x-zta-session':'s'}).status_code==200
