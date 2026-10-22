"""Exercise real Envoy v3 messages and gRPC transport; HTTP double is the PE boundary."""
import httpx
import pytest

pytest.importorskip('grpc')
import grpc
from envoy.service.auth.v3 import external_auth_pb2 as auth
from envoy.service.auth.v3 import external_auth_pb2_grpc as auth_grpc

SOURCE = 'spiffe://cluster.local/ns/zta-207a/sa/frontend'
TARGET = 'spiffe://cluster.local/ns/zta-207a/sa/salary'


def check_request(source=SOURCE, destination=TARGET):
    request = auth.CheckRequest()
    request.attributes.source.principal = source
    request.attributes.destination.principal = destination
    request.attributes.request.http.method = 'GET'
    request.attributes.request.http.path = '/api/salary?trace=1'
    # These untrusted headers must have no bearing on the PE's identity input.
    request.attributes.request.http.headers['x-forwarded-client-cert'] = 'URI=' + SOURCE
    request.attributes.request.http.headers['x-zta-subject'] = 'admin'
    return request


async def grpc_check(monkeypatch, request, handler):
    from app import mesh_authz
    monkeypatch.setattr(mesh_authz, 'pe_transport', httpx.MockTransport(handler))
    monkeypatch.setenv('SERVICE_KEY', 'adapter-key')
    server = grpc.aio.server()
    auth_grpc.add_AuthorizationServicer_to_server(mesh_authz.Authorization(), server)
    port = server.add_insecure_port('127.0.0.1:0')
    await server.start()
    try:
        async with grpc.aio.insecure_channel(f'127.0.0.1:{port}') as channel:
            return await auth_grpc.AuthorizationStub(channel).Check(request, timeout=5)
    finally:
        await server.stop(0)


@pytest.mark.asyncio
async def test_adapter_passes_authenticated_metadata_to_pe(monkeypatch):
    import json
    seen = []
    def pe(request):
        seen.append(json.loads(request.content))
        assert request.headers['x-service-key'] == 'adapter-key'
        return httpx.Response(200, json={'decision': 'ALLOW', 'policy_version': 1})
    response = await grpc_check(monkeypatch, check_request(), pe)
    assert response.status.code == 0 and response.HasField('ok_response')
    assert seen == [dict(source=SOURCE, destination=TARGET, method='GET', path='/api/salary?trace=1')]


@pytest.mark.asyncio
@pytest.mark.parametrize('source,destination', [('', TARGET), (SOURCE, ''), ('forged', TARGET)])
async def test_forged_headers_cannot_replace_authenticated_metadata(monkeypatch, source, destination):
    def must_not_call_pe(request):
        pytest.fail('No authenticated principal: must deny locally')
    response = await grpc_check(monkeypatch, check_request(source, destination), must_not_call_pe)
    assert response.status.code == 7
    assert response.denied_response.status.code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize('status,payload', [(200, {'decision': 'DENY'}), (503, {}), (200, {}), (200, {'decision': True})])
async def test_pe_denial_outage_and_malformed_decision_never_allow(monkeypatch, status, payload):
    response = await grpc_check(monkeypatch, check_request(), lambda r: httpx.Response(status, json=payload))
    assert response.status.code == 7 and response.HasField('denied_response')


@pytest.mark.asyncio
async def test_pe_transport_outage_fails_closed(monkeypatch):
    def offline(request):
        raise httpx.ConnectError('PE offline', request=request)
    response = await grpc_check(monkeypatch, check_request(), offline)
    assert response.status.code == 7 and response.denied_response.status.code == 503


@pytest.mark.asyncio
async def test_identity_adapter_forwards_token_to_dynamic_pe_never_identity_headers(monkeypatch):
    import json
    monkeypatch.setenv('IDENTITY_MODE', '1')
    request = check_request()
    request.attributes.request.http.headers['authorization'] = 'Bearer test-credential'
    request.attributes.request.http.headers['x-attempt-id'] = 'unique-attempt'
    request.attributes.request.http.headers['x-request-id'] = 'unique-request'
    def pe(r):
        assert r.url.path == '/evaluate-resource'
        body = json.loads(r.content)
        assert body['source'] == SOURCE and body['token'] == 'test-credential'
        assert body['attempt_id'] == 'unique-attempt' and body['request_id'] == 'unique-request'
        assert 'x-zta-subject' not in body and 'role' not in body
        return httpx.Response(200, json={'decision': 'DENY'})
    response = await grpc_check(monkeypatch, request, pe)
    assert response.status.code == 7
