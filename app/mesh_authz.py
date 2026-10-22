"""Opt-in Envoy v3 gRPC adapter to the existing PE's workload endpoint.

Istio ALLOW trusts the destination backend Pods/ServiceAccounts, including their
application processes. Native data-plane ALLOW remains required independently.
An application-provided XFCC/subject header is never a workload identity source.
"""
import asyncio
import json
import os

import grpc
import httpx
from envoy.service.auth.v3 import external_auth_pb2 as auth
from envoy.service.auth.v3 import external_auth_pb2_grpc as auth_grpc
from envoy.type.v3.http_status_pb2 import HttpStatus
from google.rpc.status_pb2 import Status

pe_transport = None


def denied(http_status=403):
    return auth.CheckResponse(status=Status(code=7),
                              denied_response=auth.DeniedHttpResponse(status=HttpStatus(code=http_status)))


class Authorization(auth_grpc.AuthorizationServicer):
    async def Check(self, request, context):
        attributes = request.attributes
        source = attributes.source.principal
        destination = attributes.destination.principal
        if not source.startswith('spiffe://') or not destination.startswith('spiffe://'):
            return denied()
        body = dict(source=source, destination=destination,
                    method=attributes.request.http.method, path=attributes.request.http.path)
        endpoint = '/evaluate-service'
        if os.environ.get('IDENTITY_MODE') == '1':
            endpoint = '/evaluate-resource'
            headers = attributes.request.http.headers
            authorization = headers.get('authorization', '')
            body.update(token=authorization[7:] if authorization.startswith('Bearer ') else '',
                        request_id=headers.get('x-request-id', ''), attempt_id=headers.get('x-attempt-id', ''))
        try:
            key = os.environ['SERVICE_KEY']
            if not key:
                return denied(503)
            async with httpx.AsyncClient(timeout=2, trust_env=False, transport=pe_transport) as client:
                response = await client.post(os.environ.get('PE_URL', 'http://pe:8000') + endpoint,
                                             headers={'x-service-key': key}, json=body)
            response.raise_for_status()
            allowed = response.json().get('decision') == 'ALLOW'
            print(json.dumps({'kind': 'mesh_ext_authz', 'source': source, 'destination': destination,
                              'method': body['method'], 'path': body['path'].split('?', 1)[0],
                              'decision': 'ALLOW' if allowed else 'DENY'}), flush=True)
            if allowed:
                return auth.CheckResponse(status=Status(code=0), ok_response=auth.OkHttpResponse())
            return denied()
        except (httpx.HTTPError, ValueError, KeyError, AttributeError):
            return denied(503)


async def serve():
    if not os.environ.get('SERVICE_KEY'):
        raise RuntimeError('SERVICE_KEY is required')
    server = grpc.aio.server(options=[('grpc.max_receive_message_length', 65536)])
    auth_grpc.add_AuthorizationServicer_to_server(Authorization(), server)
    server.add_insecure_port('[::]:9000')  # Sidecar enforces mTLS on the network hop.
    await server.start()
    await server.wait_for_termination()


if __name__ == '__main__':
    asyncio.run(serve())
