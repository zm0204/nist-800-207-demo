"""Application defense in depth; receiving sidecars enforce workload identity."""
import re
from uuid import uuid4

from fastapi import HTTPException
from app.user_tokens import bearer, verify


def authenticated(request):
    try:
        return verify(bearer(request))
    except ValueError:
        raise HTTPException(401, 'verified_user_jwt_required')


def resource_claims(request, resource, owner, method='GET'):
    claims = authenticated(request)
    required = resource + (':read' if method == 'GET' else ':write')
    if required not in claims['scope'].split():
        raise HTTPException(403, 'scope_denied')
    if claims['sub'] != owner:
        raise HTTPException(403, 'resource_ownership_denied')
    return claims


def correlation(request):
    # Correlation is never authentication. Reject control characters/oversized IDs.
    return {name: value if re.fullmatch(r'[a-zA-Z0-9_.-]{1,80}', value) else str(uuid4())
            for name in ('x-request-id', 'x-attempt-id')
            for value in [request.headers.get(name, '')]}
