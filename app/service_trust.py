"""Separate workload policy domain; does not reuse human/device risk scores."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ServiceGrant(BaseModel):
    model_config = ConfigDict(extra='forbid')
    source: str = Field(pattern=r'^spiffe://[a-z0-9.-]+/ns/[a-z0-9-]+/sa/[a-z0-9-]+$')
    destination: str = Field(pattern=r'^spiffe://[a-z0-9.-]+/ns/[a-z0-9-]+/sa/[a-z0-9-]+$')
    method: Literal['GET']
    path: Literal['/api/salary', '/api/profile']


class ServicePolicy(BaseModel):
    model_config = ConfigDict(extra='forbid')
    version: int = Field(strict=True, ge=1)
    grants: list[ServiceGrant] = Field(max_length=100)


def evaluate_service(policy: dict, source: str, destination: str, method: str, path: str) -> dict:
    checked = ServicePolicy.model_validate(policy)
    requested = dict(source=source, destination=destination, method=method, path=path.split('?', 1)[0])
    allowed = any(grant.model_dump() == requested for grant in checked.grants)
    return {'decision': 'ALLOW' if allowed else 'DENY',
            'reason': 'workload_grant_matched' if allowed else 'no_workload_grant',
            'policy_version': checked.version}
