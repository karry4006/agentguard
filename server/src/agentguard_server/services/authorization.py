"""Trusted principal and fixed V13 permission registry."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from agentguard_server.services.auth import AuthContext

ROLE_PERMISSIONS = {
    "VIEWER": frozenset({
        "dashboard:access", "traces:read", "analysis:read", "replay:read",
        "evaluations:read", "incidents:read", "notifications:read", "system:read", "integrity:read", "archives:read",
    }),
    "ENGINEER": frozenset({
        "dashboard:access", "traces:read", "analysis:read", "analysis:run",
        "replay:read", "replay:run", "evaluations:read", "evaluations:run",
        "incidents:read", "incidents:manage", "notifications:read", "system:read", "integrity:read", "archives:read",
    }),
    "ADMIN": frozenset({
        "dashboard:access", "traces:read", "analysis:read", "analysis:run",
        "replay:read", "replay:run", "evaluations:read", "evaluations:run",
        "evaluations:manage", "incidents:read", "incidents:manage",
        "notifications:read", "notifications:manage", "members:read", "members:manage",
        "keys:manage", "system:read", "integrity:read", "integrity:anchor", "archives:read", "retention:manage", "retention:hold",
    }),
}
PERMISSIONS = frozenset().union(*ROLE_PERMISSIONS.values())


@dataclass(frozen=True)
class Principal:
    principal_type: str
    principal_id: UUID
    tenant_id: UUID | None
    permissions: frozenset[str]
    public_id: str | None = None
    organization_id: UUID | None = None
    membership_id: UUID | None = None
    role: str | None = None
    display_name: str | None = None
    organization_name: str | None = None

    @property
    def scopes(self) -> frozenset[str]:
        return self.permissions

    def allows(self, permission: str) -> bool:
        return permission in PERMISSIONS and permission in self.permissions


def principal_from_api_key(context: AuthContext) -> Principal:
    return Principal("API_KEY", context.api_key_id, context.tenant_id, context.scopes, public_id=context.public_id)


def role_permissions(role: str | None) -> frozenset[str]:
    return ROLE_PERMISSIONS.get(role or "", frozenset())

