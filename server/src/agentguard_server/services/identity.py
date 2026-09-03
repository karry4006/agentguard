"""Organization membership administration with fixed-role RBAC."""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentguard_server.models import ApiKey, DashboardSession, HumanUser, IdentityAuditEvent, Organization, OrganizationMembership
from agentguard_server.services.auth import SCOPES, create_api_key
from agentguard_server.services.authorization import Principal, ROLE_PERMISSIONS

logger = logging.getLogger("agentguard.security")


class IdentityValidationError(ValueError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _require_admin(principal: Principal) -> None:
    if principal.principal_type != "HUMAN_SESSION" or not principal.allows("members:manage") or not principal.organization_id:
        raise PermissionError("member administration denied")


def _audit(db: Session, principal: Principal, event_type: str, user: HumanUser | None = None,
           membership: OrganizationMembership | None = None, metadata: dict | None = None) -> None:
    db.add(IdentityAuditEvent(
        tenant_id=principal.tenant_id, organization_id=principal.organization_id,
        actor_type="HUMAN_USER", actor_id=str(principal.principal_id), event_type=event_type,
        target_user_id=user.id if user else None,
        target_membership_id=membership.id if membership else None,
        metadata_json=metadata or {}, created_at=_now(),
    ))


def list_members(db: Session, principal: Principal, limit: int = 100) -> list[tuple[OrganizationMembership, HumanUser]]:
    if principal.principal_type != "HUMAN_SESSION" or not principal.allows("members:read") or not principal.organization_id:
        raise PermissionError("member read denied")
    return list(db.execute(
        select(OrganizationMembership, HumanUser)
        .join(HumanUser, HumanUser.id == OrganizationMembership.user_id)
        .where(OrganizationMembership.organization_id == principal.organization_id)
        .order_by(HumanUser.display_name, HumanUser.id).limit(min(max(limit, 1), 100))
    ))


def provision_member(db: Session, principal: Principal, issuer: str, subject: str,
                     display_name: str | None, email: str | None, role: str) -> OrganizationMembership:
    _require_admin(principal)
    role = role.strip().upper()
    subject = subject.strip()
    if role not in ROLE_PERMISSIONS or not subject or len(subject) > 255:
        raise IdentityValidationError("invalid member identity or role")
    user = db.scalar(select(HumanUser).where(
        HumanUser.external_issuer == issuer, HumanUser.external_subject == subject,
    ))
    now = _now()
    if user is None:
        user = HumanUser(external_issuer=issuer, external_subject=subject,
                         display_name=(display_name or subject)[:255],
                         email=email[:320] if email else None, created_at=now, updated_at=now)
        db.add(user)
        db.flush()
        _audit(db, principal, "user_created", user=user)
    existing = db.scalar(select(OrganizationMembership).where(
        OrganizationMembership.organization_id == principal.organization_id,
        OrganizationMembership.user_id == user.id,
    ))
    if existing is not None:
        raise IdentityValidationError("membership already exists")
    membership = OrganizationMembership(organization_id=principal.organization_id, user_id=user.id,
                                        role=role, created_at=now, updated_at=now)
    db.add(membership)
    db.flush()
    _audit(db, principal, "membership_created", user=user, membership=membership, metadata={"role": role})
    db.commit()
    logger.info("membership_created actor_id=%s organization_id=%s membership_id=%s role=%s",
                principal.principal_id, principal.organization_id, membership.id, role)
    return membership


def _scoped_membership(db: Session, principal: Principal, membership_id) -> OrganizationMembership | None:
    _require_admin(principal)
    return db.scalar(select(OrganizationMembership).where(
        OrganizationMembership.id == membership_id,
        OrganizationMembership.organization_id == principal.organization_id,
    ).with_for_update())


def _protect_last_admin(db: Session, membership: OrganizationMembership, new_role: str | None = None) -> None:
    removing_admin = membership.disabled_at is None and membership.role == "ADMIN" and new_role != "ADMIN"
    if not removing_admin:
        return
    active_admins = list(db.scalars(select(OrganizationMembership.id).where(
        OrganizationMembership.organization_id == membership.organization_id,
        OrganizationMembership.role == "ADMIN", OrganizationMembership.disabled_at.is_(None),
    ).with_for_update()))
    if len(active_admins) <= 1:
        raise IdentityValidationError("cannot remove the last active administrator")


def change_membership_role(db: Session, principal: Principal, membership_id, role: str) -> OrganizationMembership | None:
    role = role.strip().upper()
    if role not in ROLE_PERMISSIONS:
        raise IdentityValidationError("invalid role")
    membership = _scoped_membership(db, principal, membership_id)
    if membership is None:
        return None
    _protect_last_admin(db, membership, role)
    old_role = membership.role
    membership.role = role
    membership.updated_at = _now()
    _audit(db, principal, "membership_role_changed", membership=membership,
           metadata={"old_role": old_role, "new_role": role})
    db.commit()
    return membership


def disable_membership(db: Session, principal: Principal, membership_id) -> OrganizationMembership | None:
    membership = _scoped_membership(db, principal, membership_id)
    if membership is None:
        return None
    _protect_last_admin(db, membership)
    if membership.disabled_at is None:
        membership.disabled_at = _now()
        membership.updated_at = membership.disabled_at
        _audit(db, principal, "membership_disabled", membership=membership)
        db.commit()
    return membership


def selectable_organizations(db: Session, principal: Principal, limit: int = 50) -> list[tuple[OrganizationMembership, Organization]]:
    if principal.principal_type != "HUMAN_SESSION":
        raise PermissionError("organization selection denied")
    return list(db.execute(
        select(OrganizationMembership, Organization)
        .join(Organization, Organization.id == OrganizationMembership.organization_id)
        .where(OrganizationMembership.user_id == principal.principal_id,
               OrganizationMembership.disabled_at.is_(None))
        .order_by(Organization.name, Organization.id).limit(min(max(limit, 1), 50))
    ))


def select_organization(db: Session, principal: Principal, session: DashboardSession,
                        organization_id) -> bool:
    if principal.principal_type != "HUMAN_SESSION" or session.human_user_id != principal.principal_id:
        raise PermissionError("organization selection denied")
    row = db.execute(
        select(OrganizationMembership, Organization)
        .join(Organization, Organization.id == OrganizationMembership.organization_id)
        .where(OrganizationMembership.user_id == principal.principal_id,
               OrganizationMembership.organization_id == organization_id,
               OrganizationMembership.disabled_at.is_(None))
    ).one_or_none()
    if row is None:
        return False
    membership, organization = row
    if not ROLE_PERMISSIONS.get(membership.role):
        return False
    session.organization_id = organization.id
    session.tenant_id = organization.tenant_id
    db.add(IdentityAuditEvent(
        tenant_id=organization.tenant_id, organization_id=organization.id,
        actor_type="HUMAN_USER", actor_id=str(principal.principal_id),
        event_type="organization_selected", target_user_id=principal.principal_id,
        target_membership_id=membership.id, metadata_json={}, created_at=_now(),
    ))
    db.commit()
    return True


def bootstrap_admin(db: Session, tenant, issuer: str, subject: str,
                    display_name: str | None, email: str | None) -> OrganizationMembership:
    """Explicit first-admin operation; refuses once an active admin exists."""
    if not issuer or not subject.strip() or len(subject.strip()) > 255:
        raise IdentityValidationError("OIDC issuer and subject are required")
    organization = db.scalar(select(Organization).where(Organization.tenant_id == tenant.id))
    now = _now()
    if organization is None:
        organization = Organization(tenant_id=tenant.id, name=tenant.name, created_at=now, updated_at=now)
        db.add(organization)
        db.flush()
    active_admins = db.scalar(select(func.count()).select_from(OrganizationMembership).where(
        OrganizationMembership.organization_id == organization.id,
        OrganizationMembership.role == "ADMIN", OrganizationMembership.disabled_at.is_(None),
    )) or 0
    if active_admins:
        raise IdentityValidationError("active administrator already exists")
    subject = subject.strip()
    user = db.scalar(select(HumanUser).where(
        HumanUser.external_issuer == issuer, HumanUser.external_subject == subject,
    ))
    if user is None:
        user = HumanUser(external_issuer=issuer, external_subject=subject,
                         display_name=(display_name or subject)[:255],
                         email=email[:320] if email else None, created_at=now, updated_at=now)
        db.add(user)
        db.flush()
    membership = db.scalar(select(OrganizationMembership).where(
        OrganizationMembership.organization_id == organization.id,
        OrganizationMembership.user_id == user.id,
    ))
    if membership is None:
        membership = OrganizationMembership(organization_id=organization.id, user_id=user.id,
                                            role="ADMIN", created_at=now, updated_at=now)
        db.add(membership)
        db.flush()
    else:
        membership.role = "ADMIN"
        membership.disabled_at = None
        membership.updated_at = now
    db.add(IdentityAuditEvent(
        tenant_id=tenant.id, organization_id=organization.id,
        actor_type="SYSTEM", actor_id="operator-cli", event_type="bootstrap_admin_created",
        target_user_id=user.id, target_membership_id=membership.id,
        metadata_json={"role": "ADMIN"}, created_at=now,
    ))
    db.commit()
    logger.info("bootstrap_admin_created organization_id=%s user_id=%s membership_id=%s",
                organization.id, user.id, membership.id)
    return membership


def list_machine_api_keys(db: Session, principal: Principal, limit: int = 100) -> list[ApiKey]:
    if principal.principal_type != "HUMAN_SESSION" or not principal.allows("keys:manage") or principal.tenant_id is None:
        raise PermissionError("API key management denied")
    return list(db.scalars(select(ApiKey).where(ApiKey.tenant_id == principal.tenant_id)
                           .order_by(ApiKey.created_at.desc()).limit(min(max(limit, 1), 100))))


def create_machine_api_key(db: Session, principal: Principal, name: str, scopes: list[str],
                           pepper: str) -> tuple[ApiKey, str]:
    if principal.principal_type != "HUMAN_SESSION" or not principal.allows("keys:manage") or principal.tenant_id is None:
        raise PermissionError("API key management denied")
    normalized = {scope.strip() for scope in scopes if scope.strip()}
    if not normalized or "dashboard:access" in normalized or not normalized <= SCOPES:
        raise IdentityValidationError("invalid machine API key scopes")
    tenant = db.get(__import__("agentguard_server.models", fromlist=["Tenant"]).Tenant, principal.tenant_id)
    if tenant is None:
        raise IdentityValidationError("tenant unavailable")
    api_key, plaintext = create_api_key(db, tenant, normalized, name[:255], pepper)
    _audit(db, principal, "api_key_created_by_human", metadata={
        "public_id": api_key.public_id, "scopes": sorted(normalized),
    })
    db.commit()
    return api_key, plaintext


def revoke_machine_api_key(db: Session, principal: Principal, public_id: str) -> bool:
    if principal.principal_type != "HUMAN_SESSION" or not principal.allows("keys:manage") or principal.tenant_id is None:
        raise PermissionError("API key management denied")
    api_key = db.scalar(select(ApiKey).where(
        ApiKey.tenant_id == principal.tenant_id, ApiKey.public_id == public_id,
    ))
    if api_key is None:
        return False
    if api_key.revoked_at is None:
        api_key.revoked_at = _now()
        _audit(db, principal, "api_key_revoked_by_human", metadata={"public_id": api_key.public_id})
        db.commit()
    return True


def record_human_event(db: Session, principal: Principal, event_type: str) -> None:
    if principal.principal_type != "HUMAN_SESSION":
        return
    _audit(db, principal, event_type)
    db.commit()
