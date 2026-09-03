"""Opaque operator dashboard sessions and browser CSRF boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentguard_server.config import Settings, get_settings
from agentguard_server.models import ApiKey, DashboardSession, HumanUser, Organization, OrganizationMembership
from agentguard_server.services.auth import AuthContext, authenticate
from agentguard_server.services.authorization import Principal, principal_from_api_key, role_permissions
from agentguard_server.services.rate_limit import RateLimitStorageError, rate_limiter

SESSION_COOKIE = "agentguard_session"
CSRF_FIELD = "csrf_token"
_LOGIN_LIMIT_KEY = uuid.UUID(int=0)


@dataclass(frozen=True)
class DashboardLogin:
    context: Principal
    session: DashboardSession
    session_token: str
    csrf_token: str


@dataclass(frozen=True)
class DashboardIdentity:
    context: Principal
    session: DashboardSession


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def csrf_token_for_session(session: DashboardSession) -> str:
    """Derive a request token from the stored session hash; no plaintext is persisted."""
    return hmac.new(session.session_token_hash.encode("ascii"), b"agentguard-dashboard-csrf-v1", hashlib.sha256).hexdigest()


def allow_login(client_key: str = "unknown", flow: str = "login", settings: Settings | None = None,
                db: Session | None = None) -> bool:
    settings = settings or get_settings()
    safe_flow = flow if flow in {"api-key", "oidc-init", "oidc-callback"} else "login"
    client_digest = hashlib.sha256(client_key[:256].encode("utf-8", "replace")).hexdigest()[:32]
    operation = f"dashboard-login:{safe_flow}"
    if db is None:
        client_id = uuid.UUID(client_digest)
        per_client = rate_limiter.allow(
            client_id, operation, settings.dashboard_login_rate_limit,
            settings.dashboard_login_rate_window_seconds,
        )[0]
        if not per_client:
            return False
        global_limit = min(100000, settings.dashboard_login_rate_limit * 20)
        return rate_limiter.allow(
            _LOGIN_LIMIT_KEY, f"dashboard-login-global:{safe_flow}", global_limit,
            settings.dashboard_login_rate_window_seconds,
        )[0]
    try:
        per_client = rate_limiter.allow_shared(
            db, None, operation, settings.dashboard_login_rate_limit,
            settings.dashboard_login_rate_window_seconds, bucket_type="dashboard-client",
            subject=f"client:{client_digest}",
        )[0]
        if not per_client:
            return False
        global_limit = min(100000, settings.dashboard_login_rate_limit * 20)
        return rate_limiter.allow_shared(
            db, None, f"dashboard-login-global:{safe_flow}", global_limit,
            settings.dashboard_login_rate_window_seconds, bucket_type="dashboard-global",
            subject="global",
        )[0]
    except RateLimitStorageError:
        return False

def create_dashboard_session(db: Session, presented_key: str, pepper: str, settings: Settings | None = None) -> DashboardLogin | None:
    settings = settings or get_settings()
    context = authenticate(db, presented_key, pepper)
    if context is None or "dashboard:access" not in context.scopes:
        return None
    now = _now()
    active = db.scalar(select(func.count()).select_from(DashboardSession).where(
        DashboardSession.api_key_id == context.api_key_id,
        DashboardSession.revoked_at.is_(None), DashboardSession.expires_at > now,
    )) or 0
    if active >= settings.dashboard_max_sessions_per_api_key:
        return None
    session_token = secrets.token_urlsafe(32)
    csrf_token = csrf_token_for_session(DashboardSession(session_token_hash=hash_token(session_token)))
    session = DashboardSession(
        tenant_id=context.tenant_id, api_key_id=context.api_key_id,
        session_token_hash=hash_token(session_token), csrf_token_hash=hash_token(csrf_token),
        created_at=now, expires_at=now + timedelta(seconds=settings.dashboard_session_lifetime_seconds),
        last_seen_at=now,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return DashboardLogin(principal_from_api_key(context), session, session_token, csrf_token)


def create_human_dashboard_session(db: Session, user: HumanUser, membership: OrganizationMembership,
                                   settings: Settings | None = None) -> DashboardLogin | None:
    settings = settings or get_settings()
    organization = db.get(Organization, membership.organization_id)
    permissions = role_permissions(membership.role)
    if user.disabled_at is not None or membership.disabled_at is not None or organization is None or not permissions:
        return None
    now = _now()
    active = db.scalar(select(func.count()).select_from(DashboardSession).where(
        DashboardSession.human_user_id == user.id,
        DashboardSession.revoked_at.is_(None), DashboardSession.expires_at > now,
    )) or 0
    if active >= settings.dashboard_max_sessions_per_human:
        return None
    session_token = secrets.token_urlsafe(32)
    csrf_token = csrf_token_for_session(DashboardSession(session_token_hash=hash_token(session_token)))
    session = DashboardSession(
        tenant_id=organization.tenant_id, api_key_id=None, human_user_id=user.id,
        organization_id=organization.id, session_token_hash=hash_token(session_token),
        csrf_token_hash=hash_token(csrf_token), created_at=now,
        expires_at=now + timedelta(seconds=settings.dashboard_session_lifetime_seconds), last_seen_at=now,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    principal = Principal("HUMAN_SESSION", user.id, organization.tenant_id, permissions,
                          organization_id=organization.id, membership_id=membership.id,
                          role=membership.role, display_name=user.display_name,
                          organization_name=organization.name)
    return DashboardLogin(principal, session, session_token, csrf_token)


def create_pending_human_dashboard_session(db: Session, user: HumanUser,
                                           settings: Settings | None = None) -> DashboardLogin | None:
    settings = settings or get_settings()
    if user.disabled_at is not None:
        return None
    now = _now()
    active = db.scalar(select(func.count()).select_from(DashboardSession).where(
        DashboardSession.human_user_id == user.id,
        DashboardSession.revoked_at.is_(None), DashboardSession.expires_at > now,
    )) or 0
    if active >= settings.dashboard_max_sessions_per_human:
        return None
    session_token = secrets.token_urlsafe(32)
    csrf_token = csrf_token_for_session(DashboardSession(session_token_hash=hash_token(session_token)))
    session = DashboardSession(
        tenant_id=None, api_key_id=None, human_user_id=user.id, organization_id=None,
        session_token_hash=hash_token(session_token), csrf_token_hash=hash_token(csrf_token),
        created_at=now, expires_at=now + timedelta(seconds=settings.dashboard_session_lifetime_seconds),
        last_seen_at=now,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    principal = Principal("HUMAN_SESSION", user.id, None, frozenset(), display_name=user.display_name)
    return DashboardLogin(principal, session, session_token, csrf_token)


def load_dashboard_session(db: Session, session_token: str | None, settings: Settings | None = None) -> DashboardIdentity | None:
    if not session_token or len(session_token) > 512:
        return None
    settings = settings or get_settings()
    row = db.scalar(select(DashboardSession).where(DashboardSession.session_token_hash == hash_token(session_token)))
    if row is None:
        return None
    now = _now()
    expired = _utc(row.expires_at) <= now
    idle = settings.dashboard_idle_timeout_seconds > 0 and _utc(row.last_seen_at) + timedelta(seconds=settings.dashboard_idle_timeout_seconds) <= now
    principal = None
    if row.api_key_id is not None and row.human_user_id is None:
        api_key = db.get(ApiKey, row.api_key_id)
        invalid = api_key is None or api_key.revoked_at is not None or (api_key.expires_at is not None and _utc(api_key.expires_at) <= now)
        if not invalid and api_key.tenant_id == row.tenant_id and api_key.tenant.disabled_at is None:
            principal = principal_from_api_key(AuthContext(
                api_key.tenant_id, api_key.id, frozenset(api_key.scopes or []), api_key.public_id))
    elif row.human_user_id is not None and row.api_key_id is None and row.organization_id is not None:
        user = db.get(HumanUser, row.human_user_id)
        organization = db.get(Organization, row.organization_id)
        membership = db.scalar(select(OrganizationMembership).where(
            OrganizationMembership.organization_id == row.organization_id,
            OrganizationMembership.user_id == row.human_user_id,
            OrganizationMembership.disabled_at.is_(None),
        ))
        permissions = role_permissions(membership.role if membership else None)
        if (user is not None and user.disabled_at is None and organization is not None and membership is not None
                and organization.tenant_id == row.tenant_id and permissions):
            principal = Principal("HUMAN_SESSION", user.id, organization.tenant_id, permissions,
                                  organization_id=organization.id, membership_id=membership.id,
                                  role=membership.role, display_name=user.display_name,
                                  organization_name=organization.name)
    elif row.human_user_id is not None and row.api_key_id is None and row.organization_id is None and row.tenant_id is None:
        user = db.get(HumanUser, row.human_user_id)
        active_memberships = db.scalar(select(func.count()).select_from(OrganizationMembership).where(
            OrganizationMembership.user_id == row.human_user_id,
            OrganizationMembership.disabled_at.is_(None),
        )) or 0
        if user is not None and user.disabled_at is None and active_memberships > 0:
            principal = Principal("HUMAN_SESSION", user.id, None, frozenset(), display_name=user.display_name)
    if row.revoked_at is not None or expired or idle or principal is None:
        if row.revoked_at is None:
            row.revoked_at = now
            db.commit()
        return None
    row.last_seen_at = now
    db.commit()
    return DashboardIdentity(principal, row)


def revoke_dashboard_session(db: Session, session: DashboardSession) -> None:
    if session.revoked_at is None:
        session.revoked_at = _now()
        db.commit()


def validate_csrf(session: DashboardSession, token: str | None) -> bool:
    if not token or len(token) > 512:
        return False
    return hmac.compare_digest(session.csrf_token_hash, hash_token(token)) and hmac.compare_digest(token, csrf_token_for_session(session))
