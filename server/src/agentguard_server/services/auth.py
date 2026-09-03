from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import logging
import re
import secrets
from typing import Iterable
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentguard_server.models import ApiKey, Tenant

logger = logging.getLogger("agentguard.security")
SCOPES = frozenset({
    "ingest:write", "traces:read", "keys:manage", "replay:run", "analysis:run",
    "evaluations:read", "evaluations:run", "evaluations:manage", "incidents:read", "incidents:manage",
    "notifications:read", "notifications:manage", "dashboard:access", "integrity:read", "integrity:anchor",
      "archives:read", "retention:manage", "retention:hold", "ledger:compact", "integrity:compact",
})
_KEY_RE = re.compile(r"^agk_([0-9a-f]{16})_([A-Za-z0-9_-]{32,})$")


@dataclass(frozen=True)
class AuthContext:
    tenant_id: uuid.UUID
    api_key_id: uuid.UUID
    scopes: frozenset[str]
    public_id: str


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def digest_secret(secret: str, pepper: str) -> str:
    return hmac.new(pepper.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256).hexdigest()


def parse_key(value: str) -> tuple[str, str] | None:
    match = _KEY_RE.fullmatch(value)
    return match.groups() if match else None


def validate_scopes(scopes: Iterable[str]) -> frozenset[str]:
    normalized = frozenset(str(scope) for scope in scopes)
    unknown = normalized - SCOPES
    if unknown:
        raise ValueError(f"unknown scopes: {', '.join(sorted(unknown))}")
    return normalized


def create_tenant(db: Session, slug: str, name: str) -> Tenant:
    slug = slug.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,98}[a-z0-9]", slug):
        raise ValueError("slug must be 3-100 lowercase letters, digits, or hyphens")
    if db.scalar(select(Tenant).where(Tenant.slug == slug)):
        raise ValueError(f"tenant already exists: {slug}")
    tenant = Tenant(slug=slug, name=name.strip(), created_at=utc_now())
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    logger.info("tenant_created tenant_id=%s slug=%s", tenant.id, tenant.slug)
    return tenant


def get_or_create_local_tenant(db: Session) -> Tenant:
    tenant = db.scalar(select(Tenant).where(Tenant.slug == "local"))
    if tenant:
        return tenant
    tenant = Tenant(slug="local", name="Local legacy tenant", created_at=utc_now())
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


def create_api_key(db: Session, tenant: Tenant, scopes: Iterable[str], name: str, pepper: str, expires_at: datetime | None = None) -> tuple[ApiKey, str]:
    normalized_scopes = validate_scopes(scopes)
    public_id = secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    api_key = ApiKey(
        tenant_id=tenant.id,
        public_id=public_id,
        secret_digest=digest_secret(secret, pepper),
        scopes=sorted(normalized_scopes),
        created_at=utc_now(),
        expires_at=expires_at,
        name=name.strip(),
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    logger.info("api_key_created tenant_id=%s public_id=%s scopes=%s", tenant.id, public_id, ",".join(sorted(normalized_scopes)))
    return api_key, f"agk_{public_id}_{secret}"


def authenticate(db: Session, presented_key: str | None, pepper: str) -> AuthContext | None:
    parsed = parse_key(presented_key or "")
    if parsed is None:
        logger.warning("authentication_failed reason=malformed_key")
        return None
    public_id, secret = parsed
    api_key = db.scalar(select(ApiKey).where(ApiKey.public_id == public_id))
    if api_key is None:
        logger.warning("authentication_failed public_id=%s reason=unknown_key", public_id)
        return None
    now = utc_now()
    if api_key.revoked_at is not None:
        logger.warning("authentication_failed public_id=%s reason=revoked", public_id)
        return None
    if api_key.expires_at is not None and _utc(api_key.expires_at) <= now:
        logger.warning("authentication_failed public_id=%s reason=expired", public_id)
        return None
    if api_key.tenant.disabled_at is not None:
        logger.warning("authentication_failed public_id=%s reason=disabled_tenant", public_id)
        return None
    candidate = digest_secret(secret, pepper)
    if not hmac.compare_digest(candidate, api_key.secret_digest):
        logger.warning("authentication_failed public_id=%s reason=bad_secret", public_id)
        return None
    api_key.last_used_at = now
    db.commit()
    return AuthContext(api_key.tenant_id, api_key.id, frozenset(api_key.scopes or []), public_id)


def revoke_api_key(db: Session, public_id: str) -> bool:
    api_key = db.scalar(select(ApiKey).where(ApiKey.public_id == public_id))
    if api_key is None:
        return False
    api_key.revoked_at = utc_now()
    db.commit()
    logger.info("api_key_revoked tenant_id=%s public_id=%s", api_key.tenant_id, public_id)
    return True

