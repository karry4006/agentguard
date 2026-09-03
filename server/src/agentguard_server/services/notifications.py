"""Secure, bounded notification policy and webhook delivery primitives."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import re
import secrets
import socket
import ssl
import threading
from typing import Any, Callable
from urllib.parse import urlsplit

from sqlalchemy import func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from agentguard_server.config import get_settings
from agentguard_server.services.rate_limit import database_now
from agentguard_server.models import (AlertPolicy, Incident, NotificationDelivery,
    NotificationCircuitState, NotificationDestination, NotificationEvent)


class NotificationSecurityError(ValueError):
    """The destination or payload violates a server-side security policy."""


@dataclass(frozen=True)
class WebhookTarget:
    scheme: str
    host: str
    port: int
    path: str
    resolved_addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeliveryClassification:
    retryable: bool
    failure_category: str | None = None
    retry_after_seconds: int | None = None


_FORBIDDEN_HOSTS = {"localhost", "postgres", "postgresql", "agentguard-server", "agentguard-migrate"}
_FORBIDDEN_SCHEMES = {"file", "ftp", "gopher", "data", "javascript", "unix"}
logger = logging.getLogger("agentguard.coordination")


def _is_private_or_internal(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


def _resolve_all(host: str, port: int, resolver: Callable[..., Any] | None = None,
                 *, reject_private: bool = True) -> tuple[str, ...]:
    resolver = resolver or socket.getaddrinfo
    try:
        rows = resolver(host, port, type=socket.SOCK_STREAM)
    except (OSError, ValueError) as exc:
        raise NotificationSecurityError("webhook host cannot be resolved") from exc
    addresses: list[str] = []
    for row in rows:
        sockaddr = row[4]
        address = str(sockaddr[0])
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            raise NotificationSecurityError("webhook resolver returned an invalid address") from exc
        if reject_private and _is_private_or_internal(address):
            raise NotificationSecurityError("webhook destination resolves to a private or internal address")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise NotificationSecurityError("webhook host has no usable address")
    return tuple(addresses)


def validate_webhook_url(value: str, *, allow_private_test: bool = False, environment: str = "development",
                         resolver: Callable[..., Any] | None = None, allowed_hosts: set[str] | None = None) -> WebhookTarget:
    if not isinstance(value, str) or len(value) > 2048:
        raise NotificationSecurityError("invalid webhook URL")
    parsed = urlsplit(value.strip())
    scheme = parsed.scheme.lower()
    if scheme in _FORBIDDEN_SCHEMES or scheme not in {"https", "http"}:
        raise NotificationSecurityError("webhook must use HTTPS")
    if scheme != "https" and not (allow_private_test and environment.lower() == "test"):
        raise NotificationSecurityError("webhook must use HTTPS")
    if parsed.username or parsed.password or not parsed.hostname or parsed.query or parsed.fragment:
        raise NotificationSecurityError("webhook URL contains forbidden authority or query data")
    host = parsed.hostname.rstrip(".").lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}[a-z0-9]$|[a-z0-9]", host):
        raise NotificationSecurityError("invalid webhook host")
    test_private = allow_private_test and environment.lower() == "test"
    if (host in _FORBIDDEN_HOSTS or host.endswith((".local", ".internal", ".docker"))) and not test_private:
        raise NotificationSecurityError("webhook host is internal")
    if allowed_hosts and host not in {item.strip().lower().rstrip(".") for item in allowed_hosts}:
        raise NotificationSecurityError("webhook host is not allowlisted")
    try:
        direct_ip = ipaddress.ip_address(host)
    except ValueError:
        direct_ip = None
    if direct_ip is not None and _is_private_or_internal(str(direct_ip)) and not (allow_private_test and environment.lower() == "test"):
        raise NotificationSecurityError("webhook destination is private or internal")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise NotificationSecurityError("invalid webhook port") from exc
    if not 1 <= port <= 65535:
        raise NotificationSecurityError("invalid webhook port")
    path = parsed.path or "/"
    if not path.startswith("/") or len(path) > 1024:
        raise NotificationSecurityError("invalid webhook path")
    addresses = ()
    if direct_ip is None or not (allow_private_test and environment.lower() == "test"):
        addresses = _resolve_all(host, port, resolver, reject_private=not test_private)
    elif direct_ip is not None:
        addresses = (str(direct_ip),)
    return WebhookTarget(scheme, host, port, path, addresses)


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


def build_notification_payload(incident: Any, event_type: str, *, trend: str = "STABLE") -> dict[str, Any]:
    """Build the fixed webhook-v1 schema from trusted incident projection fields."""
    title = re.sub(r"<[^>]{0,64}>", "", str(getattr(incident, "title", "incident")))[:255]
    return {
        "schema_version": "webhook-v1", "event": str(event_type),
        "incident_id": str(incident.id), "severity": str(incident.severity),
        "status": str(incident.status), "title": title,
        "primary_category": str(incident.primary_category)[:64],
        "occurrence_count": min(max(int(incident.occurrence_count), 0), 1_000_000),
        "first_seen": _iso(incident.first_seen_at), "last_seen": _iso(incident.last_seen_at),
        "trend": str(trend),
    }


def serialize_notification_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_webhook_payload(payload: bytes, secret: str, *, timestamp: int | None = None) -> str:
    if not secret or len(secret.encode("utf-8")) < 32:
        raise NotificationSecurityError("webhook signing secret is unavailable")
    timestamp = int(timestamp if timestamp is not None else datetime.now(timezone.utc).timestamp())
    digest = hmac.new(secret.encode("utf-8"), str(timestamp).encode() + b"." + payload, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def classify_delivery_response(status_code: int, *, retry_after: str | None = None,
                               transport_error: str | None = None) -> DeliveryClassification:
    if transport_error:
        return DeliveryClassification(True, "TRANSPORT")
    if 200 <= status_code < 300:
        return DeliveryClassification(False)
    if status_code == 429:
        try:
            delay = min(300, max(0, int(float(retry_after or "0"))))
        except ValueError:
            delay = 0
        return DeliveryClassification(True, "RATE_LIMIT", delay)
    if status_code in {408, 425} or 500 <= status_code <= 599:
        return DeliveryClassification(True, "TRANSIENT")
    if status_code in {401, 403}:
        return DeliveryClassification(False, "AUTHENTICATION")
    if 400 <= status_code <= 499:
        return DeliveryClassification(False, "DESTINATION")
    return DeliveryClassification(False, "UNKNOWN")


def stable_delivery_key(tenant_id: Any, incident_id: Any, event_type: str, policy_id: Any,
                       destination_id: Any, lifecycle_version: int) -> str:
    material = ":".join(map(str, (tenant_id, incident_id, event_type, policy_id, destination_id, lifecycle_version)))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

def _now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    return current.replace(tzinfo=timezone.utc) if current.tzinfo is None else current.astimezone(timezone.utc)


def create_destination(db: Session, tenant_id: Any, *, name: str, url: str,
                       signing_secret_reference: str | None = None, enabled: bool = True) -> NotificationDestination:
    settings = get_settings()
    target = validate_webhook_url(url, allow_private_test=settings.allow_private_webhook_tests,
                                  environment=settings.environment,
                                  allowed_hosts={item.strip() for item in (settings.notification_allowed_webhook_hosts or "").split(",") if item.strip()} or None)
    count = db.scalar(select(func.count(NotificationDestination.id)).where(NotificationDestination.tenant_id == tenant_id)) or 0
    if count >= settings.notification_max_destinations:
        raise ValueError("notification destination limit reached")
    now = _now()
    row = NotificationDestination(tenant_id=tenant_id, name=name.strip(), destination_type="HTTPS_WEBHOOK",
                                  endpoint_scheme=target.scheme, endpoint_host=target.host, endpoint_port=target.port,
                                  endpoint_path=target.path, signing_secret_reference=signing_secret_reference,
                                  enabled=enabled, created_at=now, updated_at=now)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def create_policy(db: Session, tenant_id: Any, *, name: str, minimum_severity: str = "HIGH",
                  incident_status_filter: list[str] | None = None, failure_categories: list[str] | None = None,
                  event_types: list[str] | None = None, cooldown_seconds: int = 300,
                  enabled: bool = True) -> AlertPolicy:
    settings = get_settings()
    if minimum_severity not in _SEVERITY_RANK or cooldown_seconds < 0:
        raise ValueError("invalid notification policy")
    count = db.scalar(select(func.count(AlertPolicy.id)).where(AlertPolicy.tenant_id == tenant_id)) or 0
    if count >= settings.notification_max_policies:
        raise ValueError("notification policy limit reached")
    now = _now()
    row = AlertPolicy(tenant_id=tenant_id, name=name.strip(), minimum_severity=minimum_severity,
                      incident_status_filter=[str(x) for x in (incident_status_filter or ["OPEN"])],
                      failure_categories=[str(x).upper()[:64] for x in (failure_categories or [])],
                      event_types=[str(x) for x in (event_types or ["INCIDENT_CREATED", "INCIDENT_REOPENED", "SEVERITY_INCREASED", "INCIDENT_RESOLVED"])],
                      cooldown_seconds=cooldown_seconds, enabled=enabled, policy_version=1,
                      created_at=now, updated_at=now)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def create_notification_intents(db: Session, tenant_id: Any, incident: Incident, event_type: str,
                                *, lifecycle_version: int = 1, now: datetime | None = None) -> list[NotificationDelivery]:
    """Persist bounded notification intent before any external request is attempted."""
    settings = get_settings()
    now = _now(now)
    if event_type not in {"INCIDENT_CREATED", "INCIDENT_REOPENED", "SEVERITY_INCREASED", "INCIDENT_RESOLVED"}:
        return []
    policies = list(db.scalars(select(AlertPolicy).where(AlertPolicy.tenant_id == tenant_id, AlertPolicy.enabled).limit(settings.notification_max_policies)))
    destinations = list(db.scalars(select(NotificationDestination).where(NotificationDestination.tenant_id == tenant_id, NotificationDestination.enabled).limit(settings.notification_max_destinations)))
    pending = db.scalar(select(func.count(NotificationDelivery.id)).where(NotificationDelivery.tenant_id == tenant_id,
        NotificationDelivery.status.in_(["PENDING", "RETRYING"]))) or 0
    created: list[NotificationDelivery] = []
    for policy in policies:
        if event_type not in (policy.event_types or []) or incident.status not in (policy.incident_status_filter or []):
            continue
        if _SEVERITY_RANK.get(incident.severity, 0) < _SEVERITY_RANK.get(policy.minimum_severity, 2):
            continue
        if policy.failure_categories and incident.primary_category not in policy.failure_categories:
            continue
        for destination in destinations:
            if pending + len(created) >= settings.notification_max_pending:
                return created
            recent = db.scalar(select(NotificationDelivery.id).where(
                NotificationDelivery.tenant_id == tenant_id, NotificationDelivery.incident_id == incident.id,
                NotificationDelivery.policy_id == policy.id, NotificationDelivery.destination_id == destination.id,
                NotificationDelivery.created_at >= now - timedelta(seconds=policy.cooldown_seconds)).limit(1))
            if recent is not None:
                continue
            payload = build_notification_payload(incident, event_type)
            payload_bytes = serialize_notification_payload(payload)
            key = stable_delivery_key(tenant_id, incident.id, event_type, policy.id, destination.id, lifecycle_version)
            values = dict(tenant_id=tenant_id, incident_id=incident.id, destination_id=destination.id, policy_id=policy.id,
                          event_type=event_type, lifecycle_version=lifecycle_version, idempotency_key=key, status="PENDING",
                          attempt_count=0, payload=payload, payload_digest=hashlib.sha256(payload_bytes).hexdigest(),
                          created_at=now)
            if db.get_bind().dialect.name == "postgresql":
                db.execute(pg_insert(NotificationDelivery).values(**values).on_conflict_do_nothing(
                    index_elements=["tenant_id", "idempotency_key"]))
            else:
                if db.scalar(select(NotificationDelivery.id).where(NotificationDelivery.tenant_id == tenant_id,
                                                                     NotificationDelivery.idempotency_key == key)) is not None:
                    continue
                db.add(NotificationDelivery(**values))
            db.flush()
            row = db.scalar(select(NotificationDelivery).where(NotificationDelivery.tenant_id == tenant_id,
                                                               NotificationDelivery.idempotency_key == key))
            if row is not None:
                created.append(row)
    db.commit()
    return created


def _default_sender(target: WebhookTarget, payload: bytes, headers: dict[str, str], *, timeout: float) -> tuple[int, str | None]:
    """POST to the already-resolved IP; no proxy, redirects, or second DNS lookup."""
    sock = socket.create_connection((target.resolved_addresses[0], target.port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        if target.scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=target.host)
        request = http.client.HTTPConnection(target.host, target.port, timeout=timeout)
        request.sock = sock
        request.putrequest("POST", target.path, skip_host=True, skip_accept_encoding=True)
        request.putheader("Host", target.host if target.port in {80, 443} else f"{target.host}:{target.port}")
        request.putheader("Content-Type", "application/json")
        request.putheader("Content-Length", str(len(payload)))
        for key, value in headers.items():
            request.putheader(key, value)
        request.endheaders(payload)
        response = request.getresponse()
        response.read(64 * 1024)
        return response.status, response.getheader("Retry-After")
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _retry_delay(delivery: NotificationDelivery, classification: DeliveryClassification) -> int:
    settings = get_settings()
    if classification.retry_after_seconds is not None:
        return min(settings.notification_retry_max_delay_seconds, classification.retry_after_seconds)
    base = settings.notification_retry_base_seconds * (2 ** max(0, delivery.attempt_count - 1))
    jitter = int(hashlib.sha256(str(delivery.id).encode()).hexdigest()[:2], 16) % max(1, settings.notification_retry_base_seconds)
    return min(settings.notification_retry_max_delay_seconds, base + jitter)


@dataclass(frozen=True)
class DeliveryClaim:
    delivery_id: Any
    instance_id: str
    claim_token: str


def _coordination_now(db: Session, supplied: datetime | None = None) -> datetime:
    return _now(supplied) if supplied is not None else database_now(db)


def _claim_delivery(db: Session, delivery_id: Any, *, now: datetime | None = None,
                    instance_id: str | None = None) -> DeliveryClaim | None:
    settings = get_settings()
    owner = (instance_id or settings.instance_id)[:128]
    current = _coordination_now(db, now)
    token = secrets.token_hex(32)
    statement = update(NotificationDelivery).where(
        NotificationDelivery.id == delivery_id,
        NotificationDelivery.status.in_(["PENDING", "RETRYING"]),
        or_(NotificationDelivery.next_retry_at.is_(None),
            NotificationDelivery.next_retry_at <= current),
        or_(NotificationDelivery.lease_expires_at.is_(None),
            NotificationDelivery.lease_expires_at <= current),
    ).values(
        claimed_by=owner,
        claim_token=token,
        claimed_at=current,
        lease_expires_at=current + timedelta(seconds=settings.notification_lease_seconds),
        claim_attempt=NotificationDelivery.claim_attempt + 1,
    ).returning(NotificationDelivery.id)
    result = db.execute(statement.execution_options(synchronize_session=False))
    claimed_id = result.scalar_one_or_none()
    if claimed_id is None:
        db.rollback()
        return None
    db.commit()
    # The conditional UPDATE intentionally bypasses ORM synchronization. Expire
    # pre-existing identity-map entries before reading the claimed row.
    db.expire_all()
    logger.info(
        "coordination_operation=notification_claim result=claimed instance_id=%s",
        owner,
    )
    return DeliveryClaim(claimed_id, owner, token)

def claim_delivery(db: Session, delivery_id: Any, *, now: datetime | None = None,
                   instance_id: str | None = None) -> NotificationDelivery | None:
    """Claim one delivery atomically and return it for a worker."""
    claim = _claim_delivery(db, delivery_id, now=now, instance_id=instance_id)
    if claim is None:
        return None
    return db.get(NotificationDelivery, claim.delivery_id)


def claim_pending_deliveries(db: Session, *, limit: int = 100, now: datetime | None = None,
                             instance_id: str | None = None) -> list[NotificationDelivery]:
    """Claim a bounded batch; each row is independently protected by a DB lock."""
    current = _coordination_now(db, now)
    bounded = min(max(1, int(limit)), 1000)
    ids = list(db.scalars(select(NotificationDelivery.id).where(
        NotificationDelivery.status.in_(["PENDING", "RETRYING"]),
        (NotificationDelivery.next_retry_at.is_(None) | (NotificationDelivery.next_retry_at <= current)),
        (NotificationDelivery.lease_expires_at.is_(None) | (NotificationDelivery.lease_expires_at <= current)),
    ).order_by(NotificationDelivery.created_at).limit(bounded)))
    claimed: list[NotificationDelivery] = []
    for delivery_id in ids:
        row = claim_delivery(db, delivery_id, now=current, instance_id=instance_id)
        if row is not None:
            claimed.append(row)
    return claimed


def _ensure_circuit_state(db: Session, destination: NotificationDestination,
                          current: datetime) -> NotificationCircuitState:
    values = {
        "destination_id": destination.id,
        "tenant_id": destination.tenant_id,
        "state": "CLOSED",
        "failure_count": 0,
        "updated_at": current,
    }
    dialect = db.get_bind().dialect.name
    insert = pg_insert if dialect == "postgresql" else sqlite_insert
    db.execute(insert(NotificationCircuitState).values(**values).on_conflict_do_nothing(
        index_elements=["destination_id"]
    ))
    db.flush()
    state = db.scalar(select(NotificationCircuitState).where(
        NotificationCircuitState.destination_id == destination.id
    ).with_for_update())
    if state is None:
        raise RuntimeError("notification circuit state unavailable")
    return state


def _before_notification_send(db: Session, destination: NotificationDestination,
                              current: datetime, claim_token: str) -> tuple[bool, datetime | None]:
    settings = get_settings()
    state = _ensure_circuit_state(db, destination, current)
    if state.state == "OPEN":
        if state.next_probe_at is not None and _now(state.next_probe_at) > current:
            retry_at = _now(state.next_probe_at)
            db.commit()
            return False, retry_at
        state.state = "HALF_OPEN"
        state.half_open_probe_owner = claim_token
        state.half_open_lease_expires_at = current + timedelta(
            seconds=settings.notification_circuit_probe_lease_seconds
        )
        state.updated_at = current
    elif state.state == "HALF_OPEN":
        if (state.half_open_probe_owner != claim_token
                and state.half_open_lease_expires_at is not None
                and _now(state.half_open_lease_expires_at) > current):
            retry_at = state.half_open_lease_expires_at
            db.commit()
            return False, retry_at
        if state.half_open_probe_owner != claim_token:
            state.half_open_probe_owner = claim_token
            state.half_open_lease_expires_at = current + timedelta(
                seconds=settings.notification_circuit_probe_lease_seconds
            )
            state.updated_at = current
    db.commit()
    return True, None


def _record_circuit_result(db: Session, destination: NotificationDestination,
                           current: datetime, claim_token: str, success: bool) -> None:
    settings = get_settings()
    state = _ensure_circuit_state(db, destination, current)
    if success:
        state.state = "CLOSED"
        state.failure_count = 0
        state.opened_at = None
        state.next_probe_at = None
        state.half_open_probe_owner = None
        state.half_open_lease_expires_at = None
    else:
        state.failure_count = int(state.failure_count or 0) + 1
        if state.state == "HALF_OPEN" or state.failure_count >= settings.notification_circuit_failure_threshold:
            state.state = "OPEN"
            state.opened_at = current
            state.next_probe_at = current + timedelta(seconds=settings.notification_circuit_open_seconds)
            state.half_open_probe_owner = None
            state.half_open_lease_expires_at = None
        else:
            state.state = "CLOSED"
    state.updated_at = current


def _finish_delivery(db: Session, delivery_id: Any, claim_token: str, destination: NotificationDestination,
                     current: datetime, classification: DeliveryClassification) -> NotificationDelivery:
    settings = get_settings()
    delivery = db.scalar(select(NotificationDelivery).where(
        NotificationDelivery.id == delivery_id
    ).with_for_update())
    if delivery is None:
        db.rollback()
        raise LookupError("notification delivery not found")
    if delivery.claim_token != claim_token:
        db.rollback()
        return delivery
    delivery.attempt_count = int(delivery.attempt_count or 0) + 1
    delivery.last_attempt_at = current
    if not classification.retryable:
        if classification.failure_category is None:
            delivery.status, delivery.delivered_at = "DELIVERED", current
            delivery.failure_category = None
            event_type = "DELIVERED"
        else:
            delivery.status, delivery.failure_category = "FAILED", classification.failure_category
            event_type = "FAILED"
    elif delivery.attempt_count >= settings.notification_retry_max_attempts:
        delivery.status, delivery.failure_category, delivery.next_retry_at = "FAILED", classification.failure_category, None
        event_type = "FAILED"
    else:
        delay = _retry_delay(delivery, classification)
        delivery.status, delivery.failure_category, delivery.next_retry_at = (
            "RETRYING", classification.failure_category, current + timedelta(seconds=delay)
        )
        event_type = "RETRY_SCHEDULED"
    if classification.retryable:
        _record_circuit_result(db, destination, current, claim_token, False)
    else:
        _record_circuit_result(db, destination, current, claim_token, True)
    delivery.claimed_by = None
    delivery.claim_token = None
    delivery.claimed_at = None
    delivery.lease_expires_at = None
    db.add(NotificationEvent(
        tenant_id=delivery.tenant_id, delivery_id=delivery.id, event_type=event_type,
        metadata_json={"attempt": str(delivery.attempt_count), "category": delivery.failure_category or "none"},
        created_at=current,
    ))
    db.commit()
    db.refresh(delivery)
    return delivery


def dispatch_delivery(db: Session, delivery_id: Any, *, sender: Callable[..., tuple[int, str | None]] | None = None,
                      now: datetime | None = None) -> NotificationDelivery:
    """Claim one durable intent, perform at-least-once delivery, then finalize it."""
    settings = get_settings()
    current = _coordination_now(db, now)
    claim = _claim_delivery(db, delivery_id, now=current)
    if claim is None:
        row = db.get(NotificationDelivery, delivery_id)
        if row is None:
            raise LookupError("notification delivery not found")
        return row
    delivery = db.get(NotificationDelivery, claim.delivery_id)
    destination = db.get(NotificationDestination, delivery.destination_id) if delivery else None
    if delivery is None:
        raise LookupError("notification delivery not found")
    if destination is None or not destination.enabled:
        delivery.status = "FAILED"
        delivery.failure_category = "DESTINATION"
        delivery.claimed_by = None
        delivery.claim_token = None
        delivery.claimed_at = None
        delivery.lease_expires_at = None
        db.commit()
        db.refresh(delivery)
        return delivery
    target = validate_webhook_url(
        f"{destination.endpoint_scheme}://{destination.endpoint_host}:{destination.endpoint_port}{destination.endpoint_path}",
        allow_private_test=settings.allow_private_webhook_tests, environment=settings.environment,
        allowed_hosts={item.strip() for item in (settings.notification_allowed_webhook_hosts or "").split(",") if item.strip()} or None,
    )
    allowed, retry_at = _before_notification_send(db, destination, current, claim.claim_token)
    if not allowed:
        delivery = db.get(NotificationDelivery, delivery.id)
        delivery.status = "RETRYING"
        delivery.failure_category = "CIRCUIT_OPEN"
        delivery.next_retry_at = retry_at or current + timedelta(seconds=settings.notification_circuit_open_seconds)
        delivery.claimed_by = None
        delivery.claim_token = None
        delivery.claimed_at = None
        delivery.lease_expires_at = None
        db.commit()
        db.refresh(delivery)
        return delivery
    payload_bytes = serialize_notification_payload(delivery.payload)
    headers: dict[str, str] = {"User-Agent": "AgentGuard-V14", "X-AgentGuard-Delivery-Id": str(delivery.id)}
    if settings.notification_signing_secret:
        headers["X-AgentGuard-Timestamp"] = str(int(current.timestamp()))
        headers["X-AgentGuard-Signature"] = sign_webhook_payload(
            payload_bytes, settings.notification_signing_secret, timestamp=int(current.timestamp())
        )
    try:
        status_code, retry_after = (
            sender(target, payload_bytes, headers, timeout=settings.notification_total_timeout_seconds)
            if sender else _default_sender(target, payload_bytes, headers, timeout=settings.notification_total_timeout_seconds)
        )
        classification = classify_delivery_response(status_code, retry_after=retry_after)
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        classification = classify_delivery_response(0, transport_error=type(exc).__name__)
    return _finish_delivery(db, delivery.id, claim.claim_token, destination, current, classification)


def dispatch_pending_notifications(db: Session, *, limit: int = 100, now: datetime | None = None) -> list[NotificationDelivery]:
    claimed = claim_pending_deliveries(db, limit=limit, now=now)
    results: list[NotificationDelivery] = []
    for delivery in claimed:
        claim = DeliveryClaim(delivery.id, delivery.claimed_by or get_settings().instance_id,
                              delivery.claim_token or "")
        results.append(dispatch_delivery(db, delivery.id, now=now, _claim=claim))
    return results