from __future__ import annotations

from datetime import datetime, timezone
import hmac
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agentguard_server.models import EventLog, Span, Tenant, Trace
from agentguard_server.schemas.events import Event
from agentguard_server.services.auth import get_or_create_local_tenant
from agentguard_server.services.integrity import append_integrity_record, canonicalize_evidence, evidence_digest
from agentguard_server.services.sanitize import sanitize


TRACE_FIELDS = {
    "workflow_name", "group_id", "provider", "started_at", "ended_at",
    "status", "schema_version",
}
SPAN_FIELDS = {
    "parent_span_id", "span_type", "name", "started_at", "ended_at",
    "duration_ms", "status", "error_type", "error_message", "schema_version",
}


class IdempotencyConflict(ValueError):
    """An event key was reused for different evidence."""


def _tenant_id(db: Session, tenant_id: uuid.UUID | str | None) -> uuid.UUID:
    if tenant_id is None:
        return get_or_create_local_tenant(db).id
    return tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(str(tenant_id))


def _timestamp(value: object, fallback: datetime | None) -> datetime | None:
    if value is None:
        return fallback
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return fallback


def _apply_values(target: object, data: dict, fields: set[str], occurred_at: datetime | None) -> None:
    for field in fields:
        if field not in data:
            continue
        value = data[field]
        if field in {"started_at", "ended_at"}:
            value = _timestamp(value, occurred_at)
        setattr(target, field, value)


def _ensure_trace(db: Session, tenant_id: uuid.UUID, trace_id: str, occurred_at: datetime | None) -> Trace:
    trace = db.scalar(select(Trace).where(Trace.tenant_id == tenant_id, Trace.trace_id == trace_id))
    if trace is not None:
        return trace
    trace = Trace(
        tenant_id=tenant_id,
        trace_id=trace_id,
        status="running",
        metadata_json={},
        started_at=occurred_at,
    )
    db.add(trace)
    db.flush()
    return trace


def ingest_event(db: Session, event: Event, tenant_id: uuid.UUID | str | None = None, *, capture_content: bool = False) -> bool:
    tenant = _tenant_id(db, tenant_id)
    data = sanitize(dict(event.data), capture_content=capture_content)
    canonical_data = dict(data)
    if event.occurred_at is not None:
        canonical_data["__agentguard_occurred_at"] = event.occurred_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    canonical = canonicalize_evidence(event_type=event.event_type, event_id=event.event_id,
                                      schema_version=event.schema_version, data=canonical_data)
    digest = evidence_digest(canonical)
    if event.event_type.startswith("trace."):
        trace_id = str(data.get("trace_id") or event.event_id)
    else:
        trace_id = str(data.get("trace_id") or "unknown")
    existing = db.scalar(select(EventLog).where(
        EventLog.tenant_id == tenant,
        EventLog.event_type == event.event_type,
        EventLog.event_id == event.event_id,
    ))
    if existing is not None:
        if existing.event_digest and not hmac.compare_digest(existing.event_digest, digest):
            raise IdempotencyConflict("event idempotency key already contains different evidence")
        return False

    db.add(EventLog(
        tenant_id=tenant,
        event_id=event.event_id,
        event_type=event.event_type,
        event_key=f"{event.event_type}:{event.event_id}",
        trace_id=None if trace_id == "unknown" else trace_id,
        payload_json={"data": canonical_data, "schema_version": event.schema_version},
        event_digest=digest,
    ))
    db.flush()

    if event.event_type.startswith("trace."):
        trace = _ensure_trace(db, tenant, trace_id, event.occurred_at)
        _apply_values(trace, data, TRACE_FIELDS, event.occurred_at)
        if event.event_type == "trace.started" and trace.started_at is None:
            trace.started_at = event.occurred_at
        if event.event_type == "trace.ended" and trace.ended_at is None:
            trace.ended_at = event.occurred_at
        if "metadata" in data and isinstance(data["metadata"], dict):
            trace.metadata_json = data["metadata"]
    else:
        span_id = str(data.get("span_id") or event.event_id)
        _ensure_trace(db, tenant, trace_id, event.occurred_at)
        span = db.scalar(select(Span).where(Span.tenant_id == tenant, Span.span_id == span_id))
        if span is None:
            span = Span(tenant_id=tenant, trace_id=trace_id, span_id=span_id, started_at=event.occurred_at)
            db.add(span)
            db.flush()
        elif span.trace_id != trace_id:
            raise ValueError("span cannot move between traces")
        _apply_values(span, data, SPAN_FIELDS, event.occurred_at)
        if "attributes" in data and isinstance(data["attributes"], dict):
            span.attributes = data["attributes"]
        parent_id = span.parent_span_id
        if parent_id:
            parent = db.scalar(select(Span).where(Span.tenant_id == tenant, Span.span_id == parent_id))
            if parent is not None and parent.trace_id != trace_id:
                raise ValueError("parent span belongs to another trace")
    if trace_id != "unknown":
        append_integrity_record(db, tenant_id=tenant, trace_id=trace_id, event_type=event.event_type,
                                event_id=event.event_id, event_digest_value=digest)
    return True


def ingest_events(db: Session, events: list[Event], tenant_id: uuid.UUID | str | None = None, *, capture_content: bool = False) -> tuple[int, int]:
    tenant = _tenant_id(db, tenant_id)
    accepted = 0
    duplicates = 0
    try:
        for event in events:
            if ingest_event(db, event, tenant, capture_content=capture_content):
                accepted += 1
            else:
                duplicates += 1
        db.commit()
    except IntegrityError:
        db.rollback()
        # A concurrent writer may have won the idempotency race. Re-read the
        # event log so callers still receive a safe duplicate result.
        accepted = 0
        duplicates = 0
        for event in events:
            if db.scalar(select(EventLog).where(
                EventLog.tenant_id == tenant,
                EventLog.event_type == event.event_type,
                EventLog.event_id == event.event_id,
            )):
                duplicates += 1
        if duplicates != len(events):
            raise
    return accepted, duplicates
