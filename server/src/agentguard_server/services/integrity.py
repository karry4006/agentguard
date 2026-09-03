"""Deterministic evidence canonicalization and cryptographic primitives."""

from __future__ import annotations

from datetime import date, datetime, timezone
import hashlib
import hmac
import json
import math
import unicodedata
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from agentguard_server.config import Settings, get_settings
from agentguard_server.models import ArchiveLifecycle, ArchiveRecord, EventLog, IntegrityChainHead, IntegrityRecord, Span, Trace


CANONICALIZATION_VERSION = "jcs-lite-v1"
TIMESTAMP_KEYS = {"occurred_at", "started_at", "ended_at", "created_at", "updated_at"}


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("evidence object keys must be strings")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise ValueError("evidence object keys collide after NFC normalization")
            if normalized_key in TIMESTAMP_KEYS and isinstance(item, str):
                try:
                    item = datetime.fromisoformat(item.replace("Z", "+00:00"))
                except ValueError:
                    pass
            normalized[normalized_key] = _normalize(item)
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("evidence timestamps must include a timezone")
        utc = value.astimezone(timezone.utc)
        return utc.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("evidence numbers must be finite")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise ValueError(f"unsupported evidence value type: {type(value).__name__}")


def canonicalize_evidence(*, event_type: str, event_id: str, schema_version: str, data: dict[str, Any]) -> bytes:
    """Return the stable UTF-8 representation used as the event digest input."""
    document = {
        "data": _normalize(data),
        "event_id": _normalize(event_id),
        "event_type": _normalize(event_type),
        "schema_version": _normalize(schema_version),
    }
    return json.dumps(document, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def evidence_digest(canonical: bytes) -> str:
    return hashlib.sha256(canonical).hexdigest()


def _keyring(settings: Settings) -> dict[str, bytes]:
    active = (settings.integrity_key or "").strip()
    keys: dict[str, bytes] = {}
    if active:
        keys[settings.integrity_key_id] = active.encode("utf-8")
    if settings.integrity_verify_keys:
        try:
            configured = json.loads(settings.integrity_verify_keys)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("AGENTGUARD_INTEGRITY_VERIFY_KEYS must be a JSON object") from exc
        if not isinstance(configured, dict):
            raise ValueError("AGENTGUARD_INTEGRITY_VERIFY_KEYS must be a JSON object")
        for key_id, value in configured.items():
            if isinstance(key_id, str) and isinstance(value, str) and value:
                keys[key_id] = value.encode("utf-8")
    return keys


def _chain_material(*, tenant_id: UUID, trace_id: str, sequence: int, event_id: str, event_type: str,
                    event_digest_value: str, previous_chain_mac: str | None, key_id: str,
                    canonicalization_version: str) -> bytes:
    document = {
        "canonicalization_version": canonicalization_version,
        "event_digest": event_digest_value,
        "event_id": event_id,
        "event_type": event_type,
        "key_id": key_id,
        "previous_chain_mac": previous_chain_mac,
        "schema": "agentguard.integrity.chain.v1",
        "sequence": sequence,
        "tenant_id": str(tenant_id),
        "trace_id": trace_id,
    }
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def chain_mac(*, key: bytes, tenant_id: UUID, trace_id: str, sequence: int, event_id: str, event_type: str,
              event_digest_value: str, previous_chain_mac: str | None, key_id: str,
              canonicalization_version: str = CANONICALIZATION_VERSION) -> str:
    return hmac.new(key, _chain_material(tenant_id=tenant_id, trace_id=trace_id, sequence=sequence,
                                          event_id=event_id, event_type=event_type,
                                          event_digest_value=event_digest_value,
                                          previous_chain_mac=previous_chain_mac, key_id=key_id,
                                          canonicalization_version=canonicalization_version), hashlib.sha256).hexdigest()


def append_integrity_record(db: Session, *, tenant_id: UUID, trace_id: str, event_type: str, event_id: str,
                            event_digest_value: str, settings: Settings | None = None) -> IntegrityRecord:
    settings = settings or get_settings()
    keys = _keyring(settings)
    key = keys.get(settings.integrity_key_id)
    if key is None or len(key) < 32:
        raise RuntimeError("integrity key unavailable")
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        # Serialize first-head creation as well as updates without relying on MAX(sequence).
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
                   {"lock_key": f"agentguard-integrity:{tenant_id}:{trace_id}"})
    head = db.scalar(select(IntegrityChainHead).where(
        IntegrityChainHead.tenant_id == tenant_id, IntegrityChainHead.trace_id == trace_id).with_for_update())
    now = datetime.now(timezone.utc)
    if head is None:
        head = IntegrityChainHead(tenant_id=tenant_id, trace_id=trace_id, next_sequence=1, head_mac=None, updated_at=now)
        db.add(head)
        db.flush()
    sequence = head.next_sequence
    previous = head.head_mac
    mac = chain_mac(key=key, tenant_id=tenant_id, trace_id=trace_id, sequence=sequence,
                    event_id=event_id, event_type=event_type, event_digest_value=event_digest_value,
                    previous_chain_mac=previous, key_id=settings.integrity_key_id)
    record = IntegrityRecord(tenant_id=tenant_id, trace_id=trace_id, sequence=sequence,
                             event_id=event_id, event_type=event_type, event_digest=event_digest_value,
                             previous_chain_mac=previous, chain_mac=mac, key_id=settings.integrity_key_id,
                             canonicalization_version=CANONICALIZATION_VERSION, created_at=now)
    db.add(record)
    head.next_sequence = sequence + 1
    head.head_mac = mac
    head.updated_at = now
    db.flush()
    return record


@dataclass(frozen=True)
class IntegrityVerification:
    status: str
    events_checked: int
    chain_valid: bool
    projection_consistent: bool
    first_failure: str | None = None

    def as_dict(self, trace_id: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "trace_id": trace_id,
            "status": self.status,
            "events_checked": self.events_checked,
            "chain_valid": self.chain_valid,
            "projection_consistent": self.projection_consistent,
        }
        if self.first_failure:
            result["first_failure"] = self.first_failure
        return result


def _fail(events_checked: int, reason: str, *, projection_consistent: bool = False, chain_valid: bool = False) -> IntegrityVerification:
    return IntegrityVerification("unverifiable" if reason.startswith("UNVERIFIABLE_") else "invalid",
                                 events_checked, chain_valid, projection_consistent, reason)


def _timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return None


def _same_time(left: datetime | None, right: datetime | None) -> bool:
    def normalized(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        current = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return current.astimezone(timezone.utc).replace(microsecond=(current.astimezone(timezone.utc).microsecond // 1000) * 1000)
    return normalized(left) == normalized(right)


def _projection_matches(db: Session, tenant_id: UUID, trace_id: str, events: list[EventLog]) -> bool:
    trace = db.scalar(select(Trace).where(Trace.tenant_id == tenant_id, Trace.trace_id == trace_id))
    if trace is None:
        return False
    expected_trace: dict[str, Any] = {"status": "running", "metadata": {}}
    expected_spans: dict[str, dict[str, Any]] = {}
    for event in events:
        payload = event.payload_json or {}
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        if event.event_type.startswith("trace."):
            occurred_at = _timestamp(data.get("occurred_at") or data.get("__agentguard_occurred_at"))
            if event.event_type == "trace.started":
                expected_trace["started_at"] = expected_trace.get("started_at") or occurred_at
            if event.event_type == "trace.ended":
                expected_trace["ended_at"] = expected_trace.get("ended_at") or occurred_at
            for field in ("workflow_name", "group_id", "provider", "started_at", "ended_at", "status", "schema_version"):
                if field in data:
                    expected_trace[field] = _timestamp(data[field]) if field in {"started_at", "ended_at"} else data[field]
            if isinstance(data.get("metadata"), dict):
                expected_trace["metadata"] = data["metadata"]
        else:
            span_id = str(data.get("span_id") or event.event_id)
            span = expected_spans.setdefault(span_id, {
                "span_id": span_id, "trace_id": trace_id, "status": "running", "attributes": {},
                "span_type": "unknown", "name": "unknown", "schema_version": "0.1",
                "parent_span_id": None, "started_at": None, "ended_at": None, "duration_ms": None,
                "error_type": None, "error_message": None,
            })
            for field in ("parent_span_id", "span_type", "name", "started_at", "ended_at", "duration_ms", "status", "error_type", "error_message", "schema_version"):
                if field in data:
                    span[field] = _timestamp(data[field]) if field in {"started_at", "ended_at"} else data[field]
            if isinstance(data.get("attributes"), dict):
                span["attributes"] = data["attributes"]
    if trace.status != expected_trace.get("status", "running") or trace.workflow_name != expected_trace.get("workflow_name"):
        return False
    if (trace.group_id, trace.provider, trace.metadata_json or {}) != (
        expected_trace.get("group_id"), expected_trace.get("provider"), expected_trace.get("metadata", {})) or not _same_time(trace.ended_at, expected_trace.get("ended_at")):
        return False
    actual_spans = {span.span_id: span for span in db.scalars(select(Span).where(Span.tenant_id == tenant_id, Span.trace_id == trace_id))}
    if not actual_spans and expected_spans:
        archived = db.scalar(select(ArchiveRecord.id).join(ArchiveLifecycle, ArchiveLifecycle.archive_record_id == ArchiveRecord.id).where(
            ArchiveRecord.tenant_id == tenant_id, ArchiveRecord.trace_id == trace_id,
            ArchiveLifecycle.status == "PURGED").limit(1))
        if archived is not None:
            return True
    if set(actual_spans) != set(expected_spans):
        return False
    for span_id, expected in expected_spans.items():
        actual = actual_spans[span_id]
        for field in ("parent_span_id", "span_type", "name", "ended_at", "duration_ms", "status", "error_type", "error_message", "attributes", "schema_version"):
            if field in {"ended_at"}:
                if not _same_time(getattr(actual, field), expected.get(field)):
                    return False
            elif getattr(actual, field) != expected.get(field):
                return False
    return True


def verify_trace_integrity(db: Session, tenant_id: UUID, trace_id: str, settings: Settings | None = None) -> IntegrityVerification:
    settings = settings or get_settings()
    # Once V19 has compacted any historical range, the hot V3 tables are no
    # longer a complete source of truth.  Resolve the authenticated V17/V19
    # stream first; the legacy path below remains unchanged for unsegmented
    # traces.
    try:
        from agentguard_server.models import IntegrityArchiveSegment
        has_v19 = db.scalar(select(IntegrityArchiveSegment.id).where(
            IntegrityArchiveSegment.tenant_id == tenant_id,
            IntegrityArchiveSegment.trace_id == trace_id,
            IntegrityArchiveSegment.state == "COMPACTED",
        ).limit(1)) is not None
    except Exception:
        has_v19 = False
    if has_v19:
        try:
            from agentguard_server.services.archive import ArchiveKeyring
            from agentguard_server.services.archive_store import archive_store_registry
            from agentguard_server.services.integrity_segments import resolve_integrity_records
            from agentguard_server.services.ledger import verify_mixed_ledger
            records = resolve_integrity_records(db, tenant_id=tenant_id, trace_id=trace_id,
                                                stores=archive_store_registry(settings),
                                                keyring=ArchiveKeyring.from_settings(settings), settings=settings)
            mixed = verify_mixed_ledger(db, tenant_id=tenant_id, trace_id=trace_id,
                                        store=archive_store_registry(settings),
                                        keyring=ArchiveKeyring.from_settings(settings), settings=settings)
            if mixed.status != "VALID":
                return _fail(mixed.events_checked, mixed.first_failure or mixed.status)
            return IntegrityVerification("valid", len(records), True, True)
        except Exception as exc:
            reason = getattr(exc, "status", None) or getattr(exc, "reason", None) or "INTEGRITY_SEGMENT_UNAVAILABLE"
            return _fail(0, reason)
    keys = _keyring(settings)
    events = list(db.scalars(select(EventLog).where(EventLog.tenant_id == tenant_id, EventLog.trace_id == trace_id).order_by(EventLog.id)))
    records = list(db.scalars(select(IntegrityRecord).where(IntegrityRecord.tenant_id == tenant_id, IntegrityRecord.trace_id == trace_id).order_by(IntegrityRecord.sequence)))
    if not events:
        return _fail(0, "missing_event")
    if not records:
        return _fail(0, "missing_integrity_record")
    if len(events) != len(records):
        return _fail(min(len(events), len(records)), "missing_integrity_record")
    by_key = {(event.event_type, event.event_id): event for event in events}
    previous = None
    ordered_events: list[EventLog] = []
    for index, record in enumerate(records, start=1):
        event = by_key.get((record.event_type, record.event_id))
        if event is None:
            return _fail(index - 1, "missing_integrity_record")
        if record.sequence != index:
            return _fail(index - 1, "sequence_gap")
        payload = event.payload_json or {}
        data = payload.get("data") if isinstance(payload, dict) else None
        schema_version = payload.get("schema_version") if isinstance(payload, dict) else None
        if not isinstance(data, dict) or not isinstance(schema_version, str):
            return _fail(index - 1, "missing_event")
        digest = evidence_digest(canonicalize_evidence(event_type=event.event_type, event_id=event.event_id,
                                                        schema_version=schema_version, data=data))
        if not hmac.compare_digest(digest, event.event_digest or "") or not hmac.compare_digest(digest, record.event_digest):
            return _fail(index - 1, "event_digest_mismatch")
        if record.canonicalization_version != CANONICALIZATION_VERSION:
            return _fail(index - 1, "UNVERIFIABLE_UNSUPPORTED_VERSION")
        key = keys.get(record.key_id)
        if key is None:
            return _fail(index - 1, "UNVERIFIABLE_KEY_MISSING")
        if record.previous_chain_mac != previous:
            return _fail(index - 1, "previous_chain_mismatch")
        expected_mac = chain_mac(key=key, tenant_id=tenant_id, trace_id=trace_id, sequence=record.sequence,
                                event_id=record.event_id, event_type=record.event_type,
                                event_digest_value=record.event_digest, previous_chain_mac=record.previous_chain_mac,
                                key_id=record.key_id, canonicalization_version=record.canonicalization_version)
        if not hmac.compare_digest(expected_mac, record.chain_mac):
            return _fail(index - 1, "chain_mac_mismatch")
        previous = record.chain_mac
        ordered_events.append(event)
    head = db.scalar(select(IntegrityChainHead).where(IntegrityChainHead.tenant_id == tenant_id,
                                                    IntegrityChainHead.trace_id == trace_id))
    if head is None or head.next_sequence != len(records) + 1 or not hmac.compare_digest(head.head_mac or "", previous or ""):
        return _fail(len(records), "chain_head_mismatch")
    projection = _projection_matches(db, tenant_id, trace_id, ordered_events)
    if not projection:
        return _fail(len(records), "projection_mismatch", projection_consistent=False, chain_valid=True)
    return IntegrityVerification("valid", len(records), True, True)
