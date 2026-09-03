"""V17 verifiable ledger segment archival and fail-closed compaction.

V3's real sequence is scoped to ``(tenant_id, trace_id)``.  V17 therefore
keeps that scope explicit in every segment rather than pretending that the
existing per-trace chain is a tenant-global sequence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import gzip
import hashlib
import hmac
import json
import logging
import secrets
from typing import Any, Mapping
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import and_, func, or_, select, text, update
from sqlalchemy.orm import Session

from agentguard_server.config import Settings, get_settings
from agentguard_server.models import (
    EventLog, IntegrityChainHead, IntegrityCheckpoint, IntegrityCheckpointEntry,
    IntegrityArchiveSegment, IntegrityRecord, LedgerCompactionAuthorization, LedgerCompactionJob,
    LedgerEventArchiveIndex, LedgerSegment, LedgerSegmentLifecycle, RetentionHold,
)
from agentguard_server.services.archive import ArchiveKeyMissing, _bounded_gunzip, _json_value
from agentguard_server.services.archive_store import (
    ArchiveObjectConflict, ArchiveObjectMissing, ArchiveStore, ArchiveStoreError,
    ArchiveStoreUnavailable, archive_object_key,
)
from agentguard_server.services.anchoring import remote_continuity, verify_checkpoint
from agentguard_server.services.integrity import (
    CANONICALIZATION_VERSION, canonicalize_evidence, chain_mac, evidence_digest,
)
from agentguard_server.services.rate_limit import database_now

logger = logging.getLogger("agentguard.ledger")

LEDGER_SEGMENT_VERSION = "ledger-segment-v1"
LEDGER_SEGMENT_ENVELOPE_VERSION = "ledger-segment-envelope-v1"
LEDGER_AAD_PURPOSE = "agentguard-ledger-segment-v1"
MAX_SEGMENT_DEPTH = 16


class LedgerError(ValueError):
    pass


class LedgerEligibilityError(LedgerError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class LedgerVerificationError(LedgerError):
    def __init__(self, status: str):
        super().__init__(status)
        self.status = status


class LedgerArchiveKeyMissing(LedgerVerificationError):
    def __init__(self):
        super().__init__("UNVERIFIABLE_ARCHIVE_KEY_MISSING")


@dataclass(frozen=True)
class LedgerVerification:
    status: str
    events_checked: int = 0
    first_failure: str | None = None

    def as_dict(self) -> dict[str, Any]:
        value = {"status": self.status, "events_checked": self.events_checked}
        if self.first_failure:
            value["first_failure"] = self.first_failure
        return value


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(_json_value(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _event_value(event: EventLog, record: IntegrityRecord) -> dict[str, Any]:
    payload = event.payload_json
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict) or not isinstance(payload.get("schema_version"), str):
        raise LedgerVerificationError("SEGMENT_EVENT_CHAIN_INVALID")
    return {
        "tenant_id": str(record.tenant_id),
        "trace_id": record.trace_id,
        "sequence": int(record.sequence),
        "event_id": record.event_id,
        "event_type": record.event_type,
        "payload": payload,
        "event_digest": record.event_digest,
        "previous_chain_mac": record.previous_chain_mac,
        "chain_mac": record.chain_mac,
        "key_id": record.key_id,
        "canonicalization_version": record.canonicalization_version,
        "created_at": _timestamp(record.created_at),
    }


def _event_summary(event: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "sequence": int(event["sequence"]),
        "event_id": str(event["event_id"]),
        "previous_hash": event.get("previous_chain_mac"),
        "event_hash": str(event["event_digest"]),
    }


def events_manifest_digest(events: list[Mapping[str, Any]]) -> str:
    return _digest(_canonical([_event_summary(event) for event in events]))


def segment_manifest_digest(manifest: Mapping[str, Any]) -> str:
    bound = {
        "segment_version": manifest["segment_version"],
        "tenant_id": manifest["tenant_id"],
        "trace_id": manifest["trace_id"],
        "segment_sequence": manifest["segment_sequence"],
        "start_event_sequence": manifest["start_event_sequence"],
        "end_event_sequence": manifest["end_event_sequence"],
        "start_previous_hash": manifest.get("start_previous_hash"),
        "end_event_hash": manifest["end_event_hash"],
        "event_count": manifest["event_count"],
        "events_manifest_digest": manifest["events_manifest_digest"],
        "covering_checkpoint_sequence": manifest.get("covering_checkpoint_sequence"),
        "covering_checkpoint_digest": manifest.get("covering_checkpoint_digest"),
        "archive_plaintext_sha256": manifest.get("archive_plaintext_sha256"),
    }
    return _digest(_canonical(bound))


def _aad(*, segment_id: UUID, tenant_id: UUID, trace_id: str, segment_sequence: int) -> bytes:
    return _canonical({
        "purpose": LEDGER_AAD_PURPOSE,
        "envelope_version": LEDGER_SEGMENT_ENVELOPE_VERSION,
        "segment_version": LEDGER_SEGMENT_VERSION,
        "segment_id": segment_id,
        "tenant_id": tenant_id,
        "trace_id": trace_id,
        "segment_sequence": segment_sequence,
    })


def _segment_payload(segment: LedgerSegment, events: list[Mapping[str, Any]], checkpoint: IntegrityCheckpoint | None) -> tuple[bytes, dict[str, Any]]:
    checkpoint_sequence = segment.covering_checkpoint_sequence if checkpoint is None else checkpoint.checkpoint_sequence
    checkpoint_digest = segment.covering_checkpoint_digest if checkpoint is None else checkpoint.checkpoint_digest
    manifest: dict[str, Any] = {
        "segment_version": LEDGER_SEGMENT_VERSION,
        "segment_id": str(segment.id),
        "tenant_id": str(segment.tenant_id),
        "trace_id": segment.trace_id,
        "segment_sequence": segment.segment_sequence,
        "start_event_sequence": segment.start_event_sequence,
        "end_event_sequence": segment.end_event_sequence,
        "start_previous_hash": segment.start_previous_hash,
        "end_event_hash": segment.end_event_hash,
        "event_count": len(events),
        "events_manifest_digest": events_manifest_digest(events),
        "covering_checkpoint_sequence": checkpoint_sequence,
        "covering_checkpoint_digest": checkpoint_digest,
        # This value is computed over a digest-free canonical payload to avoid
        # a circular hash while still binding the plaintext digest into the
        # segment manifest digest.
        "archive_plaintext_sha256": None,
        "segment_manifest_digest": None,
    }
    digest_free = _canonical({"manifest": manifest, "events": events})
    manifest["archive_plaintext_sha256"] = _digest(digest_free)
    manifest["segment_manifest_digest"] = segment_manifest_digest(manifest)
    plaintext = _canonical({"manifest": manifest, "events": events})
    return plaintext, manifest


def seal_ledger_segment(*, segment: LedgerSegment, plaintext: bytes, keyring: Any) -> bytes:
    compressed = gzip.compress(plaintext, compresslevel=9, mtime=0)
    key_id = keyring.current_key_id
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(keyring.key_for(key_id)).encrypt(
        nonce, compressed,
        _aad(segment_id=segment.id, tenant_id=segment.tenant_id, trace_id=segment.trace_id, segment_sequence=segment.segment_sequence),
    )
    envelope = {
        "envelope_version": LEDGER_SEGMENT_ENVELOPE_VERSION,
        "segment_version": LEDGER_SEGMENT_VERSION,
        "segment_id": segment.id,
        "tenant_id": segment.tenant_id,
        "trace_id": segment.trace_id,
        "segment_sequence": segment.segment_sequence,
        "key_id": key_id,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "plaintext_sha256": _digest(plaintext),
        "compressed_sha256": _digest(compressed),
        "ciphertext_sha256": _digest(ciphertext),
    }
    return _canonical(envelope)


def unseal_ledger_segment(*, object_bytes: bytes, segment: LedgerSegment, keyring: Any, max_object_bytes: int = 96 * 1024 * 1024, max_decompressed_bytes: int = 64 * 1024 * 1024) -> tuple[dict[str, Any], bytes]:
    if len(object_bytes) > max_object_bytes:
        raise LedgerVerificationError("INVALID_SEGMENT_ENVELOPE")
    try:
        envelope = json.loads(object_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LedgerVerificationError("INVALID_SEGMENT_ENVELOPE") from exc
    required = {"envelope_version", "segment_version", "segment_id", "tenant_id", "trace_id", "segment_sequence", "key_id", "nonce", "ciphertext", "plaintext_sha256", "compressed_sha256", "ciphertext_sha256"}
    if not isinstance(envelope, dict) or set(envelope) != required:
        raise LedgerVerificationError("INVALID_SEGMENT_ENVELOPE")
    if (envelope["envelope_version"] != LEDGER_SEGMENT_ENVELOPE_VERSION or envelope["segment_version"] != LEDGER_SEGMENT_VERSION or
            envelope["segment_id"] != str(segment.id) or envelope["tenant_id"] != str(segment.tenant_id) or
            envelope["trace_id"] != segment.trace_id or envelope["segment_sequence"] != segment.segment_sequence):
        raise LedgerVerificationError("SEGMENT_DIGEST_MISMATCH")
    try:
        nonce = base64.b64decode(str(envelope["nonce"]).encode("ascii"), validate=True)
        ciphertext = base64.b64decode(str(envelope["ciphertext"]).encode("ascii"), validate=True)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise LedgerVerificationError("INVALID_SEGMENT_CIPHERTEXT") from exc
    if len(nonce) != 12 or _digest(ciphertext) != envelope["ciphertext_sha256"]:
        raise LedgerVerificationError("INVALID_SEGMENT_CIPHERTEXT")
    try:
        compressed = AESGCM(keyring.key_for(str(envelope["key_id"]))).decrypt(
            nonce, ciphertext,
            _aad(segment_id=segment.id, tenant_id=segment.tenant_id, trace_id=segment.trace_id, segment_sequence=segment.segment_sequence),
        )
    except (LedgerArchiveKeyMissing, ArchiveKeyMissing) as exc:
        raise LedgerArchiveKeyMissing() from exc
    except (InvalidTag, ValueError) as exc:
        raise LedgerVerificationError("INVALID_SEGMENT_CIPHERTEXT") from exc
    if _digest(compressed) != envelope["compressed_sha256"]:
        raise LedgerVerificationError("SEGMENT_DIGEST_MISMATCH")
    try:
        plaintext = _bounded_gunzip(compressed, max_decompressed_bytes)
    except Exception as exc:
        if isinstance(exc, LedgerVerificationError):
            raise
        raise LedgerVerificationError("INVALID_SEGMENT_ENVELOPE") from exc
    if _digest(plaintext) != envelope["plaintext_sha256"]:
        raise LedgerVerificationError("SEGMENT_DIGEST_MISMATCH")
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LedgerVerificationError("INVALID_SEGMENT_ENVELOPE") from exc
    if not isinstance(payload, dict) or set(payload) != {"manifest", "events"} or not isinstance(payload["manifest"], dict) or not isinstance(payload["events"], list):
        raise LedgerVerificationError("INVALID_SEGMENT_ENVELOPE")
    manifest = payload["manifest"]
    if manifest.get("segment_version") != LEDGER_SEGMENT_VERSION or manifest.get("segment_id") != str(segment.id) or manifest.get("tenant_id") != str(segment.tenant_id) or manifest.get("trace_id") != segment.trace_id:
        raise LedgerVerificationError("SEGMENT_DIGEST_MISMATCH")
    if (
        manifest.get("segment_sequence") != segment.segment_sequence
        or manifest.get("start_event_sequence") != segment.start_event_sequence
        or manifest.get("end_event_sequence") != segment.end_event_sequence
        or manifest.get("start_previous_hash") != segment.start_previous_hash
        or manifest.get("end_event_hash") != segment.end_event_hash
    ):
        raise LedgerVerificationError("SEGMENT_BOUNDARY_MISMATCH")
    if getattr(segment, "archive_ciphertext_sha256", None) and envelope["ciphertext_sha256"] != segment.archive_ciphertext_sha256:
        raise LedgerVerificationError("SEGMENT_DIGEST_MISMATCH")
    if getattr(segment, "archive_plaintext_sha256", None) and envelope["plaintext_sha256"] != segment.archive_plaintext_sha256:
        raise LedgerVerificationError("SEGMENT_DIGEST_MISMATCH")
    if getattr(segment, "archive_encryption_key_id", None) and envelope["key_id"] != segment.archive_encryption_key_id:
        raise LedgerVerificationError("UNVERIFIABLE_ARCHIVE_KEY_MISSING")
    events = payload["events"]
    if manifest.get("event_count") != len(events) or manifest.get("events_manifest_digest") != events_manifest_digest(events):
        raise LedgerVerificationError("SEGMENT_DIGEST_MISMATCH")
    if manifest.get("segment_manifest_digest") != segment_manifest_digest(manifest):
        raise LedgerVerificationError("SEGMENT_DIGEST_MISMATCH")
    digest_free_manifest = dict(manifest)
    digest_free_manifest["archive_plaintext_sha256"] = None
    digest_free_manifest["segment_manifest_digest"] = None
    if manifest.get("archive_plaintext_sha256") != _digest(_canonical({"manifest": digest_free_manifest, "events": events})):
        raise LedgerVerificationError("SEGMENT_DIGEST_MISMATCH")
    event_keys = {"tenant_id", "trace_id", "sequence", "event_id", "event_type", "payload", "event_digest", "previous_chain_mac", "chain_mac", "key_id", "canonicalization_version", "created_at"}
    if any(not isinstance(event, dict) or set(event) != event_keys for event in events):
        raise LedgerVerificationError("INVALID_SEGMENT_ENVELOPE")
    return payload, plaintext


def _v3_keys(settings: Settings) -> dict[str, bytes]:
    active = (settings.integrity_key or "").strip()
    values: dict[str, bytes] = {settings.integrity_key_id: active.encode("utf-8")} if active else {}
    if settings.integrity_verify_keys:
        try:
            configured = json.loads(settings.integrity_verify_keys)
        except (TypeError, json.JSONDecodeError) as exc:
            raise LedgerVerificationError("UNVERIFIABLE_V3_KEY_MISSING") from exc
        if isinstance(configured, dict):
            values.update({str(k): str(v).encode("utf-8") for k, v in configured.items() if isinstance(k, str) and isinstance(v, str)})
    return values


def verify_v3_events(*, tenant_id: UUID, trace_id: str, events: list[Mapping[str, Any]], settings: Settings, expected_start: int | None = None, expected_end: int | None = None) -> LedgerVerification:
    if not events:
        return LedgerVerification("SEGMENT_EVENT_CHAIN_INVALID", 0, "missing_event")
    keys = _v3_keys(settings)
    previous: str | None = None
    first_sequence = int(events[0]["sequence"])
    if expected_start is not None and first_sequence != expected_start:
        return LedgerVerification("SEGMENT_START_BOUNDARY_INVALID", 0, "start_sequence")
    for offset, event in enumerate(events):
        sequence = int(event["sequence"])
        if sequence != first_sequence + offset:
            return LedgerVerification("SEGMENT_EVENT_CHAIN_INVALID", offset, "sequence_gap")
        payload = event.get("payload")
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict) or not isinstance(payload.get("schema_version"), str):
            return LedgerVerification("SEGMENT_EVENT_CHAIN_INVALID", offset, "missing_event")
        digest = evidence_digest(canonicalize_evidence(event_type=str(event["event_type"]), event_id=str(event["event_id"]), schema_version=payload["schema_version"], data=payload["data"]))
        if not hmac.compare_digest(digest, str(event.get("event_digest", ""))):
            return LedgerVerification("SEGMENT_EVENT_CHAIN_INVALID", offset, "event_digest_mismatch")
        key_id = str(event.get("key_id", "")); key = keys.get(key_id)
        if key is None:
            return LedgerVerification("UNVERIFIABLE_V3_KEY_MISSING", offset, "UNVERIFIABLE_V3_KEY_MISSING")
        record_previous = event.get("previous_chain_mac")
        if record_previous != previous:
            if offset == 0 and expected_start is not None and record_previous == events[0].get("previous_chain_mac"):
                previous = record_previous
            else:
                return LedgerVerification("SEGMENT_EVENT_CHAIN_INVALID", offset, "previous_chain_mismatch")
        expected_mac = chain_mac(key=key, tenant_id=tenant_id, trace_id=trace_id, sequence=sequence,
            event_id=str(event["event_id"]), event_type=str(event["event_type"]), event_digest_value=str(event["event_digest"]),
            previous_chain_mac=record_previous, key_id=key_id, canonicalization_version=str(event.get("canonicalization_version", "")))
        if not hmac.compare_digest(expected_mac, str(event.get("chain_mac", ""))):
            return LedgerVerification("SEGMENT_EVENT_CHAIN_INVALID", offset, "chain_mac_mismatch")
        previous = str(event["chain_mac"])
    if expected_end is not None and int(events[-1]["sequence"]) != expected_end:
        return LedgerVerification("SEGMENT_END_BOUNDARY_INVALID", len(events), "end_sequence")
    return LedgerVerification("VALID", len(events))


def _records_for_range(db: Session, segment: LedgerSegment) -> list[IntegrityRecord]:
    return list(db.scalars(select(IntegrityRecord).where(
        IntegrityRecord.tenant_id == segment.tenant_id, IntegrityRecord.trace_id == segment.trace_id,
        IntegrityRecord.sequence.between(segment.start_event_sequence, segment.end_event_sequence),
    ).order_by(IntegrityRecord.sequence)))


def _events_for_records(db: Session, records: list[IntegrityRecord]) -> list[dict[str, Any]]:
    if not records:
        raise LedgerEligibilityError("SEGMENT_SOURCE_EMPTY")
    event_rows = list(db.scalars(select(EventLog).where(
        EventLog.tenant_id == records[0].tenant_id, EventLog.trace_id == records[0].trace_id,
        EventLog.event_id.in_([r.event_id for r in records]), EventLog.event_type.in_([r.event_type for r in records]),
    )))
    by_key = {(row.event_type, row.event_id): row for row in event_rows}
    result: list[dict[str, Any]] = []
    for record in records:
        event = by_key.get((record.event_type, record.event_id))
        if event is None:
            raise LedgerEligibilityError("SEGMENT_SOURCE_MISSING")
        result.append(_event_value(event, record))
    return result


def _active_hold(db: Session, tenant_id: UUID, trace_id: str) -> bool:
    return db.scalar(select(RetentionHold.id).where(
        RetentionHold.tenant_id == tenant_id, RetentionHold.released_at.is_(None),
        or_(RetentionHold.subject_type == "TENANT", and_(RetentionHold.subject_type == "TRACE", RetentionHold.trace_id == trace_id)),
    ).limit(1)) is not None


def create_ledger_segment_candidate(db: Session, *, tenant_id: UUID, trace_id: str, settings: Settings | None = None, now: datetime | None = None) -> LedgerSegment:
    settings = settings or get_settings()
    if not settings.ledger_archive_enabled:
        raise LedgerEligibilityError("LEDGER_ARCHIVE_DISABLED")
    current = _utc(now) if now else datetime.now(timezone.utc)
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": f"agentguard-ledger:{tenant_id}:{trace_id}"})
    existing = db.scalar(select(LedgerSegment).join(LedgerSegmentLifecycle).where(
        LedgerSegment.tenant_id == tenant_id, LedgerSegment.trace_id == trace_id,
        LedgerSegmentLifecycle.status.in_(["CANDIDATE", "CLOSED", "ARCHIVING", "ARCHIVED_VERIFIED", "COMPACTION_AUTHORIZED"]),
    ).order_by(LedgerSegment.segment_sequence.desc()).limit(1))
    if existing is not None:
        return existing
    head = db.scalar(select(IntegrityChainHead).where(IntegrityChainHead.tenant_id == tenant_id, IntegrityChainHead.trace_id == trace_id))
    if head is None or head.next_sequence <= 1:
        raise LedgerEligibilityError("SEGMENT_SOURCE_EMPTY")
    previous = db.scalar(select(LedgerSegment).join(LedgerSegmentLifecycle).where(
        LedgerSegment.tenant_id == tenant_id, LedgerSegment.trace_id == trace_id,
        LedgerSegmentLifecycle.status == "COMPACTED",
    ).order_by(LedgerSegment.segment_sequence.desc()).limit(1))
    start = previous.end_event_sequence + 1 if previous else 1
    max_end = head.next_sequence - 1 - settings.ledger_hot_tail_events
    if max_end < start:
        raise LedgerEligibilityError("HOT_TAIL_PROTECTED")
    cutoff = current - timedelta(days=settings.ledger_segment_min_age_days)
    records = list(db.scalars(select(IntegrityRecord).where(
        IntegrityRecord.tenant_id == tenant_id, IntegrityRecord.trace_id == trace_id,
        IntegrityRecord.sequence.between(start, max_end), IntegrityRecord.created_at <= cutoff,
    ).order_by(IntegrityRecord.sequence).limit(settings.ledger_segment_max_events)))
    if not records or records[0].sequence != start:
        raise LedgerEligibilityError("SEGMENT_NOT_CONTIGUOUS")
    for left, right in zip(records, records[1:]):
        if right.sequence != left.sequence + 1:
            raise LedgerEligibilityError("SEGMENT_GAP")
    events = _events_for_records(db, records)
    result = verify_v3_events(tenant_id=tenant_id, trace_id=trace_id, events=events, settings=settings, expected_start=start, expected_end=records[-1].sequence)
    if result.status != "VALID":
        raise LedgerEligibilityError(result.first_failure or result.status)
    successor = db.scalar(select(IntegrityRecord).where(
        IntegrityRecord.tenant_id == tenant_id, IntegrityRecord.trace_id == trace_id,
        IntegrityRecord.sequence == records[-1].sequence + 1,
    ))
    if successor is None:
        raise LedgerEligibilityError("SEGMENT_END_BOUNDARY_INVALID")
    if successor.previous_chain_mac != records[-1].chain_mac:
        raise LedgerEligibilityError("SEGMENT_END_BOUNDARY_INVALID")
    segment = LedgerSegment(
        tenant_id=tenant_id, trace_id=trace_id, segment_sequence=(previous.segment_sequence + 1 if previous else 1),
        segment_version=LEDGER_SEGMENT_VERSION, start_event_sequence=start, end_event_sequence=records[-1].sequence,
        start_previous_hash=records[0].previous_chain_mac, end_event_hash=records[-1].chain_mac,
        event_count=len(records), events_manifest_digest=events_manifest_digest(events),
        segment_manifest_digest=segment_manifest_digest({
            "segment_version": LEDGER_SEGMENT_VERSION, "tenant_id": str(tenant_id), "trace_id": trace_id,
            "segment_sequence": (previous.segment_sequence + 1 if previous else 1), "start_event_sequence": start,
            "end_event_sequence": records[-1].sequence, "start_previous_hash": records[0].previous_chain_mac,
            "end_event_hash": records[-1].chain_mac, "event_count": len(records),
            "events_manifest_digest": events_manifest_digest(events), "covering_checkpoint_sequence": None,
            "covering_checkpoint_digest": None, "archive_plaintext_sha256": None,
        }),
        created_at=current,
    )
    db.add(segment); db.flush()
    db.add(LedgerSegmentLifecycle(segment_id=segment.id, status="CANDIDATE", updated_at=current))
    db.commit(); db.refresh(segment)
    logger.info("ledger_segment_created tenant_id=%s trace_id=%s segment_id=%s", tenant_id, trace_id, segment.id)
    return segment


def _covering_checkpoint(db: Session, segment: LedgerSegment, settings: Settings) -> tuple[IntegrityCheckpoint, dict[str, Any]]:
    entries = list(db.scalars(select(IntegrityCheckpointEntry).where(
        IntegrityCheckpointEntry.tenant_id == segment.tenant_id, IntegrityCheckpointEntry.trace_id == segment.trace_id,
        IntegrityCheckpointEntry.tenant_chain_sequence >= segment.end_event_sequence,
    ).order_by(IntegrityCheckpointEntry.tenant_chain_sequence)))
    for entry in entries:
        checkpoint = db.get(IntegrityCheckpoint, entry.checkpoint_id)
        if checkpoint is not None:
            verification = verify_checkpoint(db, checkpoint.id, settings=settings)
            if verification.get("status") == "VALID":
                return checkpoint, verification
    raise LedgerEligibilityError("V15_COVERAGE_INVALID")


def archive_ledger_segment(db: Session, segment_id: UUID, store: ArchiveStore, *, provider: Any, settings: Settings | None = None, keyring: Any | None = None, now: datetime | None = None) -> LedgerSegment:
    settings = settings or get_settings()
    segment = db.get(LedgerSegment, segment_id)
    if segment is None:
        raise LedgerEligibilityError("SEGMENT_NOT_FOUND")
    lifecycle = db.get(LedgerSegmentLifecycle, segment.id)
    if lifecycle is None or lifecycle.status not in {"CANDIDATE", "CLOSED", "FAILED"}:
        raise LedgerEligibilityError("SEGMENT_STATE_INVALID")
    records = _records_for_range(db, segment)
    if len(records) != segment.event_count or records[0].sequence != segment.start_event_sequence or records[-1].sequence != segment.end_event_sequence:
        raise LedgerEligibilityError("SEGMENT_SOURCE_CHANGED")
    events = _events_for_records(db, records)
    result = verify_v3_events(tenant_id=segment.tenant_id, trace_id=segment.trace_id, events=events, settings=settings, expected_start=segment.start_event_sequence, expected_end=segment.end_event_sequence)
    if result.status != "VALID":
        raise LedgerEligibilityError(result.first_failure or result.status)
    successor = db.scalar(select(IntegrityRecord).where(
        IntegrityRecord.tenant_id == segment.tenant_id, IntegrityRecord.trace_id == segment.trace_id,
        IntegrityRecord.sequence == segment.end_event_sequence + 1,
    ))
    if successor is None or successor.previous_chain_mac != segment.end_event_hash:
        raise LedgerEligibilityError("SEGMENT_END_BOUNDARY_INVALID")
    checkpoint, checkpoint_verification = _covering_checkpoint(db, segment, settings)
    continuity = remote_continuity(db, provider, settings=settings)
    if continuity.status != "MATCH":
        raise LedgerEligibilityError(f"V15_{continuity.status}")
    if segment.archive_object_key is None:
        segment.archive_object_key = archive_object_key(segment.tenant_id, segment.id).replace("trace-archive-v1/", "agentguard/ledger/v1/", 1).replace(".bin", ".agledger")
    plaintext, manifest = _segment_payload(segment, events, checkpoint)
    if len(plaintext) > settings.archive_max_plaintext_bytes:
        raise LedgerEligibilityError("ARCHIVE_SIZE_LIMIT")
    if keyring is None:
        from agentguard_server.services.archive import ArchiveKeyring
        keyring = ArchiveKeyring.from_settings(settings)
    # Commit the short state transition before touching the external store.
    # The destructive database transaction never includes network I/O.
    lifecycle.status = "ARCHIVING"; lifecycle.updated_at = _utc(now) if now else database_now(db); db.commit()
    object_bytes = seal_ledger_segment(segment=segment, plaintext=plaintext, keyring=keyring)
    try:
        store.put(segment.archive_object_key, object_bytes)
        stored = store.get(segment.archive_object_key)
    except ArchiveObjectConflict as exc:
        lifecycle.status = "FAILED"; lifecycle.last_error_category = "LEDGER_ARCHIVE_OBJECT_CONFLICT"; db.commit()
        raise LedgerVerificationError("LEDGER_ARCHIVE_OBJECT_CONFLICT") from exc
    except (ArchiveObjectMissing, ArchiveStoreUnavailable, ArchiveStoreError) as exc:
        lifecycle.status = "FAILED"; lifecycle.last_error_category = "OBJECT_STORE_UNAVAILABLE"; db.commit()
        raise LedgerVerificationError("OBJECT_STORE_UNAVAILABLE") from exc
    try:
        payload, _ = unseal_ledger_segment(object_bytes=stored, segment=segment, keyring=keyring, max_object_bytes=settings.archive_max_object_bytes, max_decompressed_bytes=settings.archive_max_decompressed_bytes)
        readback = verify_v3_events(tenant_id=segment.tenant_id, trace_id=segment.trace_id, events=payload["events"], settings=settings, expected_start=segment.start_event_sequence, expected_end=segment.end_event_sequence)
        if readback.status != "VALID":
            raise LedgerVerificationError(readback.status)
    except LedgerVerificationError as exc:
        lifecycle.status = "FAILED"; lifecycle.last_error_category = exc.status; lifecycle.updated_at = database_now(db); db.commit()
        raise
    segment.segment_manifest_digest = manifest["segment_manifest_digest"]
    segment.events_manifest_digest = manifest["events_manifest_digest"]
    segment.archive_plaintext_sha256 = _digest(plaintext)
    stored_envelope = json.loads(stored.decode("utf-8"))
    segment.archive_ciphertext_sha256 = stored_envelope["ciphertext_sha256"]
    segment.archive_encryption_key_id = stored_envelope["key_id"]
    segment.covering_checkpoint_id = checkpoint.id
    segment.covering_checkpoint_sequence = checkpoint.checkpoint_sequence
    segment.covering_checkpoint_digest = checkpoint.checkpoint_digest
    segment.archived_verified_at = _utc(now) if now else database_now(db)
    lifecycle.status = "ARCHIVED_VERIFIED"; lifecycle.last_error_category = None; lifecycle.updated_at = segment.archived_verified_at
    for event in events:
        db.add(LedgerEventArchiveIndex(tenant_id=segment.tenant_id, trace_id=segment.trace_id, event_id=str(event["event_id"]), event_sequence=int(event["sequence"]), segment_id=segment.id, event_hash=str(event["event_digest"]), original_created_at=datetime.fromisoformat(str(event["created_at"]).replace("Z", "+00:00"))))
    from agentguard_server.services.replicas import LEDGER_SEGMENT, enqueue_replication_jobs, ensure_replica, finalize_verified_replica
    primary_replica = ensure_replica(db, tenant_id=segment.tenant_id, logical_archive_type=LEDGER_SEGMENT,
                   logical_archive_id=segment.id, store_id=settings.archive_primary_store_id,
                   object_key=segment.archive_object_key, expected_ciphertext_sha256=segment.archive_ciphertext_sha256,
                   expected_plaintext_sha256=segment.archive_plaintext_sha256,
                   expected_logical_digest=segment.segment_manifest_digest,
                   encryption_key_id=segment.archive_encryption_key_id or "", state="PENDING",
                   now=segment.archived_verified_at)
    # The object was fully read back and deterministically verified above;
    # only this centralized transition may make the primary source eligible.
    finalize_verified_replica(db, replica=primary_replica, verification_status="VALID")
    db.commit()
    if settings.archive_replication_enabled:
        enqueue_replication_jobs(db, tenant_id=segment.tenant_id, logical_archive_type=LEDGER_SEGMENT, logical_archive_id=segment.id, settings=settings, now=segment.archived_verified_at)
    db.refresh(segment)
    logger.info("ledger_segment_archive_verified tenant_id=%s trace_id=%s segment_id=%s", segment.tenant_id, segment.trace_id, segment.id)
    return segment


def authorize_ledger_compaction(db: Session, segment_id: UUID, *, provider: Any, settings: Settings | None = None, keyring: Any | None = None, store: ArchiveStore | None = None, now: datetime | None = None) -> LedgerCompactionAuthorization:
    settings = settings or get_settings(); segment = db.get(LedgerSegment, segment_id); lifecycle = db.get(LedgerSegmentLifecycle, segment_id)
    if segment is None or lifecycle is None or lifecycle.status != "ARCHIVED_VERIFIED":
        raise LedgerEligibilityError("SEGMENT_NOT_ARCHIVED")
    if _active_hold(db, segment.tenant_id, segment.trace_id):
        raise LedgerEligibilityError("RETENTION_HOLD_ACTIVE")
    if store is not None:
        if keyring is None:
            from agentguard_server.services.archive import ArchiveKeyring
            keyring = ArchiveKeyring.from_settings(settings)
        try:
            object_bytes = store.get(segment.archive_object_key or "")
            unseal_ledger_segment(object_bytes=object_bytes, segment=segment, keyring=keyring, max_object_bytes=settings.archive_max_object_bytes, max_decompressed_bytes=settings.archive_max_decompressed_bytes)
        except ArchiveObjectMissing as exc:
            raise LedgerVerificationError("SEGMENT_OBJECT_MISSING") from exc
        except ArchiveStoreError as exc:
            raise LedgerVerificationError("OBJECT_STORE_UNAVAILABLE") from exc
    checkpoint = db.get(IntegrityCheckpoint, segment.covering_checkpoint_id) if segment.covering_checkpoint_id else None
    if checkpoint is None or verify_checkpoint(db, checkpoint.id, settings=settings).get("status") != "VALID":
        raise LedgerEligibilityError("V15_COVERAGE_INVALID")
    v20_result = None
    if getattr(settings, "quorum_enabled", False):
        from agentguard_server.services.quorum import require_fresh_quorum, QuorumError
        try:
            v20_result = require_fresh_quorum(db, checkpoint.id, now=now)
        except QuorumError as exc:
            raise LedgerEligibilityError(f"V20_{type(exc).__name__}") from exc
    continuity = remote_continuity(db, provider, settings=settings)
    if continuity.status != "MATCH":
        raise LedgerEligibilityError(f"V15_{continuity.status}")
    current = _utc(now) if now else database_now(db)
    replica_policy_version = None
    verified_count = None
    required_store_ids = None
    if settings.ledger_compaction_replica_policy_enabled:
        from agentguard_server.services.replicas import replica_policy_passes, verified_replica_count, ensure_policy
        policy = ensure_policy(db, settings=settings, now=current)
        verified_count = verified_replica_count(db, tenant_id=segment.tenant_id, logical_archive_type="LEDGER_SEGMENT", logical_archive_id=segment.id, settings=settings, now=current)
        if not replica_policy_passes(db, tenant_id=segment.tenant_id, logical_archive_type="LEDGER_SEGMENT", logical_archive_id=segment.id, settings=settings, now=current):
            raise LedgerEligibilityError("MINIMUM_VERIFIED_REPLICAS_NOT_MET")
        replica_policy_version = policy.policy_version
        required_store_ids = policy.required_store_ids
    authorization = LedgerCompactionAuthorization(
        segment_id=segment.id, segment_manifest_digest=segment.segment_manifest_digest,
        archive_ciphertext_sha256=segment.archive_ciphertext_sha256 or "", covering_checkpoint_digest=segment.covering_checkpoint_digest or "",
        remote_continuity_status="MATCH", replica_policy_version=replica_policy_version,
        verified_replica_count=verified_count, required_store_ids=required_store_ids,
        verified_at=current,
        expires_at=current + timedelta(seconds=settings.ledger_compaction_authorization_ttl_seconds),
        authorized_by_instance=settings.instance_id, created_at=current,
    )
    if v20_result is not None:
        authorization.v20_policy_epoch = checkpoint.policy_epoch
        authorization.v20_quorum_evaluation_digest = v20_result.evaluation_digest
        authorization.v20_quorum_state = v20_result.state
        authorization.v20_receipt_set_digest = v20_result.receipt_set_digest
        authorization.v20_evaluated_at = v20_result.evaluated_at
        authorization.v20_fresh_until = v20_result.fresh_until
    db.add(authorization); lifecycle.status = "COMPACTION_AUTHORIZED"; lifecycle.updated_at = current; db.commit(); db.refresh(authorization)
    logger.info("ledger_segment_compaction_authorized segment_id=%s", segment.id)
    return authorization


def compact_ledger_segment(db: Session, segment_id: UUID, *, settings: Settings | None = None, now: datetime | None = None, fault_inject: bool = False) -> int:
    settings = settings or get_settings()
    if not settings.ledger_compaction_enabled:
        raise LedgerEligibilityError("LEDGER_COMPACTION_DISABLED")
    segment = db.get(LedgerSegment, segment_id); lifecycle = db.get(LedgerSegmentLifecycle, segment_id)
    if segment is None or lifecycle is None:
        raise LedgerEligibilityError("SEGMENT_NOT_FOUND")
    if lifecycle.status == "COMPACTED":
        return 0
    if lifecycle.status != "COMPACTION_AUTHORIZED":
        raise LedgerEligibilityError("SEGMENT_NOT_AUTHORIZED")
    current = _utc(now) if now else database_now(db)
    authorization = db.scalar(select(LedgerCompactionAuthorization).where(LedgerCompactionAuthorization.segment_id == segment.id).order_by(LedgerCompactionAuthorization.created_at.desc()).limit(1))
    if authorization is None or _utc(authorization.expires_at) <= current:
        raise LedgerEligibilityError("COMPACTION_AUTHORIZATION_EXPIRED")
    if getattr(settings, "quorum_enabled", False):
        from agentguard_server.services.quorum import require_fresh_quorum, QuorumError
        try:
            current_quorum = require_fresh_quorum(db, segment.covering_checkpoint_id, now=now)
        except QuorumError as exc:
            raise LedgerEligibilityError(f"V20_{type(exc).__name__}") from exc
        checkpoint = db.get(IntegrityCheckpoint, segment.covering_checkpoint_id) if segment.covering_checkpoint_id else None
        if checkpoint is None or authorization.v20_policy_epoch != checkpoint.policy_epoch or authorization.v20_quorum_evaluation_digest != current_quorum.evaluation_digest:
            raise LedgerEligibilityError("V20_QUORUM_AUTHORIZATION_BINDING_MISMATCH")
    if (authorization.segment_manifest_digest != segment.segment_manifest_digest or authorization.archive_ciphertext_sha256 != (segment.archive_ciphertext_sha256 or "") or authorization.covering_checkpoint_digest != (segment.covering_checkpoint_digest or "") or authorization.remote_continuity_status != "MATCH"):
        raise LedgerEligibilityError("COMPACTION_AUTHORIZATION_DIGEST_MISMATCH")
    if settings.ledger_compaction_replica_policy_enabled:
        from agentguard_server.services.replicas import replica_policy_passes, ensure_policy, verified_replica_count
        policy = ensure_policy(db, settings=settings, now=current)
        if authorization.replica_policy_version != policy.policy_version or authorization.verified_replica_count is None or authorization.verified_replica_count != verified_replica_count(db, tenant_id=segment.tenant_id, logical_archive_type="LEDGER_SEGMENT", logical_archive_id=segment.id, settings=settings, now=current) or not replica_policy_passes(db, tenant_id=segment.tenant_id, logical_archive_type="LEDGER_SEGMENT", logical_archive_id=segment.id, settings=settings, now=current):
            raise LedgerEligibilityError("MINIMUM_VERIFIED_REPLICAS_NOT_MET")
    if _active_hold(db, segment.tenant_id, segment.trace_id):
        raise LedgerEligibilityError("RETENTION_HOLD_ACTIVE")
    records = _records_for_range(db, segment)
    if len(records) != segment.event_count:
        raise LedgerEligibilityError("SEGMENT_SOURCE_CHANGED")
    events = _events_for_records(db, records)
    if events[0]["previous_chain_mac"] != segment.start_previous_hash or events[-1]["chain_mac"] != segment.end_event_hash:
        raise LedgerEligibilityError("SEGMENT_BOUNDARY_MISMATCH")
    successor = db.scalar(select(IntegrityRecord).where(IntegrityRecord.tenant_id == segment.tenant_id, IntegrityRecord.trace_id == segment.trace_id, IntegrityRecord.sequence == segment.end_event_sequence + 1))
    if successor is None or successor.previous_chain_mac != segment.end_event_hash:
        raise LedgerEligibilityError("SEGMENT_END_BOUNDARY_INVALID")
    index_count = db.scalar(select(func.count(LedgerEventArchiveIndex.id)).where(LedgerEventArchiveIndex.segment_id == segment.id)) or 0
    if index_count != segment.event_count:
        raise LedgerEligibilityError("ARCHIVE_INDEX_INCOMPLETE")
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        deleted = int(db.execute(text("SELECT public.compact_verified_ledger_segment_v1(:segment_id)"), {"segment_id": str(segment.id)}).scalar_one())
    else:
        if fault_inject:
            db.rollback()
            raise RuntimeError("injected compaction transaction failure")
        for event in list(db.scalars(select(EventLog).where(EventLog.tenant_id == segment.tenant_id, EventLog.trace_id == segment.trace_id, EventLog.event_id.in_([r.event_id for r in records]), EventLog.event_type.in_([r.event_type for r in records])))):
            db.delete(event)
        lifecycle.status = "COMPACTED"; lifecycle.updated_at = current
        db.flush(); deleted = len(records); db.commit()
    logger.info("ledger_segment_compacted segment_id=%s deleted=%s", segment.id, deleted)
    return deleted


def _segment_events(db: Session, segment: LedgerSegment, store: ArchiveStore | Mapping[str, Any], keyring: Any, settings: Settings) -> list[dict[str, Any]]:
    if isinstance(store, Mapping):
        # V18 fallback is still a full V17 verification for every candidate;
        # a successful HTTP response or stale VALID bit is never sufficient.
        from agentguard_server.models import ArchiveReplica
        from agentguard_server.services.archive_store import ArchiveStoreBinding
        from agentguard_server.services.replicas import LEDGER_SEGMENT
        rows = list(db.scalars(select(ArchiveReplica).where(
            ArchiveReplica.tenant_id == segment.tenant_id,
            ArchiveReplica.logical_archive_type == LEDGER_SEGMENT,
            ArchiveReplica.logical_archive_id == segment.id,
        )))
        priorities = {key: getattr(value, "priority", 100) for key, value in store.items()}
        last: LedgerVerificationError | None = None
        for replica in sorted(rows, key=lambda row: (priorities.get(row.store_id, 10_000), row.store_id)):
            binding = store.get(replica.store_id)
            if replica.state != "VALID" or binding is None:
                continue
            try:
                body = binding.store.get(replica.object_key) if isinstance(binding, ArchiveStoreBinding) else binding.get(replica.object_key)
                payload, _ = unseal_ledger_segment(object_bytes=body, segment=segment, keyring=keyring, max_object_bytes=settings.archive_max_object_bytes, max_decompressed_bytes=settings.archive_max_decompressed_bytes)
                result = verify_v3_events(tenant_id=segment.tenant_id, trace_id=segment.trace_id, events=payload["events"], settings=settings, expected_start=segment.start_event_sequence, expected_end=segment.end_event_sequence)
                if result.status != "VALID":
                    raise LedgerVerificationError(result.status)
                return payload["events"]
            except (ArchiveObjectMissing, ArchiveStoreUnavailable, ArchiveStoreError, LedgerVerificationError) as exc:
                last = exc if isinstance(exc, LedgerVerificationError) else LedgerVerificationError("OBJECT_STORE_UNAVAILABLE")
        if last is not None:
            raise last
        raise LedgerVerificationError("SEGMENT_OBJECT_MISSING")
    try:
        body = store.get(segment.archive_object_key or "")
    except ArchiveObjectMissing as exc:
        raise LedgerVerificationError("SEGMENT_OBJECT_MISSING") from exc
    except ArchiveStoreError as exc:
        raise LedgerVerificationError("OBJECT_STORE_UNAVAILABLE") from exc
    payload, _ = unseal_ledger_segment(object_bytes=body, segment=segment, keyring=keyring, max_object_bytes=settings.archive_max_object_bytes, max_decompressed_bytes=settings.archive_max_decompressed_bytes)
    result = verify_v3_events(tenant_id=segment.tenant_id, trace_id=segment.trace_id, events=payload["events"], settings=settings, expected_start=segment.start_event_sequence, expected_end=segment.end_event_sequence)
    if result.status != "VALID":
        raise LedgerVerificationError(result.status)
    return payload["events"]


def verify_mixed_ledger(db: Session, *, tenant_id: UUID, trace_id: str, store: ArchiveStore | Mapping[str, Any], keyring: Any, settings: Settings | None = None) -> LedgerVerification:
    settings = settings or get_settings()
    segments = list(db.scalars(select(LedgerSegment).join(LedgerSegmentLifecycle).where(
        LedgerSegment.tenant_id == tenant_id, LedgerSegment.trace_id == trace_id, LedgerSegmentLifecycle.status == "COMPACTED",
    ).order_by(LedgerSegment.start_event_sequence)))
    archived: dict[int, Mapping[str, Any]] = {}
    try:
        expected_segment_start = 1
        for segment in segments:
            if segment.start_event_sequence != expected_segment_start or segment.end_event_sequence < segment.start_event_sequence:
                return LedgerVerification("SEGMENT_START_BOUNDARY_INVALID", 0, "segment_range_gap_or_overlap")
            for event in _segment_events(db, segment, store, keyring, settings):
                sequence = int(event["sequence"])
                if sequence in archived:
                    return LedgerVerification("SEGMENT_EVENT_CHAIN_INVALID", 0, "segment_range_overlap")
                archived[int(event["sequence"])] = event
            expected_segment_start = segment.end_event_sequence + 1
    except LedgerVerificationError as exc:
        return LedgerVerification( exc.status, 0, exc.status)
    v19_segments = db.scalar(select(IntegrityArchiveSegment.id).where(
        IntegrityArchiveSegment.tenant_id == tenant_id,
        IntegrityArchiveSegment.trace_id == trace_id,
        IntegrityArchiveSegment.state == "COMPACTED").limit(1))
    if v19_segments is not None:
        try:
            from agentguard_server.services.integrity_segments import resolve_integrity_records
            record_values = resolve_integrity_records(db, tenant_id=tenant_id, trace_id=trace_id, stores=store, keyring=keyring, settings=settings)
        except Exception as exc:
            return LedgerVerification(getattr(exc, "status", None) or "SEGMENT_OBJECT_MISSING", 0, "missing_historical_integrity_record")
        hot_rows = list(db.scalars(select(EventLog).where(EventLog.tenant_id == tenant_id, EventLog.trace_id == trace_id)))
        hot_by_key = {(row.event_type, row.event_id): row for row in hot_rows}
        resolved_events: list[Mapping[str, Any]] = []
        for value in record_values:
            event = archived.get(int(value["sequence"]))
            if event is None:
                row = hot_by_key.get((value["event_type"], value["event_id"]))
                if row is not None:
                    from types import SimpleNamespace
                    projection = dict(value)
                    projection["created_at"] = datetime.fromisoformat(str(value["created_at"]).replace("Z", "+00:00"))
                    event = _event_value(row, SimpleNamespace(**projection))
                else:
                    event = None
            if event is None:
                return LedgerVerification("SEGMENT_OBJECT_MISSING", len(resolved_events), "missing_historical_event")
            for field in ("tenant_id", "trace_id", "sequence", "event_id", "event_type", "event_digest", "previous_chain_mac", "chain_mac", "key_id", "canonicalization_version"):
                if str(event.get(field)) != str(value[field]):
                    return LedgerVerification("SEGMENT_EVENT_CHAIN_INVALID", len(resolved_events), "integrity_record_projection_mismatch")
            resolved_events.append(event)
        return verify_v3_events(tenant_id=tenant_id, trace_id=trace_id, events=resolved_events, settings=settings, expected_start=1, expected_end=int(record_values[-1]["sequence"]))
    records = list(db.scalars(select(IntegrityRecord).where(IntegrityRecord.tenant_id == tenant_id, IntegrityRecord.trace_id == trace_id).order_by(IntegrityRecord.sequence)))
    if not records:
        return LedgerVerification("SEGMENT_EVENT_CHAIN_INVALID", 0, "missing_integrity_record")
    hot_rows = list(db.scalars(select(EventLog).where(EventLog.tenant_id == tenant_id, EventLog.trace_id == trace_id)))
    hot_by_key = {(row.event_type, row.event_id): row for row in hot_rows}
    hot_by_sequence: dict[int, Mapping[str, Any]] = {}
    for record in records:
        row = hot_by_key.get((record.event_type, record.event_id))
        if row is not None:
            hot_by_sequence[record.sequence] = _event_value(row, record)
    resolved = [archived.get(record.sequence) or hot_by_sequence.get(record.sequence) for record in records]
    if any(event is None for event in resolved):
        return LedgerVerification("SEGMENT_OBJECT_MISSING", 0, "missing_historical_event")
    for record, event in zip(records, resolved):
        if (
            str(event["tenant_id"]) != str(record.tenant_id)
            or event["trace_id"] != record.trace_id
            or int(event["sequence"]) != record.sequence
            or str(event["event_id"]) != record.event_id
            or str(event["event_type"]) != record.event_type
            or str(event["event_digest"]) != record.event_digest
            or event.get("previous_chain_mac") != record.previous_chain_mac
            or str(event.get("chain_mac")) != record.chain_mac
            or str(event.get("key_id")) != record.key_id
            or str(event.get("canonicalization_version")) != record.canonicalization_version
        ):
            return LedgerVerification("SEGMENT_EVENT_CHAIN_INVALID", 0, "integrity_record_projection_mismatch")
    return verify_v3_events(tenant_id=tenant_id, trace_id=trace_id, events=[event for event in resolved if event is not None], settings=settings, expected_start=1, expected_end=records[-1].sequence)


def lookup_ledger_event(db: Session, *, tenant_id: UUID, trace_id: str, event_id: str | None = None, event_sequence: int | None = None, store: ArchiveStore | Mapping[str, Any], keyring: Any, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    condition = [LedgerEventArchiveIndex.tenant_id == tenant_id, LedgerEventArchiveIndex.trace_id == trace_id]
    if event_id is not None: condition.append(LedgerEventArchiveIndex.event_id == event_id)
    if event_sequence is not None: condition.append(LedgerEventArchiveIndex.event_sequence == event_sequence)
    row = db.scalar(select(LedgerEventArchiveIndex).where(*condition))
    if row is None:
        raise LookupError("ledger event not found")
    segment = db.get(LedgerSegment, row.segment_id)
    if segment is None: raise LedgerVerificationError("SEGMENT_OBJECT_MISSING")
    for event in _segment_events(db, segment, store, keyring, settings):
        if int(event["sequence"]) == row.event_sequence and event["event_id"] == row.event_id:
            return event
    raise LedgerVerificationError("SEGMENT_EVENT_CHAIN_INVALID")


def queue_ledger_compaction(db: Session, *, segment_id: UUID, tenant_id: UUID) -> LedgerCompactionJob:
    now = database_now(db)
    existing = db.scalar(select(LedgerCompactionJob).where(LedgerCompactionJob.segment_id == segment_id, LedgerCompactionJob.status.in_(["PENDING", "IN_FLIGHT", "RETRY_WAIT"])))
    if existing is not None: return existing
    job = LedgerCompactionJob(tenant_id=tenant_id, segment_id=segment_id, job_type="COMPACT", status="PENDING", attempt_count=0, created_at=now, updated_at=now)
    db.add(job); db.commit(); db.refresh(job); return job


def claim_ledger_compaction_job(db: Session, *, now: datetime | None = None, instance_id: str | None = None, settings: Settings | None = None) -> LedgerCompactionJob | None:
    settings = settings or get_settings(); current = _utc(now) if now else database_now(db); owner = (instance_id or settings.instance_id)[:128]; token = secrets.token_urlsafe(24)
    stmt = update(LedgerCompactionJob).where(
        LedgerCompactionJob.status.in_(["PENDING", "RETRY_WAIT", "IN_FLIGHT"]),
        or_(LedgerCompactionJob.next_attempt_at.is_(None), LedgerCompactionJob.next_attempt_at <= current),
        or_(LedgerCompactionJob.lease_expires_at.is_(None), LedgerCompactionJob.lease_expires_at <= current),
    ).values(status="IN_FLIGHT", claimed_by=owner, claim_token=token, claimed_at=current, lease_expires_at=current + timedelta(seconds=60), attempt_count=LedgerCompactionJob.attempt_count + 1, updated_at=current).returning(LedgerCompactionJob.id)
    claimed = db.execute(stmt).scalar_one_or_none(); db.commit(); return db.get(LedgerCompactionJob, claimed) if claimed else None
