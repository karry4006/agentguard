"""V19 encrypted, verifiable segments for historical V3 integrity records.

The segment catalog is deliberately separate from the V3 hot table.  A segment
is useful only after its bytes, V17 coverage, V15 continuity, and V18 replica
policy have all been verified.  This module keeps those transitions explicit;
callers never provide object-store credentials or arbitrary object keys.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import hmac
import json
import logging
import secrets
from typing import Any, Mapping, Sequence
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import and_, or_, select, text
from sqlalchemy.orm import Session

from agentguard_server.config import Settings, get_settings
from agentguard_server.models import (
    ArchiveReplica, EventLog, IntegrityArchiveSegment, IntegrityChainHead, IntegrityCheckpoint,
    IntegrityCheckpointEntry, IntegrityCompactionAuthorization, IntegrityCompactionJob,
    IntegrityRecord, LedgerSegment, LedgerSegmentLifecycle, RetentionHold,
)
from agentguard_server.services.archive import ArchiveKeyMissing, ArchiveKeyring, _bounded_gunzip
from agentguard_server.services.archive_store import (
    ArchiveObjectConflict, ArchiveObjectMissing, ArchiveStore, ArchiveStoreError,
    ArchiveStoreUnavailable, archive_object_key,
)
from agentguard_server.services.archive_store import ArchiveStoreBinding, archive_store_registry
from agentguard_server.services.anchoring import remote_continuity, verify_checkpoint
from agentguard_server.services.integrity import CANONICALIZATION_VERSION, chain_mac, evidence_digest, canonicalize_evidence
from agentguard_server.services.replicas import (
    INTEGRITY_SEGMENT, ensure_policy, ensure_replica, enqueue_replication_jobs,
    finalize_verified_replica, replica_policy_passes, verified_replica_count,
)
from agentguard_server.services.rate_limit import database_now

logger = logging.getLogger("agentguard.integrity_segments")

INTEGRITY_SEGMENT_VERSION = "integrity-segment-v1"
INTEGRITY_SEGMENT_ENVELOPE_VERSION = "integrity-segment-envelope-v1"
INTEGRITY_SEGMENT_AAD_PURPOSE = "agentguard-integrity-segment-v1"
MAX_SEGMENT_DEPTH = 16


class IntegritySegmentError(ValueError):
    pass


class IntegritySegmentEligibilityError(IntegritySegmentError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class IntegritySegmentVerificationError(IntegritySegmentError):
    def __init__(self, status: str):
        super().__init__(status)
        self.status = status


class IntegritySegmentKeyMissing(IntegritySegmentVerificationError):
    def __init__(self):
        super().__init__("UNVERIFIABLE_V3_KEY_MISSING")


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    return current if current.tzinfo else current.replace(tzinfo=timezone.utc)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _record_value(record: IntegrityRecord) -> dict[str, Any]:
    """The complete immutable V3 record projection, with no ORM metadata."""
    return {
        "id": str(record.id), "tenant_id": str(record.tenant_id), "trace_id": record.trace_id,
        "sequence": int(record.sequence), "event_id": record.event_id, "event_type": record.event_type,
        "event_digest": record.event_digest, "previous_chain_mac": record.previous_chain_mac,
        "chain_mac": record.chain_mac, "key_id": record.key_id,
        "canonicalization_version": record.canonicalization_version,
        "created_at": _utc(record.created_at).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }


def integrity_records_manifest_digest(records: Sequence[Mapping[str, Any] | IntegrityRecord]) -> str:
    values = [item if isinstance(item, Mapping) else _record_value(item) for item in records]
    values.sort(key=lambda item: (int(item["sequence"]), str(item["id"])))
    return _digest(_canonical(values))


def _logical_digest(manifest: Mapping[str, Any], records: Sequence[Mapping[str, Any]]) -> str:
    unsigned = dict(manifest)
    unsigned["logical_segment_digest"] = None
    return _digest(_canonical({"manifest": unsigned, "records": list(records)}))


def integrity_segment_logical_digest(manifest: Mapping[str, Any], records: Sequence[Mapping[str, Any]]) -> str:
    return _logical_digest(manifest, records)


def build_integrity_segment_payload(*, segment_id: UUID, tenant_id: UUID, trace_id: str,
                                    segment_sequence: int, records: Sequence[Mapping[str, Any]],
                                    v17_ledger_segment_id: UUID, v17_ledger_segment_digest: str,
                                    v15_checkpoint_id: UUID, v15_checkpoint_digest: str,
                                    v15_continuity_status: str, predecessor_boundary_hash: str | None,
                                    successor_boundary_hash: str | None) -> tuple[bytes, dict[str, Any]]:
    if not records:
        raise IntegritySegmentEligibilityError("INTEGRITY_SOURCE_EMPTY")
    ordered = sorted((dict(item) for item in records), key=lambda item: (int(item["sequence"]), str(item["id"])))
    start, end = int(ordered[0]["sequence"]), int(ordered[-1]["sequence"])
    if [int(item["sequence"]) for item in ordered] != list(range(start, end + 1)):
        raise IntegritySegmentEligibilityError("INTEGRITY_SEGMENT_GAP")
    manifest: dict[str, Any] = {
        "segment_version": INTEGRITY_SEGMENT_VERSION, "segment_id": str(segment_id),
        "tenant_id": str(tenant_id), "trace_id": trace_id, "segment_sequence": segment_sequence,
        "source_start_sequence": start, "source_end_sequence": end, "record_count": len(ordered),
        "first_record_id": ordered[0]["id"], "last_record_id": ordered[-1]["id"],
        "first_event_hash": ordered[0]["event_digest"], "last_event_hash": ordered[-1]["event_digest"],
        "predecessor_boundary_hash": predecessor_boundary_hash,
        "successor_boundary_hash": successor_boundary_hash,
        "records_manifest_digest": integrity_records_manifest_digest(ordered),
        "v17_ledger_segment_id": str(v17_ledger_segment_id),
        "v17_ledger_segment_digest": v17_ledger_segment_digest,
        "v15_checkpoint_id": str(v15_checkpoint_id), "v15_checkpoint_digest": v15_checkpoint_digest,
        "v15_continuity_status": v15_continuity_status, "logical_segment_digest": None,
    }
    manifest["logical_segment_digest"] = _logical_digest(manifest, ordered)
    return _canonical({"manifest": manifest, "records": ordered}), manifest


def _aad(segment: IntegrityArchiveSegment) -> bytes:
    return _canonical({
        "purpose": INTEGRITY_SEGMENT_AAD_PURPOSE,
        "envelope_version": INTEGRITY_SEGMENT_ENVELOPE_VERSION,
        "segment_version": INTEGRITY_SEGMENT_VERSION,
        "segment_id": str(segment.id), "tenant_id": str(segment.tenant_id),
        "trace_id": segment.trace_id, "segment_sequence": segment.segment_sequence,
    })


def seal_integrity_segment(*, segment: IntegrityArchiveSegment, plaintext: bytes, keyring: ArchiveKeyring) -> bytes:
    compressed = gzip.compress(plaintext, compresslevel=9, mtime=0)
    key_id = keyring.current_key_id
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(keyring.key_for(key_id)).encrypt(nonce, compressed, _aad(segment))
    return _canonical({
        "envelope_version": INTEGRITY_SEGMENT_ENVELOPE_VERSION,
        "segment_version": INTEGRITY_SEGMENT_VERSION, "segment_id": str(segment.id),
        "tenant_id": str(segment.tenant_id), "trace_id": segment.trace_id,
        "segment_sequence": segment.segment_sequence, "key_id": key_id,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "plaintext_sha256": _digest(plaintext), "compressed_sha256": _digest(compressed),
        "ciphertext_sha256": _digest(ciphertext),
    })


def unseal_integrity_segment(*, object_bytes: bytes, segment: IntegrityArchiveSegment,
                             keyring: ArchiveKeyring, max_object_bytes: int = 96 * 1024 * 1024,
                             max_decompressed_bytes: int = 64 * 1024 * 1024) -> tuple[dict[str, Any], bytes]:
    if len(object_bytes) > max_object_bytes:
        raise IntegritySegmentVerificationError("INVALID_INTEGRITY_SEGMENT_ENVELOPE")
    try:
        envelope = json.loads(object_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegritySegmentVerificationError("INVALID_INTEGRITY_SEGMENT_ENVELOPE") from exc
    required = {"envelope_version", "segment_version", "segment_id", "tenant_id", "trace_id", "segment_sequence", "key_id", "nonce", "ciphertext", "plaintext_sha256", "compressed_sha256", "ciphertext_sha256"}
    if not isinstance(envelope, dict) or set(envelope) != required:
        raise IntegritySegmentVerificationError("INVALID_INTEGRITY_SEGMENT_ENVELOPE")
    if (envelope["envelope_version"] != INTEGRITY_SEGMENT_ENVELOPE_VERSION or envelope["segment_version"] != INTEGRITY_SEGMENT_VERSION
            or envelope["segment_id"] != str(segment.id) or envelope["tenant_id"] != str(segment.tenant_id)
            or envelope["trace_id"] != segment.trace_id or envelope["segment_sequence"] != segment.segment_sequence):
        raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_IDENTITY_MISMATCH")
    try:
        nonce = base64.b64decode(str(envelope["nonce"]).encode("ascii"), validate=True)
        ciphertext = base64.b64decode(str(envelope["ciphertext"]).encode("ascii"), validate=True)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise IntegritySegmentVerificationError("INVALID_INTEGRITY_SEGMENT_CIPHERTEXT") from exc
    if len(nonce) != 12 or _digest(ciphertext) != envelope["ciphertext_sha256"]:
        raise IntegritySegmentVerificationError("INVALID_INTEGRITY_SEGMENT_CIPHERTEXT")
    try:
        compressed = AESGCM(keyring.key_for(str(envelope["key_id"]))).decrypt(nonce, ciphertext, _aad(segment))
    except (ArchiveKeyMissing, KeyError) as exc:
        raise IntegritySegmentKeyMissing() from exc
    except (InvalidTag, ValueError) as exc:
        raise IntegritySegmentVerificationError("INVALID_INTEGRITY_SEGMENT_CIPHERTEXT") from exc
    if _digest(compressed) != envelope["compressed_sha256"]:
        raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_DIGEST_MISMATCH")
    try:
        plaintext = _bounded_gunzip(compressed, max_decompressed_bytes)
    except Exception as exc:
        if isinstance(exc, IntegritySegmentVerificationError):
            raise
        raise IntegritySegmentVerificationError("INVALID_INTEGRITY_SEGMENT_ENVELOPE") from exc
    if _digest(plaintext) != envelope["plaintext_sha256"]:
        raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_DIGEST_MISMATCH")
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegritySegmentVerificationError("INVALID_INTEGRITY_SEGMENT_ENVELOPE") from exc
    if not isinstance(payload, dict) or set(payload) != {"manifest", "records"} or not isinstance(payload["manifest"], dict) or not isinstance(payload["records"], list):
        raise IntegritySegmentVerificationError("INVALID_INTEGRITY_SEGMENT_ENVELOPE")
    manifest, records = payload["manifest"], payload["records"]
    if manifest.get("segment_version") != INTEGRITY_SEGMENT_VERSION or manifest.get("segment_id") != str(segment.id) or manifest.get("tenant_id") != str(segment.tenant_id) or manifest.get("trace_id") != segment.trace_id:
        raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_IDENTITY_MISMATCH")
    required_record_keys = {"id", "tenant_id", "trace_id", "sequence", "event_id", "event_type", "event_digest", "previous_chain_mac", "chain_mac", "key_id", "canonicalization_version", "created_at"}
    if any(not isinstance(item, dict) or set(item) != required_record_keys for item in records):
        raise IntegritySegmentVerificationError("INVALID_INTEGRITY_SEGMENT_ENVELOPE")
    try:
        manifest_digest = integrity_records_manifest_digest(records)
        logical_digest = _logical_digest(manifest, records)
    except (KeyError, TypeError, ValueError) as exc:
        raise IntegritySegmentVerificationError("INVALID_INTEGRITY_SEGMENT_ENVELOPE") from exc
    if manifest.get("record_count") != len(records) or manifest.get("records_manifest_digest") != manifest_digest:
        raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_DIGEST_MISMATCH")
    if manifest.get("logical_segment_digest") != logical_digest:
        raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_DIGEST_MISMATCH")
    if segment.logical_segment_digest and not hmac.compare_digest(manifest["logical_segment_digest"], segment.logical_segment_digest):
        raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_DIGEST_MISMATCH")
    if segment.ciphertext_sha256 and envelope["ciphertext_sha256"] != segment.ciphertext_sha256:
        raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_DIGEST_MISMATCH")
    if segment.plaintext_sha256 and envelope["plaintext_sha256"] != segment.plaintext_sha256:
        raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_DIGEST_MISMATCH")
    if segment.archive_key_id and envelope["key_id"] != segment.archive_key_id:
        raise IntegritySegmentKeyMissing()
    return payload, plaintext


def _active_hold(db: Session, tenant_id: UUID, trace_id: str) -> bool:
    return db.scalar(select(RetentionHold.id).where(
        RetentionHold.tenant_id == tenant_id, RetentionHold.released_at.is_(None),
        or_(RetentionHold.subject_type == "TENANT", and_(RetentionHold.subject_type == "TRACE", RetentionHold.trace_id == trace_id)),
    ).limit(1)) is not None


def _v17_coverage(db: Session, tenant_id: UUID, trace_id: str, start: int, end: int) -> LedgerSegment:
    rows = list(db.scalars(select(LedgerSegment).join(LedgerSegmentLifecycle).where(
        LedgerSegment.tenant_id == tenant_id, LedgerSegment.trace_id == trace_id,
        LedgerSegment.start_event_sequence == start, LedgerSegment.end_event_sequence == end,
        LedgerSegmentLifecycle.status == "COMPACTED",
    )))
    if not rows:
        raise IntegritySegmentEligibilityError("V17_SEGMENT_COVERAGE_REQUIRED")
    return rows[0]


def _v15_coverage(db: Session, tenant_id: UUID, trace_id: str, end: int, settings: Settings) -> IntegrityCheckpoint:
    entries = list(db.scalars(select(IntegrityCheckpointEntry).where(
        IntegrityCheckpointEntry.tenant_id == tenant_id, IntegrityCheckpointEntry.trace_id == trace_id,
        IntegrityCheckpointEntry.tenant_chain_sequence >= end,
    ).order_by(IntegrityCheckpointEntry.tenant_chain_sequence)))
    for entry in entries:
        checkpoint = db.get(IntegrityCheckpoint, entry.checkpoint_id)
        if checkpoint and verify_checkpoint(db, checkpoint.id, settings=settings).get("status") == "VALID":
            return checkpoint
    raise IntegritySegmentEligibilityError("V15_COVERAGE_INVALID")


def _source_records(db: Session, tenant_id: UUID, trace_id: str, start: int, end: int) -> list[IntegrityRecord]:
    records = list(db.scalars(select(IntegrityRecord).where(
        IntegrityRecord.tenant_id == tenant_id, IntegrityRecord.trace_id == trace_id,
        IntegrityRecord.sequence.between(start, end),
    ).order_by(IntegrityRecord.sequence)))
    if len(records) != end - start + 1 or any(record.sequence != start + i for i, record in enumerate(records)):
        raise IntegritySegmentEligibilityError("INTEGRITY_SOURCE_CHANGED")
    return records


def create_integrity_segment_candidate(db: Session, *, tenant_id: UUID, trace_id: str,
                                       settings: Settings | None = None, now: datetime | None = None) -> IntegrityArchiveSegment:
    settings = settings or get_settings()
    if not settings.integrity_segment_compaction_enabled:
        raise IntegritySegmentEligibilityError("INTEGRITY_SEGMENT_COMPACTION_DISABLED")
    current = _utc(now)
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": f"agentguard-integrity-segment:{tenant_id}:{trace_id}"})
    existing = db.scalar(select(IntegrityArchiveSegment).where(
        IntegrityArchiveSegment.tenant_id == tenant_id, IntegrityArchiveSegment.trace_id == trace_id,
        IntegrityArchiveSegment.state.in_(("PLANNED", "BUILDING", "ARCHIVED", "VERIFYING", "ARCHIVED_VERIFIED", "REPLICA_POLICY_PENDING", "READY_TO_COMPACT", "COMPACTING")),
    ).order_by(IntegrityArchiveSegment.segment_sequence.desc()).limit(1))
    if existing:
        return existing
    hot = db.scalar(select(IntegrityChainHead).where(IntegrityChainHead.tenant_id == tenant_id, IntegrityChainHead.trace_id == trace_id))
    if hot is None or hot.next_sequence <= settings.integrity_hot_tail_records + 1:
        raise IntegritySegmentEligibilityError("INTEGRITY_HOT_TAIL_PROTECTED")
    v17_rows = list(db.scalars(select(LedgerSegment).join(LedgerSegmentLifecycle).where(
        LedgerSegment.tenant_id == tenant_id, LedgerSegment.trace_id == trace_id,
        LedgerSegmentLifecycle.status == "COMPACTED",
    ).order_by(LedgerSegment.segment_sequence)))
    v17 = next((item for item in v17_rows if db.scalar(select(IntegrityArchiveSegment.id).where(
        IntegrityArchiveSegment.v17_ledger_segment_id == item.id).limit(1)) is None), None)
    if v17 is None:
        raise IntegritySegmentEligibilityError("V17_SEGMENT_COVERAGE_REQUIRED")
    start, end = v17.start_event_sequence, v17.end_event_sequence
    if end >= hot.next_sequence - settings.integrity_hot_tail_records:
        raise IntegritySegmentEligibilityError("INTEGRITY_HOT_TAIL_PROTECTED")
    cutoff = current - timedelta(days=settings.integrity_segment_min_age_days)
    records = _source_records(db, tenant_id, trace_id, start, end)
    if any(_utc(item.created_at) > cutoff for item in records):
        raise IntegritySegmentEligibilityError("INTEGRITY_MIN_AGE_NOT_MET")
    checkpoint = _v15_coverage(db, tenant_id, trace_id, end, settings)
    sequence = (db.scalar(select(IntegrityArchiveSegment.segment_sequence).where(IntegrityArchiveSegment.tenant_id == tenant_id, IntegrityArchiveSegment.trace_id == trace_id).order_by(IntegrityArchiveSegment.segment_sequence.desc()).limit(1)) or 0) + 1
    predecessor = records[0].previous_chain_mac
    successor_row = db.scalar(select(IntegrityRecord).where(IntegrityRecord.tenant_id == tenant_id, IntegrityRecord.trace_id == trace_id, IntegrityRecord.sequence == end + 1))
    if successor_row is None or successor_row.previous_chain_mac != records[-1].chain_mac:
        raise IntegritySegmentEligibilityError("INTEGRITY_SUCCESSOR_BOUNDARY_INVALID")
    values = [_record_value(item) for item in records]
    base = IntegrityArchiveSegment(
        tenant_id=tenant_id, trace_id=trace_id, segment_sequence=sequence,
        segment_version=INTEGRITY_SEGMENT_VERSION, envelope_version=INTEGRITY_SEGMENT_ENVELOPE_VERSION,
        source_start_sequence=start, source_end_sequence=end, record_count=len(records),
        first_record_id=records[0].id, last_record_id=records[-1].id,
        first_event_hash=records[0].event_digest, last_event_hash=records[-1].event_digest,
        predecessor_boundary_hash=predecessor, successor_boundary_hash=successor_row.previous_chain_mac,
        records_manifest_digest=integrity_records_manifest_digest(values), logical_segment_digest="0" * 64,
        v17_ledger_segment_id=v17.id, v17_ledger_segment_digest=v17.segment_manifest_digest,
        v15_checkpoint_id=checkpoint.id, v15_checkpoint_digest=checkpoint.checkpoint_digest,
        v15_continuity_status="MATCH", state="PLANNED", created_at=current, updated_at=current,
    )
    base.archive_logical_id = base.id
    db.add(base); db.flush()
    _, manifest = build_integrity_segment_payload(segment_id=base.id, tenant_id=tenant_id, trace_id=trace_id, segment_sequence=sequence, records=values, v17_ledger_segment_id=v17.id, v17_ledger_segment_digest=v17.segment_manifest_digest, v15_checkpoint_id=checkpoint.id, v15_checkpoint_digest=checkpoint.checkpoint_digest, v15_continuity_status="MATCH", predecessor_boundary_hash=predecessor, successor_boundary_hash=successor_row.previous_chain_mac)
    base.logical_segment_digest = manifest["logical_segment_digest"]
    base.archive_object_key = archive_object_key(tenant_id, base.id).replace("trace-archive-v1/", "agentguard/integrity/v1/", 1).replace(".bin", ".agintegrity")
    db.commit(); db.refresh(base)
    logger.info("integrity_segment_planned tenant_id=%s trace_id=%s segment_id=%s range=%s-%s", tenant_id, trace_id, base.id, start, end)
    return base


def archive_integrity_segment(db: Session, segment_id: UUID, store: ArchiveStore, *, provider: Any,
                              settings: Settings | None = None, keyring: ArchiveKeyring | None = None,
                              now: datetime | None = None) -> IntegrityArchiveSegment:
    settings = settings or get_settings(); segment = db.get(IntegrityArchiveSegment, segment_id)
    if segment is None: raise IntegritySegmentEligibilityError("INTEGRITY_SEGMENT_NOT_FOUND")
    if segment.state not in {"PLANNED", "FAILED"}: raise IntegritySegmentEligibilityError("INTEGRITY_SEGMENT_STATE_INVALID")
    records = _source_records(db, segment.tenant_id, segment.trace_id, segment.source_start_sequence, segment.source_end_sequence)
    if integrity_records_manifest_digest(records) != segment.records_manifest_digest or records[0].id != segment.first_record_id or records[-1].id != segment.last_record_id:
        raise IntegritySegmentEligibilityError("INTEGRITY_SOURCE_CHANGED")
    successor = db.scalar(select(IntegrityRecord).where(
        IntegrityRecord.tenant_id == segment.tenant_id, IntegrityRecord.trace_id == segment.trace_id,
        IntegrityRecord.sequence == segment.source_end_sequence + 1))
    if records[0].previous_chain_mac != segment.predecessor_boundary_hash or successor is None or successor.previous_chain_mac != records[-1].chain_mac or successor.previous_chain_mac != segment.successor_boundary_hash:
        raise IntegritySegmentEligibilityError("INTEGRITY_SUCCESSOR_BOUNDARY_INVALID")
    if _active_hold(db, segment.tenant_id, segment.trace_id): raise IntegritySegmentEligibilityError("RETENTION_HOLD_ACTIVE")
    v17 = db.get(LedgerSegment, segment.v17_ledger_segment_id)
    v17_lifecycle = db.get(LedgerSegmentLifecycle, segment.v17_ledger_segment_id)
    if v17 is None or v17_lifecycle is None or v17_lifecycle.status != "COMPACTED" or v17.segment_manifest_digest != segment.v17_ledger_segment_digest: raise IntegritySegmentEligibilityError("V17_SEGMENT_BINDING_MISMATCH")
    checkpoint = db.get(IntegrityCheckpoint, segment.v15_checkpoint_id)
    if checkpoint is None or checkpoint.checkpoint_digest != segment.v15_checkpoint_digest or verify_checkpoint(db, checkpoint.id, settings=settings).get("status") != "VALID": raise IntegritySegmentEligibilityError("V15_COVERAGE_INVALID")
    continuity = remote_continuity(db, provider, settings=settings)
    if continuity.status != "MATCH": raise IntegritySegmentEligibilityError(f"V15_{continuity.status}")
    values = [_record_value(item) for item in records]
    keyring = keyring or ArchiveKeyring.from_settings(settings)
    # V17 is the payload authority for the event body once its EventLog rows
    # have been compacted.  Re-run the complete V3 event/chain verification
    # and bind every archived event back to the exact hot IntegrityRecord.
    try:
        from agentguard_server.services.ledger import _segment_events, verify_v3_events
        events = _segment_events(db, v17, store, keyring, settings)
        verification = verify_v3_events(tenant_id=segment.tenant_id, trace_id=segment.trace_id,
                                        events=events, settings=settings,
                                        expected_start=segment.source_start_sequence,
                                        expected_end=segment.source_end_sequence)
        if verification.status != "VALID":
            raise IntegritySegmentEligibilityError(verification.status)
        event_by_sequence = {int(item["sequence"]): item for item in events}
        for value in values:
            event = event_by_sequence.get(int(value["sequence"]))
            if event is None or any(str(event.get(field)) != str(value[field]) for field in
                                    ("tenant_id", "trace_id", "sequence", "event_id", "event_type",
                                     "event_digest", "previous_chain_mac", "chain_mac", "key_id",
                                     "canonicalization_version")):
                raise IntegritySegmentEligibilityError("V17_V3_PROJECTION_MISMATCH")
    except IntegritySegmentEligibilityError:
        raise
    except Exception as exc:
        raise IntegritySegmentEligibilityError(getattr(exc, "status", None) or "V17_EVENT_ARCHIVE_UNAVAILABLE") from exc
    plaintext, manifest = build_integrity_segment_payload(segment_id=segment.id, tenant_id=segment.tenant_id, trace_id=segment.trace_id, segment_sequence=segment.segment_sequence, records=values, v17_ledger_segment_id=v17.id, v17_ledger_segment_digest=v17.segment_manifest_digest, v15_checkpoint_id=checkpoint.id, v15_checkpoint_digest=checkpoint.checkpoint_digest, v15_continuity_status=continuity.status, predecessor_boundary_hash=segment.predecessor_boundary_hash, successor_boundary_hash=segment.successor_boundary_hash)
    if len(plaintext) > settings.archive_max_plaintext_bytes: raise IntegritySegmentEligibilityError("ARCHIVE_SIZE_LIMIT")
    segment.state = "ARCHIVED"; segment.updated_at = _utc(now); db.commit()
    object_bytes = seal_integrity_segment(segment=segment, plaintext=plaintext, keyring=keyring)
    try:
        store.put(segment.archive_object_key or "", object_bytes); stored = store.get(segment.archive_object_key or "")
        payload, _ = unseal_integrity_segment(object_bytes=stored, segment=segment, keyring=keyring, max_object_bytes=settings.archive_max_object_bytes, max_decompressed_bytes=settings.archive_max_decompressed_bytes)
    except ArchiveObjectConflict as exc: segment.state, segment.updated_at = "FAILED", _utc(now); db.commit(); raise IntegritySegmentVerificationError("INTEGRITY_OBJECT_CONFLICT") from exc
    except (ArchiveObjectMissing, ArchiveStoreUnavailable, ArchiveStoreError) as exc: segment.state, segment.updated_at = "FAILED", _utc(now); db.commit(); raise IntegritySegmentVerificationError("OBJECT_STORE_UNAVAILABLE") from exc
    except IntegritySegmentVerificationError as exc:
        segment.state, segment.updated_at = "FAILED", _utc(now); db.commit(); raise exc
    segment.records_manifest_digest = manifest["records_manifest_digest"]; segment.logical_segment_digest = manifest["logical_segment_digest"]
    envelope = json.loads(stored.decode("utf-8")); segment.plaintext_sha256 = envelope["plaintext_sha256"]; segment.ciphertext_sha256 = envelope["ciphertext_sha256"]; segment.archive_key_id = envelope["key_id"]
    segment.state, segment.verified_at, segment.updated_at = "ARCHIVED_VERIFIED", _utc(now), _utc(now); db.commit()
    replica = ensure_replica(db, tenant_id=segment.tenant_id, logical_archive_type=INTEGRITY_SEGMENT, logical_archive_id=segment.id, store_id=getattr(store, "store_id", settings.archive_primary_store_id), object_key=segment.archive_object_key or "", expected_ciphertext_sha256=segment.ciphertext_sha256, expected_plaintext_sha256=segment.plaintext_sha256, expected_logical_digest=segment.logical_segment_digest, encryption_key_id=segment.archive_key_id, state="PENDING", now=now)
    finalize_verified_replica(db, replica=replica, verification_status="VALID"); db.commit()
    if settings.archive_replication_enabled: enqueue_replication_jobs(db, tenant_id=segment.tenant_id, logical_archive_type=INTEGRITY_SEGMENT, logical_archive_id=segment.id, settings=settings, now=now)
    logger.info("integrity_segment_archive_verified tenant_id=%s trace_id=%s segment_id=%s replica_store=%s", segment.tenant_id, segment.trace_id, segment.id, getattr(store, "store_id", settings.archive_primary_store_id))
    return db.get(IntegrityArchiveSegment, segment.id) or segment


def authorize_integrity_compaction(db: Session, segment_id: UUID, *, provider: Any, settings: Settings | None = None,
                                   now: datetime | None = None) -> IntegrityCompactionAuthorization:
    settings = settings or get_settings(); segment = db.get(IntegrityArchiveSegment, segment_id)
    if segment is None: raise IntegritySegmentEligibilityError("INTEGRITY_SEGMENT_NOT_FOUND")
    if segment.state == "COMPACTED": raise IntegritySegmentEligibilityError("INTEGRITY_SEGMENT_ALREADY_COMPACTED")
    if segment.state != "ARCHIVED_VERIFIED": raise IntegritySegmentEligibilityError("INTEGRITY_ARCHIVE_NOT_VERIFIED")
    if _active_hold(db, segment.tenant_id, segment.trace_id): raise IntegritySegmentEligibilityError("RETENTION_HOLD_ACTIVE")
    v17 = db.get(LedgerSegment, segment.v17_ledger_segment_id)
    lifecycle = db.get(LedgerSegmentLifecycle, segment.v17_ledger_segment_id)
    if v17 is None or lifecycle is None or lifecycle.status != "COMPACTED" or v17.segment_manifest_digest != segment.v17_ledger_segment_digest:
        raise IntegritySegmentEligibilityError("V17_SEGMENT_BINDING_MISMATCH")
    checkpoint = db.get(IntegrityCheckpoint, segment.v15_checkpoint_id)
    if checkpoint is None or checkpoint.checkpoint_digest != segment.v15_checkpoint_digest or verify_checkpoint(db, checkpoint.id, settings=settings).get("status") != "VALID":
        raise IntegritySegmentEligibilityError("V15_COVERAGE_INVALID")
    v20_result = None
    if getattr(settings, "quorum_enabled", False):
        from agentguard_server.services.quorum import require_fresh_quorum, QuorumError
        try:
            v20_result = require_fresh_quorum(db, checkpoint.id, now=now)
        except QuorumError as exc:
            raise IntegritySegmentEligibilityError(f"V20_{type(exc).__name__}") from exc
    continuity = remote_continuity(db, provider, settings=settings)
    if continuity.status != "MATCH": raise IntegritySegmentEligibilityError(f"V15_{continuity.status}")
    if not replica_policy_passes(db, tenant_id=segment.tenant_id, logical_archive_type=INTEGRITY_SEGMENT, logical_archive_id=segment.id, settings=settings, now=now): raise IntegritySegmentEligibilityError("V18_REPLICA_POLICY_NOT_SATISFIED")
    current = _utc(now); policy = ensure_policy(db, settings=settings, now=now)
    auth = IntegrityCompactionAuthorization(segment_id=segment.id, tenant_id=segment.tenant_id, source_start_sequence=segment.source_start_sequence, source_end_sequence=segment.source_end_sequence, record_count=segment.record_count, logical_segment_digest=segment.logical_segment_digest, ciphertext_sha256=segment.ciphertext_sha256 or "", predecessor_boundary_hash=segment.predecessor_boundary_hash, successor_boundary_hash=segment.successor_boundary_hash, replica_policy_version=policy.policy_version, verified_replica_count=verified_replica_count(db, tenant_id=segment.tenant_id, logical_archive_type=INTEGRITY_SEGMENT, logical_archive_id=segment.id, settings=settings, now=now), v17_ledger_segment_digest=segment.v17_ledger_segment_digest, v15_checkpoint_digest=segment.v15_checkpoint_digest, v15_continuity_status=continuity.status, verified_at=current, expires_at=current + timedelta(seconds=settings.integrity_compaction_authorization_ttl_seconds), authorized_by_instance=settings.instance_id, created_at=current)
    if v20_result is not None:
        auth.v20_policy_epoch = checkpoint.policy_epoch
        auth.v20_quorum_evaluation_digest = v20_result.evaluation_digest
        auth.v20_quorum_state = v20_result.state
        auth.v20_receipt_set_digest = v20_result.receipt_set_digest
        auth.v20_evaluated_at = v20_result.evaluated_at
        auth.v20_fresh_until = v20_result.fresh_until
    db.add(auth); segment.state, segment.updated_at = "READY_TO_COMPACT", current; db.commit(); db.refresh(auth)
    logger.info("integrity_segment_compaction_authorized tenant_id=%s segment_id=%s replica_count=%s", segment.tenant_id, segment.id, auth.verified_replica_count)
    return auth


def compact_integrity_segment(db: Session, segment_id: UUID, *, settings: Settings | None = None,
                              now: datetime | None = None, fault_inject: bool = False,
                              provider: Any | None = None) -> int:
    settings = settings or get_settings(); segment = db.get(IntegrityArchiveSegment, segment_id)
    if segment is None: raise IntegritySegmentEligibilityError("INTEGRITY_SEGMENT_NOT_FOUND")
    if segment.state == "COMPACTED": return 0
    if segment.state != "READY_TO_COMPACT": raise IntegritySegmentEligibilityError("INTEGRITY_COMPACTION_NOT_AUTHORIZED")
    overlap = db.scalar(select(IntegrityArchiveSegment.id).where(
        IntegrityArchiveSegment.tenant_id == segment.tenant_id,
        IntegrityArchiveSegment.trace_id == segment.trace_id,
        IntegrityArchiveSegment.id != segment.id,
        IntegrityArchiveSegment.state.notin_(("FAILED", "BLOCKED")),
        IntegrityArchiveSegment.source_start_sequence <= segment.source_end_sequence,
        IntegrityArchiveSegment.source_end_sequence >= segment.source_start_sequence,
    ).limit(1))
    if overlap is not None:
        raise IntegritySegmentEligibilityError("INTEGRITY_SEGMENT_OVERLAP")
    v17 = db.get(LedgerSegment, segment.v17_ledger_segment_id)
    lifecycle = db.get(LedgerSegmentLifecycle, segment.v17_ledger_segment_id)
    if v17 is None or lifecycle is None or lifecycle.status != "COMPACTED" or v17.segment_manifest_digest != segment.v17_ledger_segment_digest:
        raise IntegritySegmentEligibilityError("V17_SEGMENT_BINDING_MISMATCH")
    checkpoint = db.get(IntegrityCheckpoint, segment.v15_checkpoint_id)
    if checkpoint is None or checkpoint.checkpoint_digest != segment.v15_checkpoint_digest or verify_checkpoint(db, checkpoint.id, settings=settings).get("status") != "VALID":
        raise IntegritySegmentEligibilityError("V15_COVERAGE_INVALID")
    if provider is not None:
        continuity = remote_continuity(db, provider, settings=settings)
        if continuity.status != "MATCH": raise IntegritySegmentEligibilityError(f"V15_{continuity.status}")
    # Authorization is intentionally short-lived, but the archive keyring and
    # object-store state can still change between authorization and the
    # destructive transaction.  Re-authenticate the exact V19 object through
    # the trusted replica fallback immediately before deletion so a missing
    # historical key, tamper, conflict, or lost replica always fails closed.
    read_integrity_segment_with_fallback(
        db, tenant_id=segment.tenant_id, segment_id=segment.id,
        keyring=ArchiveKeyring.from_settings(settings), settings=settings,
    )
    current = _utc(now); auth = db.scalar(select(IntegrityCompactionAuthorization).where(IntegrityCompactionAuthorization.segment_id == segment.id).order_by(IntegrityCompactionAuthorization.created_at.desc()).limit(1))
    if auth is None or auth.expires_at <= current: raise IntegritySegmentEligibilityError("INTEGRITY_COMPACTION_AUTHORIZATION_EXPIRED")
    if getattr(settings, "quorum_enabled", False):
        from agentguard_server.services.quorum import require_fresh_quorum, QuorumError
        try:
            current_quorum = require_fresh_quorum(db, segment.v15_checkpoint_id, now=now)
        except QuorumError as exc:
            raise IntegritySegmentEligibilityError(f"V20_{type(exc).__name__}") from exc
        if auth.v20_policy_epoch != checkpoint.policy_epoch or auth.v20_quorum_evaluation_digest != current_quorum.evaluation_digest:
            raise IntegritySegmentEligibilityError("V20_QUORUM_AUTHORIZATION_BINDING_MISMATCH")
    records = _source_records(db, segment.tenant_id, segment.trace_id, segment.source_start_sequence, segment.source_end_sequence)
    if _active_hold(db, segment.tenant_id, segment.trace_id): raise IntegritySegmentEligibilityError("RETENTION_HOLD_ACTIVE")
    if not replica_policy_passes(db, tenant_id=segment.tenant_id, logical_archive_type=INTEGRITY_SEGMENT, logical_archive_id=segment.id, settings=settings, now=now): raise IntegritySegmentEligibilityError("V18_REPLICA_POLICY_NOT_SATISFIED")
    if (len(records) != auth.record_count or integrity_records_manifest_digest(records) != segment.records_manifest_digest
            or auth.logical_segment_digest != segment.logical_segment_digest
            or auth.ciphertext_sha256 != (segment.ciphertext_sha256 or "")
            or records[0].previous_chain_mac != segment.predecessor_boundary_hash
            or records[-1].chain_mac != segment.successor_boundary_hash):
        raise IntegritySegmentEligibilityError("INTEGRITY_SOURCE_CHANGED")
    successor = db.scalar(select(IntegrityRecord).where(
        IntegrityRecord.tenant_id == segment.tenant_id, IntegrityRecord.trace_id == segment.trace_id,
        IntegrityRecord.sequence == segment.source_end_sequence + 1))
    if successor is None or successor.previous_chain_mac != records[-1].chain_mac or successor.previous_chain_mac != segment.successor_boundary_hash:
        raise IntegritySegmentEligibilityError("INTEGRITY_SUCCESSOR_BOUNDARY_INVALID")
    if fault_inject: raise IntegritySegmentError("INJECTED_COMPACTION_FAILURE")
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        try:
            deleted = int(db.execute(text("SELECT public.compact_verified_integrity_segment_v1(:segment_id, :authorization_id, :expires_at)"), {
                "segment_id": segment.id, "authorization_id": auth.id, "expires_at": auth.expires_at,
            }).scalar_one())
        except Exception as exc:
            db.rollback()
            message = str(exc)
            if "V19_" in message:
                raise IntegritySegmentEligibilityError(message.split("V19_", 1)[1].split("'", 1)[0].join(("V19_", ""))) from exc
            raise
        db.commit()
        logger.info("integrity_segment_compacted tenant_id=%s trace_id=%s segment_id=%s records=%s", segment.tenant_id, segment.trace_id, segment.id, deleted)
        return deleted
    segment.state = "COMPACTING"; db.flush()
    deleted = 0
    for record in records:
        db.delete(record); deleted += 1
    segment.state, segment.compacted_at, segment.updated_at = "COMPACTED", current, current
    db.commit(); logger.info("integrity_segment_compacted tenant_id=%s trace_id=%s segment_id=%s records=%s", segment.tenant_id, segment.trace_id, segment.id, deleted)
    return deleted


def resolve_integrity_records(db: Session, *, tenant_id: UUID, trace_id: str,
                              stores: Mapping[str, ArchiveStoreBinding] | ArchiveStore | None = None,
                              keyring: ArchiveKeyring | None = None,
                              settings: Settings | None = None) -> list[dict[str, Any]]:
    """Resolve one ordered V3 record stream from compacted segments and hot tail.

    The store map is process configuration, never request data.  Every archive
    candidate is authenticated before it contributes a record to the result.
    """
    settings = settings or get_settings()
    keyring = keyring or ArchiveKeyring.from_settings(settings)
    direct_binding = None if stores is None or isinstance(stores, Mapping) else ArchiveStoreBinding("__direct__", stores)
    raw = stores if isinstance(stores, Mapping) else (archive_store_registry(settings) if stores is None else {})
    bindings = {key: value if isinstance(value, ArchiveStoreBinding) else ArchiveStoreBinding(key, value) for key, value in raw.items()}
    resolved: dict[int, dict[str, Any]] = {}
    segments = list(db.scalars(select(IntegrityArchiveSegment).where(
        IntegrityArchiveSegment.tenant_id == tenant_id, IntegrityArchiveSegment.trace_id == trace_id,
        IntegrityArchiveSegment.state == "COMPACTED",
    ).order_by(IntegrityArchiveSegment.source_start_sequence)))
    for segment in segments:
        candidates = list(db.scalars(select(ArchiveReplica).where(
            ArchiveReplica.tenant_id == tenant_id,
            ArchiveReplica.logical_archive_type == INTEGRITY_SEGMENT,
            ArchiveReplica.logical_archive_id == segment.id,
            ArchiveReplica.state == "VALID",
        )))
        replica_now = database_now(db)
        candidates = [row for row in candidates if row.verified_at is not None and _utc(row.verified_at) >= replica_now - timedelta(seconds=settings.archive_replica_verification_max_age_seconds)]
        candidates.sort(key=lambda row: (bindings.get(row.store_id).priority if row.store_id in bindings else 0 if direct_binding else 10_000, row.store_id))
        last: Exception | None = None
        for replica in candidates:
            binding = bindings.get(replica.store_id) or direct_binding
            if binding is None or not binding.read_enabled:
                continue
            try:
                body = binding.store.get(replica.object_key)
                payload, _ = unseal_integrity_segment(object_bytes=body, segment=segment, keyring=keyring,
                                                      max_object_bytes=settings.archive_max_object_bytes,
                                                      max_decompressed_bytes=settings.archive_max_decompressed_bytes)
                if payload["manifest"]["logical_segment_digest"] != replica.expected_logical_digest:
                    raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_DIGEST_MISMATCH")
                for item in payload["records"]:
                    sequence = int(item["sequence"])
                    if sequence in resolved:
                        raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_OVERLAP")
                    resolved[sequence] = item
                break
            except (ArchiveObjectMissing, ArchiveStoreError, IntegritySegmentVerificationError) as exc:
                last = exc
        else:
            raise IntegritySegmentVerificationError(getattr(last, "status", None) or "INTEGRITY_SEGMENT_OBJECT_MISSING")
    hot = list(db.scalars(select(IntegrityRecord).where(
        IntegrityRecord.tenant_id == tenant_id, IntegrityRecord.trace_id == trace_id,
    ).order_by(IntegrityRecord.sequence)))
    for record in hot:
        if record.sequence in resolved:
            raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_OVERLAP")
        resolved[record.sequence] = _record_value(record)
    if not resolved:
        raise IntegritySegmentVerificationError("missing_integrity_record")
    ordered = [resolved[key] for key in sorted(resolved)]
    if [int(item["sequence"]) for item in ordered] != list(range(1, len(ordered) + 1)):
        raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_RANGE_GAP")
    return ordered


def read_integrity_segment_with_fallback(db: Session, *, tenant_id: UUID, segment_id: UUID,
                                         stores: Mapping[str, ArchiveStoreBinding] | ArchiveStore | None = None,
                                         keyring: ArchiveKeyring | None = None,
                                         settings: Settings | None = None) -> tuple[dict[str, Any], ArchiveReplica]:
    """Read a V19 object through the trusted V18 replica order."""
    settings = settings or get_settings(); segment = db.scalar(select(IntegrityArchiveSegment).where(
        IntegrityArchiveSegment.id == segment_id, IntegrityArchiveSegment.tenant_id == tenant_id))
    if segment is None:
        raise IntegritySegmentVerificationError("INTEGRITY_SEGMENT_NOT_FOUND")
    direct_binding = None if stores is None or isinstance(stores, Mapping) else ArchiveStoreBinding("__direct__", stores)
    raw = stores if isinstance(stores, Mapping) else (archive_store_registry(settings) if stores is None else {})
    bindings = {key: value if isinstance(value, ArchiveStoreBinding) else ArchiveStoreBinding(key, value) for key, value in raw.items()}
    replicas = list(db.scalars(select(ArchiveReplica).where(
        ArchiveReplica.tenant_id == tenant_id, ArchiveReplica.logical_archive_type == INTEGRITY_SEGMENT,
        ArchiveReplica.logical_archive_id == segment.id, ArchiveReplica.state == "VALID")))
    replica_now = database_now(db)
    replicas = [row for row in replicas if row.verified_at is not None and _utc(row.verified_at) >= replica_now - timedelta(seconds=settings.archive_replica_verification_max_age_seconds)]
    replicas.sort(key=lambda row: (bindings.get(row.store_id).priority if row.store_id in bindings else 0 if direct_binding else 10_000, row.store_id))
    last: Exception | None = None
    for replica in replicas:
        binding = bindings.get(replica.store_id) or direct_binding
        if binding is None or not binding.read_enabled:
            continue
        try:
            payload, _ = unseal_integrity_segment(object_bytes=binding.store.get(replica.object_key), segment=segment,
                                                  keyring=keyring or ArchiveKeyring.from_settings(settings),
                                                  max_object_bytes=settings.archive_max_object_bytes,
                                                  max_decompressed_bytes=settings.archive_max_decompressed_bytes)
            return payload, replica
        except (ArchiveObjectMissing, ArchiveStoreError, IntegritySegmentVerificationError) as exc:
            last = exc
    raise IntegritySegmentVerificationError(getattr(last, "status", None) or "INTEGRITY_SEGMENT_OBJECT_MISSING")


def queue_integrity_compaction(db: Session, *, tenant_id: UUID, segment_id: UUID, now: datetime | None = None) -> IntegrityCompactionJob:
    current = _utc(now)
    segment = db.get(IntegrityArchiveSegment, segment_id)
    if segment is None or segment.tenant_id != tenant_id:
        raise IntegritySegmentEligibilityError("INTEGRITY_SEGMENT_NOT_FOUND")
    existing = db.scalar(select(IntegrityCompactionJob).where(IntegrityCompactionJob.segment_id == segment_id, IntegrityCompactionJob.status.in_(("PENDING", "IN_FLIGHT", "RETRY_WAIT", "SUCCEEDED"))).order_by(IntegrityCompactionJob.created_at.desc()).limit(1))
    if existing: return existing
    job = IntegrityCompactionJob(tenant_id=tenant_id, segment_id=segment_id, status="PENDING", next_attempt_at=current, created_at=current, updated_at=current)
    db.add(job); db.commit(); db.refresh(job); return job


def claim_integrity_compaction_job(db: Session, *, settings: Settings | None = None,
                                   instance_id: str | None = None, now: datetime | None = None) -> IntegrityCompactionJob | None:
    settings = settings or get_settings(); current = _utc(now); owner = (instance_id or settings.instance_id)[:128]
    row = db.scalar(select(IntegrityCompactionJob).where(
        IntegrityCompactionJob.status.in_(("PENDING", "RETRY_WAIT", "IN_FLIGHT")),
        or_(IntegrityCompactionJob.next_attempt_at.is_(None), IntegrityCompactionJob.next_attempt_at <= current),
        or_(IntegrityCompactionJob.lease_expires_at.is_(None), IntegrityCompactionJob.lease_expires_at <= current),
    ).order_by(IntegrityCompactionJob.created_at).limit(1).with_for_update(skip_locked=True))
    if row is None:
        db.rollback(); return None
    row.status, row.claimed_by, row.claim_token = "IN_FLIGHT", owner, secrets.token_urlsafe(24)
    row.claimed_at, row.lease_expires_at = current, current + timedelta(seconds=settings.archive_replica_lease_seconds)
    row.attempt_count += 1; row.updated_at = current; db.commit(); db.refresh(row); return row


def process_integrity_compaction_job(db: Session, *, job: IntegrityCompactionJob | None = None,
                                     settings: Settings | None = None, now: datetime | None = None) -> bool:
    settings = settings or get_settings(); job = job or claim_integrity_compaction_job(db, settings=settings, now=now)
    if job is None: return False
    current = _utc(now); segment = db.get(IntegrityArchiveSegment, job.segment_id)
    try:
        if segment is None: raise IntegritySegmentEligibilityError("INTEGRITY_SEGMENT_NOT_FOUND")
        bindings = archive_store_registry(settings); primary = bindings.get(settings.archive_primary_store_id)
        if primary is None: raise IntegritySegmentEligibilityError("STORE_NOT_CONFIGURED")
        provider = __import__("agentguard_server.services.anchoring", fromlist=["HttpSignedWitnessProvider"]).HttpSignedWitnessProvider(settings)
        keyring = ArchiveKeyring.from_settings(settings)
        if segment.state in {"PLANNED", "FAILED"}:
            archive_integrity_segment(db, segment.id, primary.store, provider=provider, settings=settings, keyring=keyring, now=current)
        segment = db.get(IntegrityArchiveSegment, job.segment_id)
        if segment is None: raise IntegritySegmentEligibilityError("INTEGRITY_SEGMENT_NOT_FOUND")
        if segment.state != "READY_TO_COMPACT":
            authorize_integrity_compaction(db, segment.id, provider=provider, settings=settings, now=current)
        compact_integrity_segment(db, segment.id, settings=settings, now=current, provider=provider)
        job.status, job.last_error_category = "SUCCEEDED", None
    except Exception as exc:
        db.rollback(); job = db.get(IntegrityCompactionJob, job.id)
        if job is not None:
            job.status = "RETRY_WAIT" if isinstance(exc, (ArchiveStoreUnavailable, ArchiveObjectMissing)) and job.attempt_count < settings.integrity_compaction_retry_max_attempts else "FAILED"
            job.last_error_category = getattr(exc, "status", None) or getattr(exc, "reason", None) or type(exc).__name__
            job.next_attempt_at = current + timedelta(seconds=min(settings.integrity_compaction_retry_max_seconds, settings.integrity_compaction_retry_base_seconds * 2 ** min(job.attempt_count, 10))) if job.status == "RETRY_WAIT" else None
            job.claimed_by = job.claim_token = job.claimed_at = job.lease_expires_at = None; job.updated_at = current; db.commit()
        return False
    job.claimed_by = job.claim_token = job.claimed_at = job.lease_expires_at = None; job.updated_at = current; db.commit(); return True
