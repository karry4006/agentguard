"""V18 multi-replica verification, fallback, repair, and scrubbing.

This module is intentionally data-driven only for status display.  Store
bindings, policy, and credentials come from trusted process configuration or
the operator-managed database registry; archive contents never select either.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import secrets
from typing import Any, Mapping
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from agentguard_server.config import Settings, get_settings
from agentguard_server.models import (
    ArchiveRecord, ArchiveReplica, ArchiveReplicaPolicy, ArchiveReplicationJob,
    ArchiveScrubRun, ArchiveStore as ArchiveStoreRecord, LedgerSegment,
)
from agentguard_server.services.archive import ArchiveKeyMissing, ArchiveKeyring, ArchiveVerificationError, unseal_archive
from agentguard_server.services.archive_store import (
    ArchiveObjectConflict, ArchiveObjectMissing, ArchiveStore, ArchiveStoreBinding,
    ArchiveStoreError, ArchiveStoreUnavailable, archive_store_registry,
)
from agentguard_server.services.rate_limit import database_now

logger = logging.getLogger("agentguard.replica")

POLICY_VERSION = "archive-replica-policy-v1"
RECORD_VERSION = "archive-replica-record-v1"
SCRUB_VERSION = "archive-scrub-result-v1"
REPAIR_VERSION = "replica-repair-v1"
TRACE_ARCHIVE = "TRACE_ARCHIVE"
LEDGER_SEGMENT = "LEDGER_SEGMENT"
INTEGRITY_SEGMENT = "INTEGRITY_SEGMENT"
OPEN_JOB_STATUSES = ("PENDING", "RETRY_WAIT", "IN_FLIGHT")
VALID_STATES = frozenset({"VALID"})


class ReplicaError(RuntimeError):
    def __init__(self, status: str):
        super().__init__(status)
        self.status = status


class ReplicaUnavailable(ReplicaError):
    pass


@dataclass(frozen=True)
class ReplicaVerification:
    replica_id: UUID
    state: str
    status: str
    verified_at: datetime | None


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    return current if current.tzinfo else current.replace(tzinfo=timezone.utc)


def _db_now(db: Session, value: datetime | None = None) -> datetime:
    return _utc(value) if value is not None else database_now(db)


def _json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []
    return [item for item in parsed if isinstance(item, str)] if isinstance(parsed, list) else []


def _binding(store_id: str, stores: Mapping[str, ArchiveStoreBinding] | None = None, settings: Settings | None = None) -> ArchiveStoreBinding:
    raw = stores if stores is not None else archive_store_registry(settings)
    values = {key: value if isinstance(value, ArchiveStoreBinding) else ArchiveStoreBinding(key, value) for key, value in raw.items()}
    binding = values.get(store_id)
    if binding is None or not binding.read_enabled:
        raise ReplicaError("STORE_NOT_CONFIGURED")
    return binding


def _archive_metadata(db: Session, archive_type: str, archive_id: UUID) -> tuple[UUID, str, str, str, str, str]:
    if archive_type == TRACE_ARCHIVE:
        row = db.get(ArchiveRecord, archive_id)
        if row is None:
            raise ReplicaError("ARCHIVE_NOT_FOUND")
        if not row.ciphertext_sha256 or not row.plaintext_sha256:
            raise ReplicaError("ARCHIVE_DIGEST_MISSING")
        return row.tenant_id, row.object_key, row.ciphertext_sha256, row.plaintext_sha256, row.source_projection_digest or "", row.archive_encryption_key_id
    if archive_type == LEDGER_SEGMENT:
        row = db.get(LedgerSegment, archive_id)
        if row is None:
            raise ReplicaError("SEGMENT_NOT_FOUND")
        if not row.archive_ciphertext_sha256 or not row.archive_plaintext_sha256:
            raise ReplicaError("ARCHIVE_DIGEST_MISSING")
        return row.tenant_id, row.archive_object_key or "", row.archive_ciphertext_sha256, row.archive_plaintext_sha256, row.segment_manifest_digest, row.archive_encryption_key_id or ""
    if archive_type == INTEGRITY_SEGMENT:
        from agentguard_server.models import IntegrityArchiveSegment
        row = db.get(IntegrityArchiveSegment, archive_id)
        if row is None:
            raise ReplicaError("INTEGRITY_SEGMENT_NOT_FOUND")
        if not row.ciphertext_sha256 or not row.plaintext_sha256:
            raise ReplicaError("ARCHIVE_DIGEST_MISSING")
        return row.tenant_id, row.archive_object_key or "", row.ciphertext_sha256, row.plaintext_sha256, row.logical_segment_digest, row.archive_key_id or ""
    raise ReplicaError("UNSUPPORTED_ARCHIVE_TYPE")


def ensure_replica(
    db: Session, *, tenant_id: UUID, logical_archive_type: str, logical_archive_id: UUID,
    store_id: str, object_key: str, expected_ciphertext_sha256: str,
    expected_plaintext_sha256: str | None, expected_logical_digest: str,
    encryption_key_id: str, state: str = "PENDING", now: datetime | None = None,
) -> ArchiveReplica:
    if state == "VALID":
        # VALID is an attested state, not an object-catalog hint.  Callers
        # must first perform full deterministic verification and then use the
        # centralized finalizer below.
        raise ReplicaError("VALID_REPLICA_REQUIRES_VERIFICATION")
    if not store_id or store_id.strip() != store_id or len(store_id) > 128:
        raise ReplicaError("INVALID_STORE_ID")
    current = _db_now(db, now)
    row = db.scalar(select(ArchiveReplica).where(
        ArchiveReplica.logical_archive_type == logical_archive_type,
        ArchiveReplica.logical_archive_id == logical_archive_id,
        ArchiveReplica.store_id == store_id,
    ))
    if row is None:
        row = ArchiveReplica(
            tenant_id=tenant_id, logical_archive_type=logical_archive_type,
            logical_archive_id=logical_archive_id, store_id=store_id,
            object_key=object_key, expected_ciphertext_sha256=expected_ciphertext_sha256,
            expected_plaintext_sha256=expected_plaintext_sha256,
            expected_logical_digest=expected_logical_digest,
            encryption_key_id=encryption_key_id, state=state, created_at=current, updated_at=current,
        )
        db.add(row)
    else:
        # These are immutable artifact identity fields.  A changed value is a
        # conflict, never a catalog update that could hide tampering.
        identity = (row.tenant_id, row.object_key, row.expected_ciphertext_sha256, row.expected_plaintext_sha256, row.expected_logical_digest, row.encryption_key_id)
        expected = (tenant_id, object_key, expected_ciphertext_sha256, expected_plaintext_sha256, expected_logical_digest, encryption_key_id)
        if identity != expected:
            row.state = "CONFLICT"
            row.last_error_category = "REPLICA_METADATA_CONFLICT"
        row.updated_at = current
    db.flush()
    return row


def finalize_verified_replica(
    db: Session, *, replica: ArchiveReplica, verification_status: str,
) -> ArchiveReplica:
    """Atomically persist a successful full replica verification.

    The caller supplies only the result of a completed deterministic
    verification (currently the ``VALID`` result from ``_verify_body``).
    The timestamp is deliberately obtained from the database so distributed
    workers do not make validity depend on host clocks.
    """
    if verification_status != "VALID":
        raise ReplicaError("VALID_REPLICA_REQUIRES_VERIFICATION")
    current = database_now(db)
    replica.state = "VALID"
    replica.last_error_category = None
    replica.verified_at = current
    replica.updated_at = current
    db.flush()
    return replica


def ensure_policy(db: Session, *, settings: Settings | None = None, now: datetime | None = None) -> ArchiveReplicaPolicy:
    settings = settings or get_settings(); current = _db_now(db, now)
    row = db.scalar(select(ArchiveReplicaPolicy).where(ArchiveReplicaPolicy.policy_version == settings.archive_replica_policy_version))
    registry = archive_store_registry(settings)
    ordered = [key for key, _ in sorted(registry.items(), key=lambda item: (item[1].priority, item[0]))]
    if row is None:
        row = ArchiveReplicaPolicy(
            policy_version=settings.archive_replica_policy_version,
            minimum_verified_replicas=settings.archive_minimum_verified_replicas,
            repair_missing_replicas=settings.archive_replica_repair_enabled,
            scrub_interval_seconds=settings.archive_replica_scrub_interval_seconds,
            max_replication_attempts=settings.archive_replica_max_attempts,
            write_targets=json.dumps(ordered, separators=(",", ":")),
            read_order=json.dumps(ordered, separators=(",", ":")),
            created_at=current, updated_at=current,
        )
        db.add(row); db.commit(); db.refresh(row)
    return row


def register_archive_store(db: Session, *, store_id: str, provider_type: str, display_name: str | None = None,
                           enabled: bool = True, read_enabled: bool = True, write_enabled: bool = True,
                           replication_enabled: bool = True, scrub_enabled: bool = True, priority: int = 100,
                           now: datetime | None = None) -> ArchiveStoreRecord:
    """Persist non-secret operator metadata for a trusted store.

    Endpoint, bucket, credential reference, and credential values are
    intentionally not accepted by this function.  They belong to process
    configuration and are resolved by :func:`archive_store_registry`.
    """
    if (not isinstance(store_id, str) or not store_id or len(store_id) > 128
            or any(ch.isspace() for ch in store_id) or not isinstance(provider_type, str)
            or not provider_type or len(provider_type) > 32 or priority < 0):
        raise ReplicaError("INVALID_STORE_REGISTRY_ENTRY")
    current = _db_now(db, now)
    row = db.scalar(select(ArchiveStoreRecord).where(ArchiveStoreRecord.store_id == store_id))
    if row is None:
        row = ArchiveStoreRecord(store_id=store_id, provider_type=provider_type, display_name=display_name,
                                 enabled=enabled, read_enabled=read_enabled, write_enabled=write_enabled,
                                 replication_enabled=replication_enabled, scrub_enabled=scrub_enabled,
                                 priority=priority, created_at=current, updated_at=current)
        db.add(row)
    else:
        row.provider_type = provider_type; row.display_name = display_name
        row.enabled = enabled; row.read_enabled = read_enabled; row.write_enabled = write_enabled
        row.replication_enabled = replication_enabled; row.scrub_enabled = scrub_enabled
        row.priority = priority; row.updated_at = current
    db.commit(); db.refresh(row); return row


def _is_current(row: ArchiveReplica, now: datetime, settings: Settings) -> bool:
    return row.state == "VALID" and row.verified_at is not None and _utc(row.verified_at) >= now - timedelta(seconds=settings.archive_replica_verification_max_age_seconds)


def list_replicas(db: Session, *, tenant_id: UUID, logical_archive_type: str | None = None, logical_archive_id: UUID | None = None) -> list[ArchiveReplica]:
    conditions = [ArchiveReplica.tenant_id == tenant_id]
    if logical_archive_type is not None: conditions.append(ArchiveReplica.logical_archive_type == logical_archive_type)
    if logical_archive_id is not None: conditions.append(ArchiveReplica.logical_archive_id == logical_archive_id)
    return list(db.scalars(select(ArchiveReplica).where(*conditions).order_by(ArchiveReplica.logical_archive_id, ArchiveReplica.store_id)))


def verified_replica_count(db: Session, *, tenant_id: UUID, logical_archive_type: str, logical_archive_id: UUID, settings: Settings | None = None, now: datetime | None = None) -> int:
    settings = settings or get_settings(); current = _db_now(db, now)
    return sum(_is_current(row, current, settings) for row in list_replicas(db, tenant_id=tenant_id, logical_archive_type=logical_archive_type, logical_archive_id=logical_archive_id))


def replica_policy_passes(db: Session, *, tenant_id: UUID, logical_archive_type: str, logical_archive_id: UUID, settings: Settings | None = None, now: datetime | None = None) -> bool:
    settings = settings or get_settings()
    current = _db_now(db, now)
    count = verified_replica_count(db, tenant_id=tenant_id, logical_archive_type=logical_archive_type, logical_archive_id=logical_archive_id, settings=settings, now=now)
    policy = ensure_policy(db, settings=settings, now=now)
    required = max(settings.archive_minimum_verified_replicas, policy.minimum_verified_replicas)
    rows = list_replicas(db, tenant_id=tenant_id, logical_archive_type=logical_archive_type, logical_archive_id=logical_archive_id)
    required_ids = set(_json_list(policy.required_store_ids))
    valid_ids = {row.store_id for row in rows if _is_current(row, current, settings)}
    return count >= required and required_ids <= valid_ids


def logical_archive_health(db: Session, *, tenant_id: UUID, logical_archive_type: str, logical_archive_id: UUID, settings: Settings | None = None, now: datetime | None = None) -> dict[str, Any]:
    settings = settings or get_settings(); current = _db_now(db, now)
    rows = list_replicas(db, tenant_id=tenant_id, logical_archive_type=logical_archive_type, logical_archive_id=logical_archive_id)
    valid = sum(_is_current(row, current, settings) for row in rows)
    states = {row.state for row in rows}
    policy = db.scalar(select(ArchiveReplicaPolicy).where(ArchiveReplicaPolicy.policy_version == settings.archive_replica_policy_version))
    required = max(settings.archive_minimum_verified_replicas, policy.minimum_verified_replicas if policy else 1)
    if not rows or valid == 0:
        health = "UNAVAILABLE"
    elif "CONFLICT" in states:
        health = "CONFLICT"
    elif "CORRUPT" in states or "UNVERIFIABLE_KEY_MISSING" in states:
        health = "DEGRADED"
    elif valid < required:
        health = "UNDER_REPLICATED"
    elif len(states - {"VALID"}) == 0:
        health = "HEALTHY"
    else:
        health = "DEGRADED"
    return {"logical_archive_type": logical_archive_type, "logical_archive_id": str(logical_archive_id), "health": health, "verified_replica_count": valid, "required_verified_replicas": required, "states": {state: sum(row.state == state for row in rows) for state in sorted(states)}}


def _verify_body(db: Session, row: ArchiveReplica, body: bytes, keyring: ArchiveKeyring, settings: Settings) -> str:
    if row.logical_archive_type == TRACE_ARCHIVE:
        record = db.get(ArchiveRecord, row.logical_archive_id)
        if record is None: raise ReplicaError("ARCHIVE_NOT_FOUND")
        verified = unseal_archive(object_bytes=body, archive_id=record.id, tenant_id=record.tenant_id, trace_id=record.trace_id, keyring=keyring, max_object_bytes=settings.archive_max_object_bytes, max_decompressed_bytes=settings.archive_max_decompressed_bytes)
        if verified.envelope["ciphertext_sha256"] != row.expected_ciphertext_sha256 or verified.envelope["plaintext_sha256"] != row.expected_plaintext_sha256 or verified.payload["manifest"].get("source_projection_digest") != row.expected_logical_digest:
            raise ReplicaError("REPLICA_DIGEST_MISMATCH")
    elif row.logical_archive_type == LEDGER_SEGMENT:
        segment = db.get(LedgerSegment, row.logical_archive_id)
        if segment is None: raise ReplicaError("SEGMENT_NOT_FOUND")
        # Import lazily to avoid archive/ledger module import cycles.
        from agentguard_server.services.ledger import unseal_ledger_segment, verify_v3_events
        payload, _ = unseal_ledger_segment(object_bytes=body, segment=segment, keyring=keyring, max_object_bytes=settings.archive_max_object_bytes, max_decompressed_bytes=settings.archive_max_decompressed_bytes)
        verification = verify_v3_events(tenant_id=segment.tenant_id, trace_id=segment.trace_id, events=payload["events"], settings=settings, expected_start=segment.start_event_sequence, expected_end=segment.end_event_sequence)
        if verification.status != "VALID": raise ReplicaError(verification.status)
        if payload["manifest"].get("segment_manifest_digest") != row.expected_logical_digest:
            raise ReplicaError("SEGMENT_DIGEST_MISMATCH")
    elif row.logical_archive_type == INTEGRITY_SEGMENT:
        from agentguard_server.models import IntegrityArchiveSegment
        from agentguard_server.services.integrity_segments import unseal_integrity_segment
        segment = db.get(IntegrityArchiveSegment, row.logical_archive_id)
        if segment is None:
            raise ReplicaError("INTEGRITY_SEGMENT_NOT_FOUND")
        payload, _ = unseal_integrity_segment(object_bytes=body, segment=segment, keyring=keyring,
                                              max_object_bytes=settings.archive_max_object_bytes,
                                              max_decompressed_bytes=settings.archive_max_decompressed_bytes)
        if payload["manifest"].get("logical_segment_digest") != row.expected_logical_digest:
            raise ReplicaError("INTEGRITY_SEGMENT_DIGEST_MISMATCH")
    else:
        raise ReplicaError("UNSUPPORTED_ARCHIVE_TYPE")
    actual = hashlib.sha256(body).hexdigest()
    # The envelope's authenticated ciphertext digest is the canonical V16/V17
    # identity.  Full-object hashing is retained for diagnostics only.
    logger.debug("replica_full_verification_complete replica_id=%s object_sha256=%s", row.id, actual)
    return "VALID"


def verify_replica(db: Session, replica_id: UUID, *, store: ArchiveStore | None = None, stores: Mapping[str, ArchiveStoreBinding] | None = None, keyring: ArchiveKeyring | None = None, settings: Settings | None = None, now: datetime | None = None, commit: bool = True) -> ReplicaVerification:
    settings = settings or get_settings(); row = db.get(ArchiveReplica, replica_id)
    if row is None: raise ReplicaError("REPLICA_NOT_FOUND")
    binding = _binding(row.store_id, stores, settings) if store is None else ArchiveStoreBinding(row.store_id, store)
    current = _db_now(db, now); row.state = "VERIFYING"; row.updated_at = current
    try:
        body = binding.store.get(row.object_key)
        if keyring is None: keyring = ArchiveKeyring.from_settings(settings)
        verification_status = _verify_body(db, row, body, keyring, settings)
        finalize_verified_replica(db, replica=row, verification_status=verification_status)
        result = "VALID"
    except ArchiveObjectMissing:
        row.state, row.last_error_category = "MISSING", "ARCHIVE_OBJECT_MISSING"; result = "MISSING"
    except ArchiveStoreUnavailable:
        row.state, row.last_error_category = "UNAVAILABLE", "OBJECT_STORE_UNAVAILABLE"; result = "UNAVAILABLE"
    except ArchiveKeyMissing:
        row.state, row.last_error_category = "UNVERIFIABLE_KEY_MISSING", "UNVERIFIABLE_KEY_MISSING"; result = "UNVERIFIABLE_KEY_MISSING"
    except ReplicaError as exc:
        row.state, row.last_error_category = ("CONFLICT" if "IDENTITY" in exc.status or "CONFLICT" in exc.status else "CORRUPT"), exc.status; result = exc.status
    except ArchiveVerificationError as exc:
        row.state, row.last_error_category = ("CONFLICT" if "IDENTITY" in exc.status else "CORRUPT"), exc.status; result = exc.status
    except ArchiveStoreError:
        row.state, row.last_error_category, result = "UNAVAILABLE", "OBJECT_STORE_ERROR", "UNAVAILABLE"
    except Exception as exc:
        # Ledger verification uses its own error class.  Preserve its
        # fail-closed status without allowing provider or parser exceptions to
        # escape as an untracked VALID state.
        category = getattr(exc, "status", None) or type(exc).__name__
        if category == "UNVERIFIABLE_ARCHIVE_KEY_MISSING":
            row.state, row.last_error_category, result = "UNVERIFIABLE_KEY_MISSING", category, "UNVERIFIABLE_KEY_MISSING"
        else:
            row.state, row.last_error_category, result = ("CONFLICT" if "IDENTITY" in category else "CORRUPT"), category, category
    row.updated_at = current
    if commit: db.commit()
    return ReplicaVerification(row.id, row.state, result, row.verified_at)


def _target_object_conflict(target: ArchiveStore, object_key: str, expected: str) -> bool:
    try:
        body = target.get(object_key)
    except ArchiveObjectMissing:
        return False
    except ArchiveStoreError:
        raise
    try:
        envelope = json.loads(body.decode("utf-8"))
        return not isinstance(envelope, dict) or envelope.get("ciphertext_sha256") != expected
    except (UnicodeDecodeError, json.JSONDecodeError):
        return True


def queue_replication_job(db: Session, *, tenant_id: UUID, logical_archive_type: str, logical_archive_id: UUID, source_store_id: str, target_store_id: str, now: datetime | None = None) -> ArchiveReplicationJob:
    if source_store_id == target_store_id: raise ReplicaError("REPLICATION_SOURCE_TARGET_SAME")
    existing = db.scalar(select(ArchiveReplicationJob).where(
        ArchiveReplicationJob.logical_archive_type == logical_archive_type, ArchiveReplicationJob.logical_archive_id == logical_archive_id,
        ArchiveReplicationJob.target_store_id == target_store_id, ArchiveReplicationJob.status.in_(OPEN_JOB_STATUSES),
    ).order_by(ArchiveReplicationJob.created_at.desc()).limit(1))
    if existing: return existing
    current = _utc(now)
    job = ArchiveReplicationJob(tenant_id=tenant_id, logical_archive_type=logical_archive_type, logical_archive_id=logical_archive_id, source_store_id=source_store_id, target_store_id=target_store_id, status="PENDING", next_attempt_at=current, created_at=current, updated_at=current)
    db.add(job); db.commit(); db.refresh(job); return job


def enqueue_replication_jobs(db: Session, *, tenant_id: UUID, logical_archive_type: str, logical_archive_id: UUID, settings: Settings | None = None, now: datetime | None = None) -> list[ArchiveReplicationJob]:
    """Create bounded durable jobs for trusted configured write targets."""
    settings = settings or get_settings()
    current = _db_now(db, now)
    if not settings.archive_replication_enabled:
        return []
    tenant, object_key, ciphertext, plaintext, logical_digest, key_id = _archive_metadata(db, logical_archive_type, logical_archive_id)
    if tenant != tenant_id:
        raise ReplicaError("TENANT_SCOPE_VIOLATION")
    raw_bindings = archive_store_registry(settings)
    bindings = {key: value if isinstance(value, ArchiveStoreBinding) else ArchiveStoreBinding(key, value) for key, value in raw_bindings.items()}
    policy = ensure_policy(db, settings=settings, now=now)
    targets = _json_list(policy.write_targets) or [key for key, _ in sorted(bindings.items(), key=lambda item: (item[1].priority, item[0]))]
    rows = list_replicas(db, tenant_id=tenant_id, logical_archive_type=logical_archive_type, logical_archive_id=logical_archive_id)
    # A VALID bit without a successful verification timestamp, or outside the
    # freshness window, is never an eligible source for a new copy job.
    sources = [row for row in rows if _is_current(row, current, settings)]
    sources.sort(key=lambda row: (bindings[row.store_id].priority if row.store_id in bindings else 10_000, row.store_id))
    if not sources:
        raise ReplicaError("SOURCE_REPLICA_NOT_VALID")
    source = sources[0]; jobs: list[ArchiveReplicationJob] = []
    for target_id in targets:
        if target_id == source.store_id:
            continue
        binding = bindings.get(target_id)
        if binding is None or not binding.write_enabled or not binding.replication_enabled:
            continue
        target = next((row for row in rows if row.store_id == target_id), None)
        if target is None:
            target = ensure_replica(db, tenant_id=tenant_id, logical_archive_type=logical_archive_type, logical_archive_id=logical_archive_id, store_id=target_id, object_key=object_key, expected_ciphertext_sha256=ciphertext, expected_plaintext_sha256=plaintext, expected_logical_digest=logical_digest, encryption_key_id=key_id, state="MISSING", now=now)
        if target.state in {"MISSING", "REPAIR_PENDING", "PENDING"}:
            jobs.append(queue_replication_job(db, tenant_id=tenant_id, logical_archive_type=logical_archive_type, logical_archive_id=logical_archive_id, source_store_id=source.store_id, target_store_id=target_id, now=now))
    return jobs


def claim_replication_job(db: Session, *, settings: Settings | None = None, instance_id: str | None = None, now: datetime | None = None) -> ArchiveReplicationJob | None:
    settings = settings or get_settings(); current = _db_now(db, now); owner = (instance_id or settings.instance_id)[:128]
    row = db.scalar(select(ArchiveReplicationJob).where(
        ArchiveReplicationJob.status.in_(OPEN_JOB_STATUSES),
        or_(ArchiveReplicationJob.next_attempt_at.is_(None), ArchiveReplicationJob.next_attempt_at <= current),
        or_(ArchiveReplicationJob.lease_expires_at.is_(None), ArchiveReplicationJob.lease_expires_at <= current),
    ).order_by(ArchiveReplicationJob.created_at).limit(1).with_for_update(skip_locked=True))
    if row is None: db.rollback(); return None
    row.status, row.claimed_by, row.claim_token = "IN_FLIGHT", owner, secrets.token_urlsafe(24)
    row.claimed_at, row.lease_expires_at = current, current + timedelta(seconds=settings.archive_replica_lease_seconds)
    row.attempt_count += 1; row.updated_at = current; db.commit(); db.refresh(row); return row


def _save_job_failure(db: Session, job: ArchiveReplicationJob, category: str, settings: Settings, now: datetime) -> None:
    retry = category in {"OBJECT_STORE_UNAVAILABLE", "UNAVAILABLE", "MISSING", "STORE_NOT_CONFIGURED"} and job.attempt_count < settings.archive_replica_max_attempts
    delay = min(settings.archive_replica_retry_max_seconds, settings.archive_replica_retry_base_seconds * 2 ** min(job.attempt_count, 10))
    job.status, job.last_error_category = ("RETRY_WAIT" if retry else "FAILED"), category
    job.next_attempt_at = now + timedelta(seconds=delay) if retry else None
    job.claimed_by = job.claim_token = job.claimed_at = job.lease_expires_at = None; job.updated_at = now; db.commit()


def process_replication_job(db: Session, *, job: ArchiveReplicationJob | None = None, stores: Mapping[str, ArchiveStoreBinding] | None = None, keyring: ArchiveKeyring | None = None, settings: Settings | None = None, now: datetime | None = None, crash_after_upload: bool = False) -> bool:
    settings = settings or get_settings(); job = job or claim_replication_job(db, settings=settings)
    if job is None: return False
    current = _db_now(db, now); source = db.scalar(select(ArchiveReplica).where(ArchiveReplica.tenant_id == job.tenant_id, ArchiveReplica.logical_archive_type == job.logical_archive_type, ArchiveReplica.logical_archive_id == job.logical_archive_id, ArchiveReplica.store_id == job.source_store_id))
    target = db.scalar(select(ArchiveReplica).where(ArchiveReplica.tenant_id == job.tenant_id, ArchiveReplica.logical_archive_type == job.logical_archive_type, ArchiveReplica.logical_archive_id == job.logical_archive_id, ArchiveReplica.store_id == job.target_store_id))
    try:
        if source is None or source.state != "VALID" or not _is_current(source, current, settings): raise ReplicaError("SOURCE_REPLICA_NOT_VALID")
        if target is None: raise ReplicaError("TARGET_REPLICA_NOT_REGISTERED")
        target_binding = _binding(target.store_id, stores, settings)
        if not target_binding.write_enabled or not target_binding.replication_enabled:
            raise ReplicaError("TARGET_STORE_WRITE_DISABLED")
        source_binding = _binding(source.store_id, stores, settings)
        # Verify source again immediately before copying.  Catalog state alone
        # is never accepted as authority for a network copy.
        source_body = source_binding.store.get(source.object_key)
        if keyring is None: keyring = ArchiveKeyring.from_settings(settings)
        _verify_body(db, source, source_body, keyring, settings)
        if _target_object_conflict(target_binding.store, target.object_key, target.expected_ciphertext_sha256):
            target.state, target.last_error_category, target.updated_at = "CONFLICT", "REPLICA_CONFLICT", current
            db.commit(); _save_job_failure(db, job, "REPLICA_CONFLICT", settings, current); return False
        target.state, target.last_error_category, target.updated_at = "REPLICATING", None, current; db.commit()
        target_binding.store.put(target.object_key, source_body)
        if crash_after_upload:
            raise RuntimeError("injected replication worker crash after upload")
        target.state = "VERIFYING"; target.updated_at = current; db.commit()
        target_body = target_binding.store.get(target.object_key)
        verification_status = _verify_body(db, target, target_body, keyring, settings)
        finalize_verified_replica(db, replica=target, verification_status=verification_status)
        job.status, job.last_error_category = "SUCCEEDED", None
        job.claimed_by = job.claim_token = job.claimed_at = job.lease_expires_at = None; job.updated_at = current; db.commit()
        logger.info("replica_replication_verified logical_archive_id=%s target_store=%s", job.logical_archive_id, job.target_store_id)
        return True
    except ArchiveObjectConflict:
        if target is not None:
            target.state, target.last_error_category, target.updated_at = "CONFLICT", "REPLICA_CONFLICT", current
        _save_job_failure(db, job, "REPLICA_CONFLICT", settings, current); return False
    except ArchiveObjectMissing:
        target = target or db.get(ArchiveReplica, getattr(job, "logical_archive_id", None));
        if target is not None: target.state, target.last_error_category = "UNAVAILABLE", "OBJECT_STORE_UNAVAILABLE"
        _save_job_failure(db, job, "UNAVAILABLE", settings, current); return False
    except ArchiveStoreUnavailable:
        if target is not None: target.state, target.last_error_category = "UNAVAILABLE", "OBJECT_STORE_UNAVAILABLE"
        _save_job_failure(db, job, "UNAVAILABLE", settings, current); return False
    except ArchiveKeyMissing:
        if target is not None: target.state, target.last_error_category = "UNVERIFIABLE_KEY_MISSING", "UNVERIFIABLE_KEY_MISSING"
        _save_job_failure(db, job, "UNVERIFIABLE_KEY_MISSING", settings, current); return False
    except (ArchiveStoreError, ReplicaError, ArchiveVerificationError) as exc:
        category = getattr(exc, "status", None) or type(exc).__name__
        if target is not None and category not in {"SOURCE_REPLICA_NOT_VALID", "TARGET_REPLICA_NOT_REGISTERED"}:
            target.state = "CORRUPT" if "DIGEST" in category or "INVALID" in category else target.state
            target.last_error_category = category
        _save_job_failure(db, job, category, settings, current); return False


def repair_missing_replica(db: Session, *, tenant_id: UUID, logical_archive_type: str, logical_archive_id: UUID, target_store_id: str, stores: Mapping[str, ArchiveStoreBinding] | None = None, keyring: ArchiveKeyring | None = None, settings: Settings | None = None, dry_run: bool = False, now: datetime | None = None) -> dict[str, Any]:
    settings = settings or get_settings(); rows = list_replicas(db, tenant_id=tenant_id, logical_archive_type=logical_archive_type, logical_archive_id=logical_archive_id); target = next((row for row in rows if row.store_id == target_store_id), None); source = next((row for row in rows if row.state == "VALID" and _is_current(row, _db_now(db, now), settings)), None)
    result = {"repair_policy_version": REPAIR_VERSION, "logical_archive_id": str(logical_archive_id), "source_store_id": source.store_id if source else None, "target_store_id": target_store_id, "expected_digest": target.expected_ciphertext_sha256 if target else None, "target_state": target.state if target else None, "would_repair": bool(source and target and target.state == "MISSING"), "dry_run": dry_run, "reason": ""}
    if source is None: result["reason"] = "NO_VALID_SOURCE"
    elif target is None: result["reason"] = "TARGET_NOT_REGISTERED"
    elif target.state != "MISSING": result["reason"] = "TARGET_NOT_MISSING"
    elif dry_run: result["reason"] = "MISSING_REPLICA_SAFE_TO_REPAIR"
    else:
        target.state = "REPAIR_PENDING"; target.updated_at = _db_now(db, now); db.commit()
        job = queue_replication_job(db, tenant_id=tenant_id, logical_archive_type=logical_archive_type, logical_archive_id=logical_archive_id, source_store_id=source.store_id, target_store_id=target_store_id, now=now)
        result["job_id"] = str(job.id); result["reason"] = "REPAIR_QUEUED"
    return result


def scrub_replica(db: Session, replica_id: UUID, *, stores: Mapping[str, ArchiveStoreBinding] | None = None, keyring: ArchiveKeyring | None = None, settings: Settings | None = None, worker_instance_id: str | None = None, now: datetime | None = None) -> ArchiveScrubRun:
    settings = settings or get_settings(); row = db.get(ArchiveReplica, replica_id)
    if row is None: raise ReplicaError("REPLICA_NOT_FOUND")
    current = _db_now(db, now); verification = verify_replica(db, replica_id, stores=stores, keyring=keyring, settings=settings, now=current)
    run = ArchiveScrubRun(store_id=row.store_id, tenant_id=row.tenant_id, logical_archive_type=row.logical_archive_type, logical_archive_id=row.logical_archive_id, result=verification.state if verification.state in {"VALID", "MISSING", "UNAVAILABLE", "CORRUPT", "CONFLICT", "UNVERIFIABLE_KEY_MISSING"} else verification.status, verification_depth="FULL", checked_at=current, error_category=None if verification.state == "VALID" else row.last_error_category, worker_instance_id=(worker_instance_id or settings.instance_id)[:128])
    row.last_scrubbed_at = current; row.updated_at = current; db.add(run); db.commit(); db.refresh(run)
    if verification.state == "MISSING" and settings.archive_replica_repair_enabled:
        # Only the narrow MISSING state is eligible.  CORRUPT and CONFLICT
        # intentionally stop here so forensic evidence is preserved.
        repair_missing_replica(db, tenant_id=row.tenant_id, logical_archive_type=row.logical_archive_type,
                               logical_archive_id=row.logical_archive_id, target_store_id=row.store_id,
                               stores=stores, keyring=keyring, settings=settings, dry_run=False, now=current)
    return run


def read_archive_with_fallback(db: Session, *, tenant_id: UUID, archive_id: UUID, stores: Mapping[str, ArchiveStoreBinding] | None = None, keyring: ArchiveKeyring | None = None, settings: Settings | None = None) -> tuple[dict[str, Any], ArchiveReplica]:
    settings = settings or get_settings(); record = db.scalar(select(ArchiveRecord).where(ArchiveRecord.id == archive_id, ArchiveRecord.tenant_id == tenant_id))
    if record is None: raise LookupError("archive not found")
    rows = list_replicas(db, tenant_id=tenant_id, logical_archive_type=TRACE_ARCHIVE, logical_archive_id=archive_id)
    raw_bindings = stores if stores is not None else archive_store_registry(settings)
    bindings = {key: value if isinstance(value, ArchiveStoreBinding) else ArchiveStoreBinding(key, value) for key, value in raw_bindings.items()}
    priority = {key: value.priority for key, value in bindings.items()}
    errors: list[str] = []
    for row in sorted(rows, key=lambda item: (priority.get(item.store_id, 10_000), item.store_id)):
        if row.state != "VALID": continue
        binding = bindings.get(row.store_id)
        if binding is None or not binding.read_enabled: continue
        result = verify_replica(db, row.id, stores=bindings, keyring=keyring, settings=settings)
        if result.state == "VALID":
            body = binding.store.get(row.object_key)
            verified = unseal_archive(object_bytes=body, archive_id=record.id, tenant_id=record.tenant_id, trace_id=record.trace_id, keyring=keyring or ArchiveKeyring.from_settings(settings), max_object_bytes=settings.archive_max_object_bytes, max_decompressed_bytes=settings.archive_max_decompressed_bytes)
            return verified.payload, row
        errors.append(result.status)
    raise ReplicaUnavailable("NO_VALID_REPLICA" if not errors else errors[-1])
