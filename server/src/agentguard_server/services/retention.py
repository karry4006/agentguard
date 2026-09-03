"""V16 deterministic retention policy, jobs, holds, archive, and purge."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
import secrets
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentguard_server.config import Settings, get_settings
from agentguard_server.models import ArchiveLifecycle, ArchiveRecord, IntegrityCheckpoint, RetentionHold, RetentionJob, Span, Trace
from agentguard_server.services.archive import (ARCHIVE_ENVELOPE_VERSION, ARCHIVE_FORMAT_VERSION, ArchiveEligibilityError, ArchiveKeyring, ArchiveVerificationError, archive_payload, build_source_projection, check_archive_eligibility, seal_archive, source_projection_digest, unseal_archive, verify_stored_archive)
from agentguard_server.services.archive_store import ArchiveObjectConflict, ArchiveStore, ArchiveStoreError, ArchiveStoreUnavailable, InMemoryArchiveStore, archive_object_key
from agentguard_server.services.replicas import TRACE_ARCHIVE, enqueue_replication_jobs, ensure_replica, finalize_verified_replica, list_replicas, read_archive_with_fallback
from agentguard_server.services.anchoring import remote_continuity, verify_checkpoint
from agentguard_server.services.integrity import verify_trace_integrity

logger = logging.getLogger("agentguard.retention")
ARCHIVE_JOB = "ARCHIVE_TRACE"
PURGE_JOB = "PURGE_TRACE"
JOB_STATUSES = ("PENDING", "RETRY_WAIT", "IN_FLIGHT")

_test_store: ArchiveStore | None = None


def set_archive_store_for_tests(store: ArchiveStore | None) -> None:
    global _test_store
    _test_store = store


def configured_archive_store(settings: Settings | None = None) -> ArchiveStore:
    if _test_store is not None:
        return _test_store
    settings = settings or get_settings()
    if not settings.archive_enabled:
        return InMemoryArchiveStore()
    from agentguard_server.services.archive_store import S3ArchiveStore
    return S3ArchiveStore(settings)


def _now(now: datetime | None = None) -> datetime:
    current = now or datetime.now(timezone.utc)
    return current if current.tzinfo else current.replace(tzinfo=timezone.utc)


def active_hold(db: Session, tenant_id: UUID, trace_id: str, *, now: datetime | None = None) -> RetentionHold | None:
    # Rows are inserted with trusted server time.  Avoid comparing aware
    # values against SQLite's deliberately timezone-naive test representation.
    return db.scalar(select(RetentionHold).where(RetentionHold.tenant_id == tenant_id, RetentionHold.released_at.is_(None), (RetentionHold.subject_type == "TENANT") | ((RetentionHold.subject_type == "TRACE") & (RetentionHold.trace_id == trace_id))).order_by(RetentionHold.created_at.desc()).limit(1))


def create_hold(db: Session, *, tenant_id: UUID, subject_type: str, trace_id: str | None, reason: str, principal_type: str, principal_id: str, now: datetime | None = None) -> RetentionHold:
    subject_type = subject_type.strip().upper()
    if subject_type not in {"TRACE", "TENANT"}:
        raise ValueError("subject_type must be TRACE or TENANT")
    if subject_type == "TRACE" and not trace_id:
        raise ValueError("trace holds require trace_id")
    if not reason.strip() or len(reason) > 4096:
        raise ValueError("hold reason is required and bounded")
    row = RetentionHold(tenant_id=tenant_id, subject_type=subject_type, trace_id=trace_id if subject_type == "TRACE" else None, reason=reason.strip(), created_by_principal_type=principal_type[:32], created_by_principal_id=principal_id[:128], created_at=_now(now))
    db.add(row)
    db.commit()
    db.refresh(row)
    logger.info("retention_hold_created tenant_id=%s hold_id=%s subject_type=%s", tenant_id, row.id, subject_type)
    return row


def release_hold(db: Session, *, tenant_id: UUID, hold_id: UUID, principal_type: str, principal_id: str, now: datetime | None = None) -> RetentionHold | None:
    row = db.scalar(select(RetentionHold).where(RetentionHold.id == hold_id, RetentionHold.tenant_id == tenant_id))
    if row is None:
        return None
    if row.released_at is None:
        row.released_at = _now(now)
        row.released_by_principal_type = principal_type[:32]
        row.released_by_principal_id = principal_id[:128]
        db.commit()
        db.refresh(row)
    return row


def queue_retention_job(db: Session, *, tenant_id: UUID, trace_id: str, job_type: str = ARCHIVE_JOB, archive_record_id: UUID | None = None, now: datetime | None = None) -> RetentionJob:
    if job_type not in {ARCHIVE_JOB, PURGE_JOB}:
        raise ValueError("unsupported retention job type")
    existing = db.scalar(select(RetentionJob).where(RetentionJob.tenant_id == tenant_id, RetentionJob.trace_id == trace_id, RetentionJob.job_type == job_type, RetentionJob.status.in_(JOB_STATUSES)).order_by(RetentionJob.created_at.desc()).limit(1))
    if existing:
        return existing
    current = _now(now)
    row = RetentionJob(tenant_id=tenant_id, trace_id=trace_id, job_type=job_type, archive_record_id=archive_record_id, status="PENDING", next_attempt_at=current, created_at=current, updated_at=current)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def claim_retention_job(db: Session, *, job_id: UUID | None = None, instance_id: str = "retention-worker", lease_seconds: int | None = None, now: datetime | None = None) -> RetentionJob | None:
    current = _now(now)
    settings = get_settings()
    lease = lease_seconds or settings.archive_lease_seconds
    query = select(RetentionJob).where(RetentionJob.status.in_(JOB_STATUSES), (RetentionJob.next_attempt_at.is_(None) | (RetentionJob.next_attempt_at <= current)), (RetentionJob.lease_expires_at.is_(None) | (RetentionJob.lease_expires_at <= current))).order_by(RetentionJob.created_at).limit(1)
    if job_id is not None:
        query = select(RetentionJob).where(RetentionJob.id == job_id, RetentionJob.status.in_(JOB_STATUSES), (RetentionJob.next_attempt_at.is_(None) | (RetentionJob.next_attempt_at <= current)), (RetentionJob.lease_expires_at.is_(None) | (RetentionJob.lease_expires_at <= current)))
    row = db.scalar(query.with_for_update(skip_locked=True))
    if row is None:
        db.rollback()
        return None
    row.status = "IN_FLIGHT"
    row.claimed_by = instance_id[:128]
    row.claim_token = secrets.token_urlsafe(24)
    row.claimed_at = current
    row.lease_expires_at = current + timedelta(seconds=lease)
    row.attempt_count += 1
    row.updated_at = current
    db.commit()
    db.refresh(row)
    return row


def _save_failure(db: Session, job: RetentionJob, category: str, *, now: datetime, retry: bool = True) -> RetentionJob:
    job.last_error_category = category
    job.status = "RETRY_WAIT" if retry else "FAILED"
    job.next_attempt_at = now + timedelta(seconds=min(3600, 2 ** min(job.attempt_count, 10))) if retry else None
    job.claimed_by = job.claim_token = job.claimed_at = job.lease_expires_at = None
    job.updated_at = now
    db.commit()
    db.refresh(job)
    return job


def archive_trace(db: Session, *, tenant_id: UUID, trace_id: str, store: ArchiveStore | None = None, settings: Settings | None = None, now: datetime | None = None) -> ArchiveRecord:
    settings = settings or get_settings()
    if not settings.archive_enabled:
        raise ArchiveEligibilityError("ARCHIVE_DISABLED")
    current = _now(now)
    eligibility = check_archive_eligibility(db, tenant_id, trace_id, settings=settings, now=current)
    record = db.scalar(select(ArchiveRecord).where(ArchiveRecord.tenant_id == tenant_id, ArchiveRecord.trace_id == trace_id, ArchiveRecord.archive_version == ARCHIVE_FORMAT_VERSION))
    if record is None:
        record = ArchiveRecord(id=uuid4(), tenant_id=tenant_id, trace_id=trace_id, archive_version=ARCHIVE_FORMAT_VERSION, envelope_version=ARCHIVE_ENVELOPE_VERSION, object_key=archive_object_key(tenant_id, uuid4()), archive_encryption_key_id=settings.archive_encryption_key_id, source_v3_min_sequence=eligibility["source_v3_min_sequence"], source_v3_max_sequence=eligibility["source_v3_max_sequence"], covering_checkpoint_id=eligibility["checkpoint"].id, covering_checkpoint_sequence=eligibility["checkpoint"].checkpoint_sequence, covering_checkpoint_digest=eligibility["checkpoint"].checkpoint_digest, trace_span_count=eligibility["span_count"], created_at=current)
        # Regenerate once so the stable catalog id is also part of the key.
        record.object_key = archive_object_key(tenant_id, record.id)
        db.add(record)
        db.flush()
        db.add(ArchiveLifecycle(archive_record_id=record.id, status="ARCHIVING", updated_at=current))
        db.commit()
        db.refresh(record)
    lifecycle = record.lifecycle or db.get(ArchiveLifecycle, record.id)
    if lifecycle and lifecycle.status == "ARCHIVED_VERIFIED":
        try:
            verify_stored_archive(db, record, store or configured_archive_store(settings), ArchiveKeyring.from_settings(settings), settings=settings)
        except ArchiveVerificationError as exc:
            lifecycle.status = "STALE" if exc.status == "ARCHIVE_PROJECTION_DIGEST_MISMATCH" else "FAILED"
            lifecycle.last_error_category = exc.status
            lifecycle.updated_at = current
            db.commit()
            raise
        return record
    keyring = ArchiveKeyring.from_settings(settings)
    plaintext, manifest = archive_payload(db, tenant_id, trace_id, record.id, eligibility["checkpoint"], now=current)
    sealed = seal_archive(archive_id=record.id, tenant_id=tenant_id, trace_id=trace_id, plaintext=plaintext, keyring=keyring)
    record.source_projection_digest = manifest["source_projection_digest"]
    record.archive_encryption_key_id = sealed.key_id
    record.plaintext_sha256 = sealed.plaintext_sha256
    record.compressed_sha256 = sealed.compressed_sha256
    record.ciphertext_sha256 = sealed.ciphertext_sha256
    record.plaintext_size = len(sealed.plaintext)
    record.compressed_size = len(sealed.compressed)
    record.ciphertext_size = len(sealed.ciphertext)
    record.trace_span_count = manifest["span_count"]
    store = store or configured_archive_store(settings)
    lifecycle = lifecycle or ArchiveLifecycle(archive_record_id=record.id, updated_at=current)
    try:
        store.put(record.object_key, sealed.object_bytes)
        verify_stored_archive(db, record, store, keyring, settings=settings)
    except ArchiveObjectConflict:
        lifecycle.status, lifecycle.last_error_category = "FAILED", "ARCHIVE_OBJECT_CONFLICT"
        db.add(lifecycle); db.commit()
        raise ArchiveVerificationError("ARCHIVE_OBJECT_CONFLICT")
    except ArchiveVerificationError as exc:
        lifecycle.status, lifecycle.last_error_category = "FAILED", exc.status
        db.add(lifecycle); db.commit()
        raise
    except (ArchiveStoreUnavailable, ArchiveStoreError) as exc:
        lifecycle.status, lifecycle.last_error_category = "FAILED", "OBJECT_STORE_UNAVAILABLE"
        db.add(lifecycle); db.commit()
        raise ArchiveVerificationError("OBJECT_STORE_UNAVAILABLE") from exc
    record.verified_at = current
    lifecycle.status = "ARCHIVED_VERIFIED"
    lifecycle.last_verified_at = current
    lifecycle.last_error_category = None
    lifecycle.updated_at = current
    db.add(record); db.add(lifecycle)
    # The original V16 object is the primary replica.  This catalog entry is
    # harmless in compatibility mode and gives V18 a durable source of truth
    # without changing V17/V16 deletion semantics.
    primary_replica = ensure_replica(db, tenant_id=tenant_id, logical_archive_type=TRACE_ARCHIVE,
                   logical_archive_id=record.id, store_id=settings.archive_primary_store_id,
                   object_key=record.object_key, expected_ciphertext_sha256=record.ciphertext_sha256,
                   expected_plaintext_sha256=record.plaintext_sha256,
                   expected_logical_digest=record.source_projection_digest or "",
                   encryption_key_id=record.archive_encryption_key_id, state="PENDING", now=current)
    # verify_stored_archive completed the full authenticated readback before
    # this catalog row is finalized as a source of truth.
    finalize_verified_replica(db, replica=primary_replica, verification_status="VALID")
    db.commit()
    if settings.archive_replication_enabled:
        enqueue_replication_jobs(db, tenant_id=tenant_id, logical_archive_type=TRACE_ARCHIVE, logical_archive_id=record.id, settings=settings, now=current)
    db.refresh(record)
    logger.info("archive_upload_verified tenant_id=%s trace_id=%s archive_id=%s", tenant_id, trace_id, record.id)
    return record


def retrieve_archive(db: Session, *, tenant_id: UUID, archive_id: UUID, store: ArchiveStore | None = None, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    record = db.scalar(select(ArchiveRecord).where(ArchiveRecord.id == archive_id, ArchiveRecord.tenant_id == tenant_id))
    if record is None:
        raise LookupError("archive not found")
    if store is None:
        replicas = list_replicas(db, tenant_id=tenant_id, logical_archive_type=TRACE_ARCHIVE, logical_archive_id=archive_id)
        if replicas:
            payload, _ = read_archive_with_fallback(db, tenant_id=tenant_id, archive_id=archive_id, keyring=ArchiveKeyring.from_settings(settings), settings=settings)
            return payload
    verified = verify_stored_archive(db, record, store or configured_archive_store(settings), ArchiveKeyring.from_settings(settings), settings=settings)
    return verified.payload


def purge_trace(db: Session, *, tenant_id: UUID, trace_id: str, archive_id: UUID | None = None, store: ArchiveStore | None = None, settings: Settings | None = None, witness_provider: Any = None, now: datetime | None = None) -> ArchiveRecord:
    settings = settings or get_settings()
    if not settings.retention_purge_enabled:
        raise ArchiveEligibilityError("PURGE_DISABLED")
    current = _now(now)
    record = db.scalar(select(ArchiveRecord).where(ArchiveRecord.tenant_id == tenant_id, ArchiveRecord.trace_id == trace_id, *( [ArchiveRecord.id == archive_id] if archive_id else [] )).order_by(ArchiveRecord.created_at.desc()).limit(1))
    if record is None or record.lifecycle is None or record.lifecycle.status != "ARCHIVED_VERIFIED":
        raise ArchiveEligibilityError("ARCHIVE_NOT_VERIFIED")
    if active_hold(db, tenant_id, trace_id, now=current):
        raise ArchiveEligibilityError("RETENTION_HOLD_ACTIVE")
    trace = db.scalar(select(Trace).where(Trace.tenant_id == tenant_id, Trace.trace_id == trace_id))
    if trace is None or not trace.ended_at:
        raise ArchiveEligibilityError("TRACE_NOT_FINALIZED")
    ended = trace.ended_at if trace.ended_at.tzinfo else trace.ended_at.replace(tzinfo=timezone.utc)
    if ended.astimezone(timezone.utc) > current - timedelta(days=settings.purge_after_days):
        raise ArchiveEligibilityError("TRACE_TOO_RECENT")
    store = store or configured_archive_store(settings)
    verify_stored_archive(db, record, store, ArchiveKeyring.from_settings(settings), settings=settings)
    if source_projection_digest(build_source_projection(db, tenant_id, trace_id)) != record.source_projection_digest:
        record.lifecycle.status, record.lifecycle.last_error_category = "STALE", "ARCHIVE_PROJECTION_STALE"
        record.lifecycle.updated_at = current
        db.commit()
        raise ArchiveEligibilityError("ARCHIVE_PROJECTION_STALE")
    if verify_trace_integrity(db, tenant_id, trace_id, settings).status != "valid":
        raise ArchiveEligibilityError("V3_INTEGRITY_INVALID")
    checkpoint = db.get(IntegrityCheckpoint, record.covering_checkpoint_id) if record.covering_checkpoint_id else None
    if checkpoint is None or verify_checkpoint(db, checkpoint.id, settings=settings).get("status") != "VALID":
        raise ArchiveEligibilityError("V15_COVERAGE_INVALID")
    if getattr(settings, "quorum_enabled", False):
        from agentguard_server.services.quorum import QuorumError, require_fresh_quorum
        try:
            require_fresh_quorum(db, checkpoint.id, now=current)
        except QuorumError as exc:
            raise ArchiveEligibilityError(f"V20_{type(exc).__name__}") from exc
    if settings.anchor_enabled:
        if witness_provider is None:
            raise ArchiveEligibilityError("V15_REMOTE_UNAVAILABLE")
        if remote_continuity(db, witness_provider, settings=settings).status != "MATCH":
            raise ArchiveEligibilityError("V15_REMOTE_NOT_MATCH")
    # V16 never deletes V3/V15 rows, trace index, incidents, identity, or API data.
    db.query(Span).filter(Span.tenant_id == tenant_id, Span.trace_id == trace_id).delete(synchronize_session=False)
    record.lifecycle.status = "PURGED"
    record.lifecycle.purged_at = current
    record.lifecycle.updated_at = current
    db.commit(); db.refresh(record)
    logger.info("hot_projection_purged tenant_id=%s trace_id=%s archive_id=%s", tenant_id, trace_id, record.id)
    return record


def retention_status(db: Session, *, tenant_id: UUID | None = None, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    def count(model: Any, *conditions: Any) -> int:
        stmt = select(func.count()).select_from(model)
        if tenant_id is not None and hasattr(model, "tenant_id"):
            stmt = stmt.where(model.tenant_id == tenant_id)
        if conditions:
            stmt = stmt.where(*conditions)
        return int(db.scalar(stmt) or 0)
    lifecycle_stmt = select(func.count()).select_from(ArchiveLifecycle).join(ArchiveRecord, ArchiveRecord.id == ArchiveLifecycle.archive_record_id)
    if tenant_id is not None:
        lifecycle_stmt = lifecycle_stmt.where(ArchiveRecord.tenant_id == tenant_id)
    archived = int(db.scalar(lifecycle_stmt.where(ArchiveLifecycle.status == "ARCHIVED_VERIFIED")) or 0)
    purged = int(db.scalar(lifecycle_stmt.where(ArchiveLifecycle.status == "PURGED")) or 0)
    return {"archive_enabled": settings.archive_enabled, "purge_enabled": settings.retention_purge_enabled, "pending_jobs": count(RetentionJob, RetentionJob.status.in_(JOB_STATUSES)), "archived": archived, "purged": purged, "failed_jobs": count(RetentionJob, RetentionJob.status == "FAILED"), "active_holds": count(RetentionHold, RetentionHold.released_at.is_(None))}
