import base64
import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from agentguard_server.config import Settings
from agentguard_server.models import ArchiveLifecycle, ArchiveRecord
from agentguard_server.services.archive import ArchiveKeyring, canonical_archive_json, seal_archive
from agentguard_server.services.archive_store import ArchiveStoreUnavailable, InMemoryArchiveStore, ArchiveStoreBinding, set_archive_store_registry_for_tests
from agentguard_server.services.auth import create_tenant
from agentguard_server.services.replicas import (
    TRACE_ARCHIVE, ReplicaError, enqueue_replication_jobs, ensure_replica,
    finalize_verified_replica, list_replicas, process_replication_job,
    queue_replication_job, read_archive_with_fallback, verify_replica,
)


def _fixture(db_session):
    tenant = create_tenant(db_session, f"v18-{uuid4().hex[:10]}", "V18 replica test")
    archive_id = uuid4(); now = datetime.now(timezone.utc)
    source = {"trace": {"trace_id": "v18-trace"}, "spans": []}
    manifest = {"archive_id": archive_id, "tenant_id": tenant.id, "trace_id": "v18-trace", "archive_version": "trace-archive-v1", "source_projection_digest": hashlib.sha256(canonical_archive_json(source)).hexdigest()}
    sealed = seal_archive(archive_id=archive_id, tenant_id=tenant.id, trace_id="v18-trace", plaintext=canonical_archive_json({"manifest": manifest, "source_projection": source}), keyring=ArchiveKeyring({"k": b"k" * 32}, "k"))
    record = ArchiveRecord(id=archive_id, tenant_id=tenant.id, trace_id="v18-trace", archive_version="trace-archive-v1", envelope_version="archive-envelope-v1", object_key=f"trace-archive-v1/{tenant.id}/{archive_id}.bin", archive_encryption_key_id="k", plaintext_sha256=sealed.plaintext_sha256, compressed_sha256=sealed.compressed_sha256, ciphertext_sha256=sealed.ciphertext_sha256, source_projection_digest=manifest["source_projection_digest"], trace_span_count=0, created_at=now)
    db_session.add(record); db_session.add(ArchiveLifecycle(archive_record_id=archive_id, status="ARCHIVED_VERIFIED", updated_at=now)); db_session.commit()
    a, b = InMemoryArchiveStore(), InMemoryArchiveStore(); a.put(record.object_key, sealed.object_bytes)
    settings = Settings(_env_file=None, environment="test", archive_replication_enabled=True, archive_replica_verification_max_age_seconds=3600, archive_encryption_keys=json.dumps({"k": base64.b64encode(b"k" * 32).decode()}), archive_encryption_key_id="k")
    set_archive_store_registry_for_tests({"a": ArchiveStoreBinding("a", a, priority=0), "b": ArchiveStoreBinding("b", b, priority=1)})
    ensure_replica(db_session, tenant_id=tenant.id, logical_archive_type=TRACE_ARCHIVE, logical_archive_id=archive_id, store_id="a", object_key=record.object_key, expected_ciphertext_sha256=sealed.ciphertext_sha256, expected_plaintext_sha256=sealed.plaintext_sha256, expected_logical_digest=manifest["source_projection_digest"], encryption_key_id="k")
    ensure_replica(db_session, tenant_id=tenant.id, logical_archive_type=TRACE_ARCHIVE, logical_archive_id=archive_id, store_id="b", object_key=record.object_key, expected_ciphertext_sha256=sealed.ciphertext_sha256, expected_plaintext_sha256=sealed.plaintext_sha256, expected_logical_digest=manifest["source_projection_digest"], encryption_key_id="k", state="MISSING")
    db_session.commit()
    return tenant, record, settings, a, b, ArchiveKeyring({"k": b"k" * 32}, "k")


def test_v18_full_verification_replication_and_fallback(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    first = list_replicas(db_session, tenant_id=tenant.id, logical_archive_type=TRACE_ARCHIVE, logical_archive_id=record.id)[0]
    assert verify_replica(db_session, first.id, stores={"a": ArchiveStoreBinding("a", a), "b": ArchiveStoreBinding("b", b)}, keyring=keyring, settings=settings).state == "VALID"
    job = queue_replication_job(db_session, tenant_id=tenant.id, logical_archive_type=TRACE_ARCHIVE, logical_archive_id=record.id, source_store_id="a", target_store_id="b")
    assert process_replication_job(db_session, job=job, stores={"a": ArchiveStoreBinding("a", a), "b": ArchiveStoreBinding("b", b)}, keyring=keyring, settings=settings)
    assert {row.state for row in list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)} == {"VALID"}
    del a.objects[record.object_key]
    payload, replica = read_archive_with_fallback(db_session, tenant_id=tenant.id, archive_id=record.id, stores={"a": ArchiveStoreBinding("a", a), "b": ArchiveStoreBinding("b", b)}, keyring=keyring, settings=settings)
    assert payload["manifest"]["trace_id"] == record.trace_id and replica.store_id == "b"


def test_v18_replica_cannot_be_created_valid_without_verification_evidence(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    with pytest.raises(ReplicaError, match="VALID_REPLICA_REQUIRES_VERIFICATION"):
        ensure_replica(
            db_session, tenant_id=tenant.id, logical_archive_type=TRACE_ARCHIVE,
            logical_archive_id=record.id, store_id="c", object_key=record.object_key,
            expected_ciphertext_sha256=record.ciphertext_sha256,
            expected_plaintext_sha256=record.plaintext_sha256,
            expected_logical_digest=record.source_projection_digest or "",
            encryption_key_id=record.archive_encryption_key_id, state="VALID",
        )


def test_v18_finalizer_rejects_non_valid_evidence(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    replica = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)[0]
    with pytest.raises(ReplicaError, match="VALID_REPLICA_REQUIRES_VERIFICATION"):
        finalize_verified_replica(db_session, replica=replica, verification_status="CORRUPT")


def test_v18_full_verification_persists_validity_timestamp(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    replica = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)[0]
    result = verify_replica(db_session, replica.id, stores={"a": ArchiveStoreBinding("a", a)}, keyring=keyring, settings=settings)
    assert result.state == "VALID" and result.verified_at is not None
    assert replica.last_error_category is None


def test_v18_missing_object_never_gets_valid_timestamp(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    del a.objects[record.object_key]
    replica = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)[0]
    result = verify_replica(db_session, replica.id, stores={"a": ArchiveStoreBinding("a", a)}, keyring=keyring, settings=settings)
    assert result.state == "MISSING" and result.verified_at is None


class _UnavailableStore:
    def get(self, object_key):
        raise ArchiveStoreUnavailable("offline")


def test_v18_provider_outage_never_gets_valid_timestamp(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    replica = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)[0]
    result = verify_replica(db_session, replica.id, store=_UnavailableStore(), keyring=keyring, settings=settings)
    assert result.state == "UNAVAILABLE" and result.verified_at is None


def test_v18_missing_key_is_unverifiable_not_valid(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    replica = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)[0]
    result = verify_replica(db_session, replica.id, stores={"a": ArchiveStoreBinding("a", a)}, keyring=ArchiveKeyring({}, "missing"), settings=settings)
    assert result.state == "UNVERIFIABLE_KEY_MISSING" and result.verified_at is None


def test_v18_digest_or_ciphertext_tamper_is_corrupt_not_valid(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    a.objects[record.object_key] = a.objects[record.object_key][:-1] + b"x"
    replica = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)[0]
    result = verify_replica(db_session, replica.id, stores={"a": ArchiveStoreBinding("a", a)}, keyring=keyring, settings=settings)
    assert result.state == "CORRUPT" and result.verified_at is None


def test_v18_stale_valid_source_is_rejected_by_worker(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    source, target = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)
    assert verify_replica(db_session, source.id, stores={"a": ArchiveStoreBinding("a", a)}, keyring=keyring, settings=settings).state == "VALID"
    source.verified_at = datetime.now(timezone.utc).replace(year=2020)
    db_session.commit()
    job = queue_replication_job(db_session, tenant_id=tenant.id, logical_archive_type=TRACE_ARCHIVE, logical_archive_id=record.id, source_store_id="a", target_store_id="b")
    assert not process_replication_job(db_session, job=job, stores={"a": ArchiveStoreBinding("a", a), "b": ArchiveStoreBinding("b", b)}, keyring=keyring, settings=settings)
    assert job.last_error_category == "SOURCE_REPLICA_NOT_VALID"


def test_v18_malformed_valid_row_is_not_an_enqueue_source(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    source = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)[0]
    source.state, source.verified_at = "VALID", None
    db_session.commit()
    with pytest.raises(ReplicaError, match="SOURCE_REPLICA_NOT_VALID"):
        enqueue_replication_jobs(db_session, tenant_id=tenant.id, logical_archive_type=TRACE_ARCHIVE, logical_archive_id=record.id, settings=settings)


def test_v18_replication_finalizer_persists_target_timestamp(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    source = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)[0]
    assert verify_replica(db_session, source.id, stores={"a": ArchiveStoreBinding("a", a)}, keyring=keyring, settings=settings).state == "VALID"
    job = queue_replication_job(db_session, tenant_id=tenant.id, logical_archive_type=TRACE_ARCHIVE, logical_archive_id=record.id, source_store_id="a", target_store_id="b")
    assert process_replication_job(db_session, job=job, stores={"a": ArchiveStoreBinding("a", a), "b": ArchiveStoreBinding("b", b)}, keyring=keyring, settings=settings)
    target = next(row for row in list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id) if row.store_id == "b")
    assert target.state == "VALID" and target.verified_at is not None


def test_v18_conflicting_target_stays_conflict(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    source, target = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)
    assert verify_replica(db_session, source.id, stores={"a": ArchiveStoreBinding("a", a)}, keyring=keyring, settings=settings).state == "VALID"
    b.put(record.object_key, b"different-object")
    job = queue_replication_job(db_session, tenant_id=tenant.id, logical_archive_type=TRACE_ARCHIVE, logical_archive_id=record.id, source_store_id="a", target_store_id="b")
    assert not process_replication_job(db_session, job=job, stores={"a": ArchiveStoreBinding("a", a), "b": ArchiveStoreBinding("b", b)}, keyring=keyring, settings=settings)
    assert target.state == "CONFLICT" and target.verified_at is None


def test_v18_malformed_valid_row_is_repaired_by_full_verification(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    replica = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)[0]
    replica.state, replica.verified_at = "VALID", None
    db_session.commit()
    result = verify_replica(db_session, replica.id, stores={"a": ArchiveStoreBinding("a", a)}, keyring=keyring, settings=settings)
    assert result.state == "VALID" and result.verified_at is not None


def test_v18_validity_timestamp_uses_database_clock(db_session, monkeypatch):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    trusted_now = datetime(2026, 9, 1, 12, 34, 56, tzinfo=timezone.utc)
    monkeypatch.setattr("agentguard_server.services.replicas.database_now", lambda db: trusted_now)
    replica = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)[0]
    result = verify_replica(db_session, replica.id, stores={"a": ArchiveStoreBinding("a", a)}, keyring=keyring, settings=settings)
    assert result.state == "VALID" and result.verified_at == trusted_now


def test_v18_finalization_is_transactional(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    replica = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)[0]
    finalize_verified_replica(db_session, replica=replica, verification_status="VALID")
    assert replica.state == "VALID" and replica.verified_at is not None
    db_session.rollback()
    assert replica.state == "PENDING" and replica.verified_at is None


def test_v18_existing_object_verification_is_idempotent(db_session):
    tenant, record, settings, a, b, keyring = _fixture(db_session)
    replica = list_replicas(db_session, tenant_id=tenant.id, logical_archive_id=record.id)[0]
    first = verify_replica(db_session, replica.id, stores={"a": ArchiveStoreBinding("a", a)}, keyring=keyring, settings=settings)
    second = verify_replica(db_session, replica.id, stores={"a": ArchiveStoreBinding("a", a)}, keyring=keyring, settings=settings)
    assert first.state == second.state == "VALID" and second.verified_at is not None
