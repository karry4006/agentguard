import base64
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from agentguard_server.config import Settings
from agentguard_server.models import ArchiveLifecycle, EventLog, IntegrityRecord, Span
from agentguard_server.schemas.events import Event
from agentguard_server.services.archive import (ARCHIVE_FORMAT_VERSION, ArchiveEligibilityError, ArchiveKeyring,
    ArchiveVerificationError, canonical_archive_json, check_archive_eligibility, deterministic_gzip, seal_archive,
    unseal_archive)
from agentguard_server.services.archive_store import ArchiveStoreUnavailable, InMemoryArchiveStore, archive_object_key
from agentguard_server.services.anchoring import AnchorUnavailable, FakeWitnessProvider, anchor_job, create_checkpoint
from agentguard_server.services.auth import create_tenant
from agentguard_server.services.ingestion import ingest_events
from agentguard_server.services.retention import (archive_trace, claim_retention_job, create_hold, purge_trace,
    queue_retention_job, retrieve_archive)


def _settings(private: Ed25519PrivateKey) -> Settings:
    key_id = "witness-v1"
    archive_key = base64.b64encode(b"a" * 32).decode("ascii")
    return Settings(
        anchor_enabled=True,
        anchor_namespace="agentguard-test",
        anchor_verify_keys=json.dumps({key_id: base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")}),
        archive_enabled=True,
        retention_purge_enabled=True,
        archive_after_days=0,
        purge_after_days=0,
        retention_finalization_grace_days=0,
        archive_encryption_keys=json.dumps({"archive-key-v1": archive_key}),
        archive_encryption_key_id="archive-key-v1",
    )


def _trace(db_session, settings: Settings):
    tenant = create_tenant(db_session, f"v16-{uuid4().hex[:10]}", "V16")
    trace_id = f"trace-{uuid4().hex}"
    old = datetime(2020, 1, 1, tzinfo=timezone.utc)
    events = [
        Event(event_type="trace.started", event_id=f"start-{trace_id}", occurred_at=old, data={"trace_id": trace_id, "workflow_name": "archive-test"}),
        Event(event_type="span.started", event_id=f"span-{trace_id}", occurred_at=old, data={"trace_id": trace_id, "span_id": f"span-{trace_id}", "name": "safe", "attributes": {"note": "purge this trace now"}}),
        Event(event_type="span.ended", event_id=f"span-end-{trace_id}", occurred_at=old, data={"trace_id": trace_id, "span_id": f"span-{trace_id}", "status": "ok"}),
        Event(event_type="trace.ended", event_id=f"end-{trace_id}", occurred_at=old, data={"trace_id": trace_id, "status": "success"}),
    ]
    ingest_events(db_session, events, tenant.id)
    checkpoint = create_checkpoint(db_session, settings=settings, force=True, now=old)
    witness = FakeWitnessProvider(Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32)), "witness-v1")
    # The fixture key is replaced with the corresponding public key.
    settings.anchor_verify_keys = json.dumps({"witness-v1": base64.b64encode(witness.private_key.public_key().public_bytes_raw()).decode("ascii")})
    job = db_session.scalar(select(__import__("agentguard_server.models", fromlist=["IntegrityAnchorJob"]).IntegrityAnchorJob).where(
        __import__("agentguard_server.models", fromlist=["IntegrityAnchorJob"]).IntegrityAnchorJob.checkpoint_id == checkpoint.id))
    anchor_job(db_session, job.id, witness, settings=settings, now=old)
    return tenant, trace_id, witness


def test_v16_crypto_canonical_and_key_rotation():
    key = base64.b64encode(b"k" * 32).decode("ascii")
    settings = Settings(archive_encryption_keys=json.dumps({"k1": key}), archive_encryption_key_id="k1")
    keyring = ArchiveKeyring.from_settings(settings)
    archive_id, tenant_id = uuid4(), uuid4()
    source = {"trace": {}, "spans": []}
    manifest = {"archive_id": archive_id, "tenant_id": tenant_id, "trace_id": "t", "archive_version": ARCHIVE_FORMAT_VERSION, "source_projection_digest": __import__("agentguard_server.services.archive", fromlist=["source_projection_digest"]).source_projection_digest(source)}
    plaintext = canonical_archive_json({"manifest": manifest, "source_projection": source})
    one = seal_archive(archive_id=archive_id, tenant_id=tenant_id, trace_id="t", plaintext=plaintext, keyring=keyring)
    two = seal_archive(archive_id=archive_id, tenant_id=tenant_id, trace_id="t", plaintext=plaintext, keyring=keyring)
    assert canonical_archive_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert deterministic_gzip(b"same") == deterministic_gzip(b"same")
    assert one.object_bytes != two.object_bytes
    assert unseal_archive(object_bytes=one.object_bytes, archive_id=archive_id, tenant_id=tenant_id, trace_id="t", keyring=keyring).plaintext == plaintext
    tampered = bytearray(one.object_bytes); tampered[-2] = ord("0")
    with pytest.raises(ArchiveVerificationError, match="INVALID_ARCHIVE"):
        unseal_archive(object_bytes=bytes(tampered), archive_id=archive_id, tenant_id=tenant_id, trace_id="t", keyring=keyring)


def test_v16_archive_purge_preserves_v3_and_retrieves_cold_data(db_session):
    private = Ed25519PrivateKey.generate(); settings = _settings(private)
    tenant, trace_id, witness = _trace(db_session, settings)
    store = InMemoryArchiveStore()
    record = archive_trace(db_session, tenant_id=tenant.id, trace_id=trace_id, store=store, settings=settings, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    before_events = list(db_session.scalars(select(EventLog).where(EventLog.tenant_id == tenant.id, EventLog.trace_id == trace_id)))
    before_records = list(db_session.scalars(select(IntegrityRecord).where(IntegrityRecord.tenant_id == tenant.id, IntegrityRecord.trace_id == trace_id)))
    purge_trace(db_session, tenant_id=tenant.id, trace_id=trace_id, archive_id=record.id, store=store, settings=settings, witness_provider=witness, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert db_session.scalars(select(Span).where(Span.tenant_id == tenant.id, Span.trace_id == trace_id)).all() == []
    assert len(db_session.scalars(select(EventLog).where(EventLog.tenant_id == tenant.id, EventLog.trace_id == trace_id)).all()) == len(before_events)
    assert len(db_session.scalars(select(IntegrityRecord).where(IntegrityRecord.tenant_id == tenant.id, IntegrityRecord.trace_id == trace_id)).all()) == len(before_records)
    assert retrieve_archive(db_session, tenant_id=tenant.id, archive_id=record.id, store=store, settings=settings)["manifest"]["trace_id"] == trace_id


def test_v16_hold_blocks_purge_and_key_is_not_request_controlled(db_session):
    private = Ed25519PrivateKey.generate(); settings = _settings(private)
    tenant, trace_id, witness = _trace(db_session, settings)
    store = InMemoryArchiveStore(); record = archive_trace(db_session, tenant_id=tenant.id, trace_id=trace_id, store=store, settings=settings, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    create_hold(db_session, tenant_id=tenant.id, subject_type="TRACE", trace_id=trace_id, reason="preserve", principal_type="API_KEY", principal_id="key")
    with pytest.raises(Exception, match="RETENTION_HOLD_ACTIVE"):
        purge_trace(db_session, tenant_id=tenant.id, trace_id=trace_id, archive_id=record.id, store=store, settings=settings, witness_provider=witness, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert "purge this trace now" not in archive_object_key(tenant.id, record.id)


def test_v16_late_data_marks_archive_stale_and_blocks_purge(db_session):
    private = Ed25519PrivateKey.generate(); settings = _settings(private)
    tenant, trace_id, witness = _trace(db_session, settings)
    store = InMemoryArchiveStore()
    record = archive_trace(db_session, tenant_id=tenant.id, trace_id=trace_id, store=store, settings=settings,
                           now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    late = datetime(2026, 1, 2, tzinfo=timezone.utc)
    ingest_events(db_session, [
        Event(event_type="span.started", event_id=f"late-{trace_id}", occurred_at=late,
              data={"trace_id": trace_id, "span_id": f"late-{trace_id}", "name": "late-data"}),
        Event(event_type="span.ended", event_id=f"late-end-{trace_id}", occurred_at=late,
              data={"trace_id": trace_id, "span_id": f"late-{trace_id}", "status": "ok"}),
    ], tenant.id)
    with pytest.raises(ArchiveEligibilityError, match="ARCHIVE_PROJECTION_STALE"):
        purge_trace(db_session, tenant_id=tenant.id, trace_id=trace_id, archive_id=record.id, store=store,
                    settings=settings, witness_provider=witness, now=datetime(2026, 1, 3, tzinfo=timezone.utc))
    assert db_session.scalars(select(Span).where(Span.tenant_id == tenant.id, Span.trace_id == trace_id)).all()


def test_v16_witness_unavailable_and_remote_ahead_block_purge(db_session):
    private = Ed25519PrivateKey.generate(); settings = _settings(private)

    class UnavailableWitness:
        def latest(self, namespace):
            raise AnchorUnavailable("witness unavailable")

    class AheadWitness:
        def latest(self, namespace):
            return {"checkpoint_sequence": 999, "checkpoint_digest": "f" * 64}

    for witness_provider in (UnavailableWitness(), AheadWitness()):
        tenant, trace_id, real_witness = _trace(db_session, settings)
        store = InMemoryArchiveStore()
        record = archive_trace(db_session, tenant_id=tenant.id, trace_id=trace_id, store=store, settings=settings,
                               now=datetime(2026, 1, 1, tzinfo=timezone.utc))
        with pytest.raises(Exception, match="V15_REMOTE_NOT_MATCH"):
            purge_trace(db_session, tenant_id=tenant.id, trace_id=trace_id, archive_id=record.id, store=store,
                        settings=settings, witness_provider=witness_provider,
                        now=datetime(2026, 1, 2, tzinfo=timezone.utc))
        assert db_session.scalars(select(Span).where(Span.tenant_id == tenant.id, Span.trace_id == trace_id)).all()


def test_v16_worker_claim_reclaims_after_crash_lease(db_session):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tenant = create_tenant(db_session, f"v16-claim-{uuid4().hex[:10]}", "claim")
    job = queue_retention_job(db_session, tenant_id=tenant.id, trace_id="crash-reclaim", now=now)
    first = claim_retention_job(db_session, job_id=job.id, instance_id="worker-a", lease_seconds=5, now=now)
    assert first is not None and first.claimed_by == "worker-a"
    assert claim_retention_job(db_session, job_id=job.id, instance_id="worker-b", lease_seconds=5,
                               now=now + timedelta(seconds=1)) is None
    second = claim_retention_job(db_session, job_id=job.id, instance_id="worker-b", lease_seconds=5,
                                 now=now + timedelta(seconds=6))
    assert second is not None and second.claimed_by == "worker-b" and second.attempt_count == 2


def test_v16_upload_retry_and_conflict_are_not_silent(db_session):
    private = Ed25519PrivateKey.generate(); settings = _settings(private)

    class FlakyStore(InMemoryArchiveStore):
        fail_once = True
        def put(self, object_key, body):
            if self.fail_once:
                self.fail_once = False
                raise ArchiveStoreUnavailable("temporary outage")
            return super().put(object_key, body)

    tenant, trace_id, witness = _trace(db_session, settings)
    store = FlakyStore()
    with pytest.raises(ArchiveVerificationError, match="OBJECT_STORE_UNAVAILABLE"):
        archive_trace(db_session, tenant_id=tenant.id, trace_id=trace_id, store=store, settings=settings,
                      now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    retried = archive_trace(db_session, tenant_id=tenant.id, trace_id=trace_id, store=store, settings=settings,
                            now=datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert retried.lifecycle.status == "ARCHIVED_VERIFIED"
    store.objects[retried.object_key] = b"different archive bytes"
    retried.lifecycle.status = "FAILED"
    db_session.commit()
    with pytest.raises(ArchiveVerificationError, match="ARCHIVE_OBJECT_CONFLICT"):
        archive_trace(db_session, tenant_id=tenant.id, trace_id=trace_id, store=store, settings=settings,
                      now=datetime(2026, 1, 3, tzinfo=timezone.utc))
