"""V19 public-seam tests: deterministic bytes, authenticated envelopes, and fail closed."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4
import base64
import json

import pytest

from agentguard_server.services.archive import ArchiveKeyring
from agentguard_server.services.integrity_segments import (
    INTEGRITY_SEGMENT_ENVELOPE_VERSION,
    IntegritySegmentEligibilityError, IntegritySegmentKeyMissing,
    IntegritySegmentVerificationError,
    build_integrity_segment_payload,
    integrity_records_manifest_digest,
    seal_integrity_segment,
    unseal_integrity_segment,
)
from agentguard_server.models import (ArchiveReplica, IntegrityArchiveSegment,
    IntegrityCompactionAuthorization, IntegrityCheckpoint, IntegrityRecord,
    LedgerSegment, LedgerSegmentLifecycle, Tenant)
from agentguard_server.services.replicas import INTEGRITY_SEGMENT
from agentguard_server.services.archive_store import set_archive_store_registry_for_tests
from agentguard_server.config import get_settings


def _record(tenant, trace, sequence):
    return {
        "id": str(uuid4()), "tenant_id": str(tenant), "trace_id": trace,
        "sequence": sequence, "event_id": f"evt-{sequence}", "event_type": "tool.completed",
        "event_digest": f"{sequence:064x}", "previous_chain_mac": None if sequence == 1 else f"{sequence - 1:064x}",
        "chain_mac": f"{sequence + 100:064x}", "key_id": "v3-test",
        "canonicalization_version": "jcs-lite-v1", "created_at": "2026-01-01T00:00:00.000Z",
    }


def _segment(tenant, trace, sequence=1):
    return SimpleNamespace(id=uuid4(), tenant_id=tenant, trace_id=trace, segment_sequence=sequence,
                           logical_segment_digest=None, ciphertext_sha256=None, plaintext_sha256=None,
                           archive_key_id=None)


def _sealed():
    tenant, trace = uuid4(), "trace-v19"
    segment = _segment(tenant, trace)
    records = [_record(tenant, trace, 1), _record(tenant, trace, 2)]
    plaintext, manifest = build_integrity_segment_payload(
        segment_id=segment.id, tenant_id=tenant, trace_id=trace, segment_sequence=1,
        records=records, v17_ledger_segment_id=uuid4(), v17_ledger_segment_digest="a" * 64,
        v15_checkpoint_id=uuid4(), v15_checkpoint_digest="b" * 64, v15_continuity_status="MATCH",
        predecessor_boundary_hash=None, successor_boundary_hash=records[-1]["chain_mac"],
    )
    segment.logical_segment_digest = manifest["logical_segment_digest"]
    keyring = ArchiveKeyring({"archive-v19": b"k" * 32}, "archive-v19")
    return segment, records, plaintext, seal_integrity_segment(segment=segment, plaintext=plaintext, keyring=keyring), keyring


def test_manifest_is_order_independent_and_complete():
    tenant, trace = uuid4(), "trace-order"
    records = [_record(tenant, trace, 1), _record(tenant, trace, 2)]
    assert integrity_records_manifest_digest(records) == integrity_records_manifest_digest(list(reversed(records)))
    changed = dict(records[0]); changed["key_id"] = "different"
    assert integrity_records_manifest_digest([changed, records[1]]) != integrity_records_manifest_digest(records)


def test_payload_serialization_is_stable():
    segment, records, plaintext, _, _ = _sealed()
    rebuilt, manifest = build_integrity_segment_payload(
        segment_id=segment.id, tenant_id=segment.tenant_id, trace_id=segment.trace_id,
        segment_sequence=1, records=records, v17_ledger_segment_id=uuid4(),
        v17_ledger_segment_digest="a" * 64, v15_checkpoint_id=uuid4(),
        v15_checkpoint_digest="b" * 64, v15_continuity_status="MATCH",
        predecessor_boundary_hash=None, successor_boundary_hash=records[-1]["chain_mac"],
    )
    assert json.loads(rebuilt)["manifest"]["segment_version"] == "integrity-segment-v1"
    assert manifest["logical_segment_digest"]
    assert plaintext


def test_round_trip_requires_exact_v19_envelope_and_digest():
    segment, records, plaintext, object_bytes, keyring = _sealed()
    payload, restored = unseal_integrity_segment(object_bytes=object_bytes, segment=segment, keyring=keyring)
    assert restored == plaintext
    assert payload["records"] == records
    assert json.loads(object_bytes)["envelope_version"] == INTEGRITY_SEGMENT_ENVELOPE_VERSION


def test_ciphertext_tampering_fails_closed():
    segment, _, _, object_bytes, keyring = _sealed()
    envelope = json.loads(object_bytes)
    raw = bytearray(base64.b64decode(envelope["ciphertext"]))
    raw[-1] ^= 1
    envelope["ciphertext"] = base64.b64encode(raw).decode()
    with pytest.raises(IntegritySegmentVerificationError):
        unseal_integrity_segment(object_bytes=json.dumps(envelope).encode(), segment=segment, keyring=keyring)


def test_missing_archive_key_is_unverifiable_not_invalid():
    segment, _, _, object_bytes, _ = _sealed()
    with pytest.raises(IntegritySegmentKeyMissing) as failure:
        unseal_integrity_segment(object_bytes=object_bytes, segment=segment,
                                 keyring=ArchiveKeyring({"other": b"x" * 32}, "other"))
    assert failure.value.status == "UNVERIFIABLE_V3_KEY_MISSING"


def test_segment_identity_is_authenticated():
    segment, _, _, object_bytes, keyring = _sealed()
    segment.trace_id = "other-trace"
    with pytest.raises(IntegritySegmentVerificationError) as failure:
        unseal_integrity_segment(object_bytes=object_bytes, segment=segment, keyring=keyring)
    assert failure.value.status == "INTEGRITY_SEGMENT_IDENTITY_MISMATCH"


def test_gap_is_rejected_before_archival():
    tenant, trace = uuid4(), "trace-gap"
    records = [_record(tenant, trace, 1), _record(tenant, trace, 3)]
    with pytest.raises(IntegritySegmentEligibilityError):
        build_integrity_segment_payload(segment_id=uuid4(), tenant_id=tenant, trace_id=trace,
                                         segment_sequence=1, records=records, v17_ledger_segment_id=uuid4(),
                                         v17_ledger_segment_digest="a" * 64, v15_checkpoint_id=uuid4(),
                                         v15_checkpoint_digest="b" * 64, v15_continuity_status="MATCH",
                                         predecessor_boundary_hash=None, successor_boundary_hash=None)


def test_compaction_fault_rolls_back_and_keeps_source(db_session):
    tenant = Tenant(slug="v19-fault-tenant", name="V19 fault", created_at=datetime.now(timezone.utc))
    db_session.add(tenant); db_session.flush()
    now = datetime.now(timezone.utc)
    record = IntegrityRecord(id=uuid4(), tenant_id=tenant.id, trace_id="fault-trace", sequence=1,
                             event_id="event-1", event_type="trace.started", event_digest="a" * 64,
                             previous_chain_mac=None, chain_mac="b" * 64, key_id="v1",
                             canonicalization_version="jcs-lite-v1", created_at=now - timedelta(days=40))
    db_session.add(record); db_session.flush()
    segment = IntegrityArchiveSegment(id=uuid4(), tenant_id=tenant.id, trace_id="fault-trace", segment_sequence=1,
        segment_version="integrity-segment-v1", envelope_version="integrity-segment-envelope-v1",
        source_start_sequence=1, source_end_sequence=1, record_count=1, first_record_id=record.id,
        last_record_id=record.id, first_event_hash="a" * 64, last_event_hash="a" * 64,
        predecessor_boundary_hash=None, successor_boundary_hash="next" * 16,
        records_manifest_digest=integrity_records_manifest_digest([record]), logical_segment_digest="d" * 64,
        plaintext_sha256="e" * 64, ciphertext_sha256="f" * 64, archive_key_id="archive-v19",
        archive_object_key="agentguard/integrity/v1/x.agintegrity", v17_ledger_segment_id=uuid4(),
        v17_ledger_segment_digest="1" * 64, v15_checkpoint_id=uuid4(), v15_checkpoint_digest="2" * 64,
        v15_continuity_status="MATCH", state="READY_TO_COMPACT", created_at=now, updated_at=now)
    db_session.add(segment); db_session.flush()
    checkpoint = IntegrityCheckpoint(id=segment.v15_checkpoint_id, namespace="v19-key-recheck",
        checkpoint_sequence=1, checkpoint_version="checkpoint-v1", manifest_digest="c" * 64,
        previous_checkpoint_digest=None, checkpoint_digest=segment.v15_checkpoint_digest,
        entry_count=0, created_at=now)
    ledger = LedgerSegment(id=segment.v17_ledger_segment_id, tenant_id=tenant.id,
        trace_id=segment.trace_id, segment_sequence=1, segment_version="ledger-segment-v1",
        start_event_sequence=1, end_event_sequence=1, start_previous_hash=None,
        end_event_hash="a" * 64, event_count=1, events_manifest_digest="1" * 64,
        segment_manifest_digest=segment.v17_ledger_segment_digest,
        archive_object_key="agentguard/ledger/v1/key-recheck.agledger", created_at=now)
    db_session.add_all([checkpoint, ledger, LedgerSegmentLifecycle(segment_id=ledger.id,
        status="COMPACTED", updated_at=now)])
    auth = IntegrityCompactionAuthorization(segment_id=segment.id, tenant_id=tenant.id, source_start_sequence=1,
        source_end_sequence=1, record_count=1, logical_segment_digest=segment.logical_segment_digest,
        ciphertext_sha256=segment.ciphertext_sha256, predecessor_boundary_hash=None,
        successor_boundary_hash=segment.successor_boundary_hash, replica_policy_version="archive-replica-policy-v1",
        verified_replica_count=1, v17_ledger_segment_digest=segment.v17_ledger_segment_digest,
        v15_checkpoint_digest=segment.v15_checkpoint_digest, v15_continuity_status="MATCH",
        verified_at=now, expires_at=now + timedelta(minutes=1), authorized_by_instance="test", created_at=now)
    db_session.add(auth)
    db_session.add(ArchiveReplica(tenant_id=tenant.id, logical_archive_type=INTEGRITY_SEGMENT,
        logical_archive_id=segment.id, store_id="primary", object_key=segment.archive_object_key,
        expected_ciphertext_sha256=segment.ciphertext_sha256, expected_plaintext_sha256=segment.plaintext_sha256,
        expected_logical_digest=segment.logical_segment_digest, encryption_key_id="archive-v19", state="VALID",
        verified_at=now, created_at=now, updated_at=now))
    db_session.commit()
    settings = get_settings().model_copy(update={"archive_replication_enabled": False,
                                                   "archive_encryption_keys": json.dumps({"archive-v19": base64.b64encode(b"k" * 32).decode()}),
                                                   "archive_encryption_key_id": "archive-v19"})
    set_archive_store_registry_for_tests({"primary": SimpleNamespace()})
    try:
        from agentguard_server.services.integrity_segments import compact_integrity_segment, IntegritySegmentError
        with pytest.raises(IntegritySegmentError):
            compact_integrity_segment(db_session, segment.id, settings=settings, now=now, fault_inject=True)
        assert db_session.get(IntegrityRecord, record.id) is not None
        assert db_session.get(IntegrityArchiveSegment, segment.id).state == "READY_TO_COMPACT"
    finally:
        set_archive_store_registry_for_tests({})


def test_compaction_rechecks_archive_key_before_delete(db_session, monkeypatch):
    tenant = Tenant(slug="v19-key-recheck-tenant", name="V19 key recheck", created_at=datetime.now(timezone.utc))
    db_session.add(tenant); db_session.flush()
    now = datetime.now(timezone.utc)
    record = IntegrityRecord(id=uuid4(), tenant_id=tenant.id, trace_id="key-recheck-trace", sequence=1,
                             event_id="event-1", event_type="trace.started", event_digest="a" * 64,
                             previous_chain_mac=None, chain_mac="b" * 64, key_id="v1",
                             canonicalization_version="jcs-lite-v1", created_at=now - timedelta(days=40))
    db_session.add(record); db_session.flush()
    segment = IntegrityArchiveSegment(id=uuid4(), tenant_id=tenant.id, trace_id="key-recheck-trace", segment_sequence=1,
        segment_version="integrity-segment-v1", envelope_version="integrity-segment-envelope-v1",
        source_start_sequence=1, source_end_sequence=1, record_count=1, first_record_id=record.id,
        last_record_id=record.id, first_event_hash="a" * 64, last_event_hash="a" * 64,
        predecessor_boundary_hash=None, successor_boundary_hash="next" * 16,
        records_manifest_digest=integrity_records_manifest_digest([record]), logical_segment_digest="d" * 64,
        plaintext_sha256="e" * 64, ciphertext_sha256="f" * 64, archive_key_id="archive-v19",
        archive_object_key="agentguard/integrity/v1/key-recheck.agintegrity", v17_ledger_segment_id=uuid4(),
        v17_ledger_segment_digest="1" * 64, v15_checkpoint_id=uuid4(), v15_checkpoint_digest="2" * 64,
        v15_continuity_status="MATCH", state="READY_TO_COMPACT", created_at=now, updated_at=now)
    db_session.add(segment); db_session.flush()
    checkpoint = IntegrityCheckpoint(id=segment.v15_checkpoint_id, namespace="v19-key-recheck",
        checkpoint_sequence=1, checkpoint_version="checkpoint-v1", manifest_digest="c" * 64,
        previous_checkpoint_digest=None, checkpoint_digest=segment.v15_checkpoint_digest,
        entry_count=0, created_at=now)
    ledger = LedgerSegment(id=segment.v17_ledger_segment_id, tenant_id=tenant.id,
        trace_id=segment.trace_id, segment_sequence=1, segment_version="ledger-segment-v1",
        start_event_sequence=1, end_event_sequence=1, start_previous_hash=None,
        end_event_hash="a" * 64, event_count=1, events_manifest_digest="1" * 64,
        segment_manifest_digest=segment.v17_ledger_segment_digest,
        archive_object_key="agentguard/ledger/v1/key-recheck.agledger", created_at=now)
    db_session.add_all([checkpoint, ledger, LedgerSegmentLifecycle(segment_id=ledger.id,
        status="COMPACTED", updated_at=now)])
    auth = IntegrityCompactionAuthorization(segment_id=segment.id, tenant_id=tenant.id, source_start_sequence=1,
        source_end_sequence=1, record_count=1, logical_segment_digest=segment.logical_segment_digest,
        ciphertext_sha256=segment.ciphertext_sha256, predecessor_boundary_hash=None,
        successor_boundary_hash=segment.successor_boundary_hash, replica_policy_version="archive-replica-policy-v1",
        verified_replica_count=1, v17_ledger_segment_digest=segment.v17_ledger_segment_digest,
        v15_checkpoint_digest=segment.v15_checkpoint_digest, v15_continuity_status="MATCH",
        verified_at=now, expires_at=now + timedelta(minutes=1), authorized_by_instance="test", created_at=now)
    db_session.add(auth)
    db_session.add(ArchiveReplica(tenant_id=tenant.id, logical_archive_type=INTEGRITY_SEGMENT,
        logical_archive_id=segment.id, store_id="primary", object_key=segment.archive_object_key,
        expected_ciphertext_sha256=segment.ciphertext_sha256, expected_plaintext_sha256=segment.plaintext_sha256,
        expected_logical_digest=segment.logical_segment_digest, encryption_key_id="archive-v19", state="VALID",
        verified_at=now, created_at=now, updated_at=now))
    db_session.commit()
    settings = get_settings().model_copy(update={"archive_replication_enabled": False,
                                                   "archive_encryption_keys": json.dumps({"archive-v19": base64.b64encode(b"k" * 32).decode()}),
                                                   "archive_encryption_key_id": "archive-v19"})
    set_archive_store_registry_for_tests({"primary": SimpleNamespace()})
    import agentguard_server.services.integrity_segments as segments_service
    monkeypatch.setattr(segments_service, "verify_checkpoint", lambda *args, **kwargs: {"status": "VALID"})
    monkeypatch.setattr(segments_service, "read_integrity_segment_with_fallback",
                        lambda *args, **kwargs: (_ for _ in ()).throw(IntegritySegmentKeyMissing()))
    try:
        from agentguard_server.services.integrity_segments import compact_integrity_segment
        with pytest.raises(IntegritySegmentKeyMissing):
            compact_integrity_segment(db_session, segment.id, settings=settings, now=now)
        assert db_session.get(IntegrityRecord, record.id) is not None
        assert db_session.get(IntegrityArchiveSegment, segment.id).state == "READY_TO_COMPACT"
    finally:
        set_archive_store_registry_for_tests({})


def test_compaction_rejects_overlapping_segment_before_delete(db_session):
    tenant = Tenant(slug="v19-overlap-tenant", name="V19 overlap", created_at=datetime.now(timezone.utc))
    db_session.add(tenant); db_session.flush()
    now = datetime.now(timezone.utc)
    values = dict(
        segment_version="integrity-segment-v1", envelope_version="integrity-segment-envelope-v1",
        source_start_sequence=1, source_end_sequence=4, record_count=4,
        first_record_id=uuid4(), last_record_id=uuid4(), first_event_hash="a" * 64,
        last_event_hash="b" * 64, predecessor_boundary_hash=None,
        successor_boundary_hash="c" * 64, records_manifest_digest="d" * 64,
        logical_segment_digest="e" * 64, plaintext_sha256="f" * 64,
        ciphertext_sha256="0" * 64, archive_key_id="archive-v19",
        archive_object_key="agentguard/integrity/v1/overlap.agintegrity",
        v17_ledger_segment_id=uuid4(), v17_ledger_segment_digest="1" * 64,
        v15_checkpoint_id=uuid4(), v15_checkpoint_digest="2" * 64,
        v15_continuity_status="MATCH", state="READY_TO_COMPACT",
        created_at=now, updated_at=now,
    )
    segment = IntegrityArchiveSegment(id=uuid4(), tenant_id=tenant.id, trace_id="overlap-trace", segment_sequence=1, **values)
    overlap = IntegrityArchiveSegment(id=uuid4(), tenant_id=tenant.id, trace_id="overlap-trace", segment_sequence=2,
        **{**values, "source_start_sequence": 2, "source_end_sequence": 5,
           "archive_object_key": "agentguard/integrity/v1/overlap-2.agintegrity", "state": "PLANNED"})
    db_session.add_all([segment, overlap]); db_session.commit()
    from agentguard_server.services.integrity_segments import compact_integrity_segment
    with pytest.raises(IntegritySegmentEligibilityError) as failure:
        compact_integrity_segment(db_session, segment.id, settings=get_settings())
    assert failure.value.reason == "INTEGRITY_SEGMENT_OVERLAP"
    assert db_session.get(IntegrityArchiveSegment, segment.id).state == "READY_TO_COMPACT"
