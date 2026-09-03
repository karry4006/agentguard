import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from agentguard_server.config import Settings
from agentguard_server.models import (
    EventLog, IntegrityRecord, LedgerCompactionAuthorization, LedgerEventArchiveIndex,
    LedgerSegmentLifecycle, Trace,
)
from agentguard_server.services.archive import ArchiveKeyring
from agentguard_server.services.archive_store import InMemoryArchiveStore
from agentguard_server.services.integrity import canonicalize_evidence, evidence_digest, append_integrity_record
from agentguard_server.services.ledger import (
    LEDGER_SEGMENT_VERSION, _events_for_records,
    _segment_payload, compact_ledger_segment, create_ledger_segment_candidate,
    events_manifest_digest, seal_ledger_segment, unseal_ledger_segment,
    LedgerArchiveKeyMissing, verify_mixed_ledger, verify_v3_events,
)
from agentguard_server.services.auth import create_tenant


def _settings(tmp_path, *, archive=True, compact=True):
    key = base64.b64encode(b"v17-archive-key-0123456789012345").decode("ascii")
    return Settings(
        _env_file=None, database_url=f"sqlite:///{tmp_path / 'v17.db'}", environment="test",
        key_pepper="v17-test-pepper", integrity_key="v17-integrity-key-012345678901234567890",
        ledger_archive_enabled=archive, ledger_compaction_enabled=compact,
        ledger_hot_tail_events=1, ledger_segment_min_age_days=0,
        archive_encryption_keys=json.dumps({"archive-key-v1": key}),
    )


def _seed_chain(db, settings, count=5):
    tenant = create_tenant(db, f"v17-{uuid4().hex[:12]}", "V17 test tenant")
    trace_id = f"trace-{uuid4().hex}"
    now = datetime.now(timezone.utc)
    db.add(Trace(tenant_id=tenant.id, trace_id=trace_id, status="running", metadata_json={}, schema_version="0.1", started_at=now))
    db.commit()
    for index in range(1, count + 1):
        event_id = f"event-{index}"
        data = {"message": f"event-{index}"}
        payload = {"schema_version": "0.1", "data": data}
        digest = evidence_digest(canonicalize_evidence(event_type="trace.note", event_id=event_id, schema_version="0.1", data=data))
        append_integrity_record(db, tenant_id=tenant.id, trace_id=trace_id, event_type="trace.note", event_id=event_id, event_digest_value=digest, settings=settings)
        db.add(EventLog(tenant_id=tenant.id, trace_id=trace_id, event_id=event_id, event_type="trace.note", event_key=f"trace.note:{event_id}", payload_json=payload, event_digest=digest))
        db.commit()
    return tenant, trace_id


def test_v17_segment_serialization_is_deterministic_and_domain_separated(tmp_path, db_session):
    settings = _settings(tmp_path)
    tenant, trace_id = _seed_chain(db_session, settings)
    records = list(db_session.scalars(select(IntegrityRecord).where(IntegrityRecord.tenant_id == tenant.id).order_by(IntegrityRecord.sequence)))
    events = _events_for_records(db_session, records)
    result = verify_v3_events(tenant_id=tenant.id, trace_id=trace_id, events=events, settings=settings, expected_start=1, expected_end=5)
    assert result.status == "VALID"
    segment = type("Segment", (), {"id": uuid4(), "tenant_id": tenant.id, "trace_id": trace_id, "segment_sequence": 1,
        "start_event_sequence": 1, "end_event_sequence": 4, "start_previous_hash": records[0].previous_chain_mac,
        "end_event_hash": records[3].chain_mac, "covering_checkpoint_sequence": 1, "covering_checkpoint_digest": "c" * 64})()
    plaintext, manifest = _segment_payload(segment, events[:4], None)
    assert manifest["segment_version"] == LEDGER_SEGMENT_VERSION
    assert manifest["events_manifest_digest"] == events_manifest_digest(events[:4])
    keyring = ArchiveKeyring({"archive-key-v1": b"v17-archive-key-0123456789012345"}, "archive-key-v1")
    object_bytes = seal_ledger_segment(segment=segment, plaintext=plaintext, keyring=keyring)
    payload, _ = unseal_ledger_segment(object_bytes=object_bytes, segment=segment, keyring=keyring)
    assert payload["manifest"]["segment_manifest_digest"] == manifest["segment_manifest_digest"]
    assert "delete" not in payload
    with pytest.raises(Exception):
        unseal_ledger_segment(object_bytes=object_bytes[:-1] + b"x", segment=segment, keyring=keyring)
    with pytest.raises(LedgerArchiveKeyMissing, match="UNVERIFIABLE_ARCHIVE_KEY_MISSING"):
        unseal_ledger_segment(object_bytes=object_bytes, segment=segment,
                              keyring=ArchiveKeyring({}, "missing"))


def test_v17_candidate_is_bounded_by_hot_tail_and_compaction_is_exact_and_idempotent(tmp_path, db_session):
    settings = _settings(tmp_path)
    tenant, trace_id = _seed_chain(db_session, settings)
    segment = create_ledger_segment_candidate(db_session, tenant_id=tenant.id, trace_id=trace_id, settings=settings)
    assert (segment.start_event_sequence, segment.end_event_sequence, segment.event_count) == (1, 4, 4)
    records = list(db_session.scalars(select(IntegrityRecord).where(IntegrityRecord.tenant_id == tenant.id).order_by(IntegrityRecord.sequence)))
    events = _events_for_records(db_session, records[:4])
    segment.covering_checkpoint_digest = "c" * 64
    segment.archive_ciphertext_sha256 = "b" * 64
    segment.segment_manifest_digest = "a" * 64
    lifecycle = db_session.get(LedgerSegmentLifecycle, segment.id)
    lifecycle.status = "COMPACTION_AUTHORIZED"
    for event in events:
        db_session.add(LedgerEventArchiveIndex(tenant_id=tenant.id, trace_id=trace_id, event_id=event["event_id"], event_sequence=event["sequence"], segment_id=segment.id, event_hash=event["event_digest"], original_created_at=datetime.now(timezone.utc)))
    now = datetime.now(timezone.utc)
    db_session.add(LedgerCompactionAuthorization(segment_id=segment.id, segment_manifest_digest="a" * 64, archive_ciphertext_sha256="b" * 64, covering_checkpoint_digest="c" * 64, remote_continuity_status="MATCH", verified_at=now, expires_at=now + timedelta(minutes=1), authorized_by_instance="test", created_at=now))
    db_session.commit()
    with pytest.raises(RuntimeError, match="injected compaction transaction failure"):
        compact_ledger_segment(db_session, segment.id, settings=settings, fault_inject=True)
    assert db_session.scalars(select(EventLog).where(
        EventLog.tenant_id == tenant.id, EventLog.trace_id == trace_id,
    )).all()
    assert db_session.scalar(select(LedgerSegmentLifecycle.status).where(
        LedgerSegmentLifecycle.segment_id == segment.id,
    )) == "COMPACTION_AUTHORIZED"
    assert compact_ledger_segment(db_session, segment.id, settings=settings) == 4
    remaining = list(db_session.scalars(select(EventLog).where(EventLog.tenant_id == tenant.id, EventLog.trace_id == trace_id)))
    assert len(remaining) == 1 and remaining[0].event_id == "event-5"
    assert db_session.scalar(select(IntegrityRecord).where(IntegrityRecord.tenant_id == tenant.id, IntegrityRecord.trace_id == trace_id, IntegrityRecord.sequence == 1)) is not None
    assert compact_ledger_segment(db_session, segment.id, settings=settings) == 0


def test_v17_mixed_verifier_reads_compacted_segment_and_fails_closed_on_missing_object(tmp_path, db_session):
    settings = _settings(tmp_path)
    tenant, trace_id = _seed_chain(db_session, settings)
    segment = create_ledger_segment_candidate(db_session, tenant_id=tenant.id, trace_id=trace_id, settings=settings)
    records = list(db_session.scalars(select(IntegrityRecord).where(
        IntegrityRecord.tenant_id == tenant.id, IntegrityRecord.trace_id == trace_id,
    ).order_by(IntegrityRecord.sequence)))
    events = _events_for_records(db_session, records[:4])
    segment.archive_object_key = f"agentguard/ledger/v1/{tenant.id}/{segment.id}.agledger"
    plaintext, manifest = _segment_payload(segment, events, None)
    keyring = ArchiveKeyring({"archive-key-v1": b"v17-archive-key-0123456789012345"}, "archive-key-v1")
    object_bytes = seal_ledger_segment(segment=segment, plaintext=plaintext, keyring=keyring)
    envelope = json.loads(object_bytes.decode("utf-8"))
    segment.segment_manifest_digest = manifest["segment_manifest_digest"]
    segment.archive_plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()
    segment.archive_ciphertext_sha256 = envelope["ciphertext_sha256"]
    segment.archive_encryption_key_id = envelope["key_id"]
    lifecycle = db_session.get(LedgerSegmentLifecycle, segment.id)
    lifecycle.status = "COMPACTED"
    lifecycle.updated_at = datetime.now(timezone.utc)
    for event in events:
        db_session.add(LedgerEventArchiveIndex(
            tenant_id=tenant.id, trace_id=trace_id, event_id=event["event_id"],
            event_sequence=event["sequence"], segment_id=segment.id,
            event_hash=event["event_digest"], original_created_at=datetime.now(timezone.utc),
        ))
    for row in list(db_session.scalars(select(EventLog).where(
        EventLog.tenant_id == tenant.id, EventLog.trace_id == trace_id,
        EventLog.event_id != "event-5",
    ))):
        db_session.delete(row)
    store = InMemoryArchiveStore()
    store.put(segment.archive_object_key, object_bytes)
    db_session.commit()

    result = verify_mixed_ledger(db_session, tenant_id=tenant.id, trace_id=trace_id,
                                 store=store, keyring=keyring, settings=settings)
    assert result.status == "VALID"
    del store.objects[segment.archive_object_key]
    missing = verify_mixed_ledger(db_session, tenant_id=tenant.id, trace_id=trace_id,
                                  store=store, keyring=keyring, settings=settings)
    assert missing.status == "SEGMENT_OBJECT_MISSING"


def test_v17_missing_v3_key_is_unverifiable_not_tampering(tmp_path, db_session):
    settings = _settings(tmp_path)
    tenant, trace_id = _seed_chain(db_session, settings, count=1)
    records = list(db_session.scalars(select(IntegrityRecord).where(IntegrityRecord.tenant_id == tenant.id)))
    events = _events_for_records(db_session, records)
    missing = settings.model_copy(update={"integrity_key": None, "integrity_verify_keys": None})
    result = verify_v3_events(tenant_id=tenant.id, trace_id=trace_id, events=events, settings=missing, expected_start=1, expected_end=1)
    assert result.status == "UNVERIFIABLE_V3_KEY_MISSING"
