from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from agentguard_server.models import EventLog, IntegrityRecord
from agentguard_server.schemas.events import Event
from agentguard_server.services.integrity import canonicalize_evidence
from agentguard_server.services.ingestion import IdempotencyConflict, ingest_events
from agentguard_server.services.integrity import verify_trace_integrity
from agentguard_server.config import Settings, get_settings
from agentguard_server.services.auth import create_tenant


def test_canonicalize_evidence_is_deterministic_and_uses_nfc_utc_and_sorted_keys():
    first = canonicalize_evidence(
        event_type="trace.started",
        event_id="event-1",
        schema_version="0.1",
        data={
            "z": "cafe\u0301",
            "a": True,
            "occurred_at": datetime(2026, 1, 1, 1, 2, 3, 456000, tzinfo=timezone.utc),
        },
    )
    second = canonicalize_evidence(
        event_type="trace.started",
        event_id="event-1",
        schema_version="0.1",
        data={
            "occurred_at": "2026-01-01T01:02:03.456Z",
            "a": True,
            "z": "café",
        },
    )

    assert first == second
    assert first == b'{"data":{"a":true,"occurred_at":"2026-01-01T01:02:03.456Z","z":"caf\xc3\xa9"},"event_id":"event-1","event_type":"trace.started","schema_version":"0.1"}'


def test_canonicalize_evidence_rejects_non_finite_numbers():
    with pytest.raises(ValueError, match="finite"):
        canonicalize_evidence(event_type="trace.started", event_id="event-1", schema_version="0.1", data={"value": float("nan")})


def test_trace_integrity_chain_and_idempotency(db_session):
    tenant = create_tenant(db_session, f"integrity-{uuid4().hex[:10]}", "Integrity test")
    trace_id = f"trace-{uuid4().hex}"
    events = [
        Event(event_type="trace.started", event_id=trace_id, data={"trace_id": trace_id, "metadata": {"json": {"ok": True}}}),
        Event(event_type="span.started", event_id="root", data={"trace_id": trace_id, "span_id": "root", "name": "root"}),
        Event(event_type="span.started", event_id="child", data={"trace_id": trace_id, "span_id": "child", "parent_span_id": "root", "attributes": {"count": 2}}),
    ]
    assert ingest_events(db_session, events, tenant.id) == (3, 0)
    assert ingest_events(db_session, [events[2]], tenant.id) == (0, 1)
    result = verify_trace_integrity(db_session, tenant.id, trace_id)
    assert result.status == "valid", result
    assert result.events_checked == 3
    assert result.chain_valid is True
    assert result.projection_consistent is True

    conflict = Event(event_type="span.started", event_id="child", data={"trace_id": trace_id, "span_id": "child", "parent_span_id": "root", "attributes": {"count": 9}})
    with pytest.raises(IdempotencyConflict):
        ingest_events(db_session, [conflict], tenant.id)
    assert db_session.scalar(select(IntegrityRecord).where(IntegrityRecord.tenant_id == tenant.id, IntegrityRecord.trace_id == trace_id).order_by(IntegrityRecord.sequence.desc())).sequence == 3


def test_trace_integrity_detects_payload_and_chain_tampering(db_session):
    tenant = create_tenant(db_session, f"tamper-{uuid4().hex[:10]}", "Tamper test")
    trace_id = f"tamper-{uuid4().hex}"
    event = Event(event_type="trace.started", event_id=trace_id, data={"trace_id": trace_id, "metadata": {"safe": True}})
    assert ingest_events(db_session, [event], tenant.id) == (1, 0)
    row = db_session.scalar(select(EventLog).where(EventLog.tenant_id == tenant.id, EventLog.trace_id == trace_id))
    assert row is not None
    row.payload_json = {"data": {"trace_id": trace_id, "metadata": {"safe": False}}, "schema_version": "0.1"}
    db_session.commit()
    result = verify_trace_integrity(db_session, tenant.id, trace_id)
    assert result.status == "invalid"
    assert result.first_failure == "event_digest_mismatch"


def test_integrity_endpoint_is_tenant_scoped_and_safe(client):
    trace_id = f"api-{uuid4().hex}"
    response = client.post("/v1/ingest", json={"events": [
        {"event_type": "trace.started", "event_id": trace_id, "data": {"trace_id": trace_id}},
    ]})
    assert response.status_code == 202
    integrity = client.get(f"/v1/traces/{trace_id}/integrity")
    assert integrity.status_code == 200
    assert integrity.json() == {
        "trace_id": trace_id,
        "status": "valid",
        "events_checked": 1,
        "chain_valid": True,
        "projection_consistent": True,
    }
    assert "chain_mac" not in integrity.text
    assert client.get("/v1/traces/does-not-exist/integrity").status_code == 404


def test_integrity_key_rotation_requires_retired_verification_key(db_session):
    settings = get_settings()
    original = (settings.integrity_key, settings.integrity_key_id, settings.integrity_verify_keys)
    old_key = "old-integrity-test-key-with-32-bytes!!"
    try:
        settings.integrity_key = old_key
        settings.integrity_key_id = "v1"
        settings.integrity_verify_keys = None
        tenant = create_tenant(db_session, f"rotation-{uuid4().hex[:10]}", "Rotation test")
        trace_id = f"rotation-{uuid4().hex}"
        event = Event(event_type="trace.started", event_id=trace_id, data={"trace_id": trace_id})
        assert ingest_events(db_session, [event], tenant.id) == (1, 0)

        settings.integrity_key = "new-integrity-test-key-with-32-bytes!!"
        settings.integrity_key_id = "v2"
        assert verify_trace_integrity(db_session, tenant.id, trace_id).first_failure == "UNVERIFIABLE_KEY_MISSING"
        settings.integrity_verify_keys = '{"v1":"old-integrity-test-key-with-32-bytes!!"}'
        assert verify_trace_integrity(db_session, tenant.id, trace_id).status == "valid"
        assert verify_trace_integrity(db_session, tenant.id, trace_id).first_failure is None
        missing_key_settings = Settings()
        missing_key_settings.integrity_key = None
        missing_key_settings.integrity_verify_keys = None
        assert verify_trace_integrity(db_session, tenant.id, trace_id, missing_key_settings).first_failure == "UNVERIFIABLE_KEY_MISSING"
    finally:
        settings.integrity_key, settings.integrity_key_id, settings.integrity_verify_keys = original
