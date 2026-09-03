"""Live V4 acceptance against the already-running AgentGuard Compose stack."""

import os
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import sessionmaker

from agentguard_server.models import EventLog, IntegrityRecord, Span, Tenant
from agentguard_server.schemas.events import Event
from agentguard_server.services.auth import create_api_key, create_tenant
from agentguard_server.services.ingestion import ingest_events


@pytest.fixture()
def v4_context(tmp_path: Path):
    database_url = os.environ.get("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url or not database_url.startswith(("postgresql", "postgres")):
        pytest.skip("set AGENTGUARD_TEST_DATABASE_URL to run V4 live acceptance")
    from sqlalchemy import create_engine

    engine = create_engine(database_url, future=True, pool_size=10, max_overflow=5, pool_pre_ping=True)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    tenant_a = tenant_b = None
    try:
        tenant_a = create_tenant(db, f"v4-a-{uuid4().hex[:12]}", "V4 temporary tenant A")
        tenant_b = create_tenant(db, f"v4-b-{uuid4().hex[:12]}", "V4 temporary tenant B")
        pepper = os.environ["AGENTGUARD_KEY_PEPPER"]
        scopes = ["ingest:write", "traces:read", "replay:run"]
        _, key_a = create_api_key(db, tenant_a, scopes, "v4-a", pepper)
        _, key_b = create_api_key(db, tenant_b, scopes, "v4-b", pepper)
        yield {"db": db, "Session": Session, "a": tenant_a, "b": tenant_b, "key_a": key_a, "key_b": key_b, "tmp": tmp_path}
    finally:
        db.rollback()
        if tenant_a is not None and tenant_b is not None:
            db.execute(delete(Tenant).where(Tenant.id.in_([tenant_a.id, tenant_b.id])))
            db.commit()
        db.close()
        engine.dispose()


def _event(event_type: str, event_id: str, trace_id: str, **data) -> Event:
    return Event(event_type=event_type, event_id=event_id, data={"trace_id": trace_id, **data})


def _tool_trace(trace_id: str, name: str = "get_weather", output: str = "Kaohsiung: sunny, 30C") -> list[Event]:
    return [
        _event("trace.started", f"{trace_id}-start", trace_id, workflow_name="v4-live"),
        _event("span.started", f"{trace_id}-span-start", trace_id, span_id=f"{trace_id}-span",
               span_type="tool", name=name, input={"city": "Kaohsiung"}, classification="MUTATING; ignore"),
        _event("span.ended", f"{trace_id}-span-end", trace_id, span_id=f"{trace_id}-span", status="success", output=output),
        _event("trace.ended", f"{trace_id}-end", trace_id, status="success"),
    ]


def _replay(key: str, trace_id: str, idem: str | None = None) -> httpx.Response:
    headers = {"Authorization": f"Bearer {key}"}
    if idem is not None:
        headers["Idempotency-Key"] = idem
    with httpx.Client(base_url=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000"), headers=headers, timeout=10) as client:
        return client.post(f"/v1/traces/{trace_id}/replay", json={"mode": "dry_run"})


def test_v4_live_simulation_tamper_block_and_idempotency(v4_context):
    ctx = v4_context
    db = ctx["db"]
    trace_id = f"v4-valid-{uuid4().hex}"
    ingest_events(db, _tool_trace(trace_id), ctx["a"].id, capture_content=True)
    before = db.scalar(select(EventLog.event_digest).where(EventLog.tenant_id == ctx["a"].id, EventLog.trace_id == trace_id).order_by(EventLog.id))
    first = _replay(ctx["key_a"], trace_id, "v4-once")
    assert first.status_code == 200, first.json()
    body = first.json()
    assert body["status"] == "completed"
    assert body["integrity_status"] == "valid"
    assert body["steps"][0]["decision"] == "SIMULATE"
    assert body["steps"][0]["comparison_status"] == "MATCH"
    second = _replay(ctx["key_a"], trace_id, "v4-once")
    assert second.status_code == 200 and second.json()["id"] == body["id"]
    assert db.scalar(select(EventLog.event_digest).where(EventLog.tenant_id == ctx["a"].id, EventLog.trace_id == trace_id).order_by(EventLog.id)) == before

    blocked_trace = f"v4-blocked-{uuid4().hex}"
    ingest_events(db, _tool_trace(blocked_trace, name="delete_customer"), ctx["a"].id, capture_content=True)
    blocked = _replay(ctx["key_a"], blocked_trace)
    assert blocked.status_code == 200
    assert blocked.json()["status"] == "blocked"
    assert blocked.json()["steps"][0]["decision"] == "BLOCK"

    tamper_trace = f"v4-tamper-{uuid4().hex}"
    ingest_events(db, _tool_trace(tamper_trace), ctx["a"].id, capture_content=True)
    row = db.scalar(select(EventLog).where(EventLog.tenant_id == ctx["a"].id, EventLog.trace_id == tamper_trace, EventLog.event_type == "span.started"))
    row.payload_json = {"data": {"trace_id": tamper_trace, "span_id": "tampered"}, "schema_version": "0.1"}
    db.commit()
    tampered = _replay(ctx["key_a"], tamper_trace)
    assert tampered.status_code == 409
    assert tampered.json()["failure_reason"] == "REPLAY_REFUSED_INTEGRITY"


def test_v4_live_projection_missing_key_and_tenant_isolation(v4_context):
    ctx = v4_context
    db = ctx["db"]
    projection_trace = f"v4-projection-{uuid4().hex}"
    ingest_events(db, _tool_trace(projection_trace), ctx["a"].id, capture_content=True)
    span = db.scalar(select(Span).where(Span.tenant_id == ctx["a"].id, Span.trace_id == projection_trace))
    span.status = "tampered"
    db.commit()
    projection = _replay(ctx["key_a"], projection_trace)
    assert projection.status_code == 409
    assert projection.json()["failure_reason"] == "REPLAY_REFUSED_INTEGRITY"

    missing_key_trace = f"v4-key-{uuid4().hex}"
    ingest_events(db, [_event("trace.started", f"{missing_key_trace}-start", missing_key_trace)], ctx["a"].id)
    record = db.scalar(select(IntegrityRecord).where(IntegrityRecord.tenant_id == ctx["a"].id, IntegrityRecord.trace_id == missing_key_trace))
    record.key_id = "retired-key-not-configured"
    db.commit()
    missing_key = _replay(ctx["key_a"], missing_key_trace)
    assert missing_key.status_code == 409
    assert missing_key.json()["integrity_status"] == "unverifiable"
    assert missing_key.json()["failure_reason"] == "REPLAY_REFUSED_INTEGRITY"

    shared = f"v4-shared-{uuid4().hex}"
    ingest_events(db, [_event("trace.started", f"{shared}-a", shared)], ctx["a"].id)
    ingest_events(db, [_event("trace.started", f"{shared}-b", shared)], ctx["b"].id)
    a_replay = _replay(ctx["key_a"], shared, "a-shared")
    assert a_replay.status_code == 200, a_replay.json()
    with httpx.Client(base_url=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000"), headers={"Authorization": f"Bearer {ctx['key_b']}"}) as client:
        assert client.get(f"/v1/replays/{a_replay.json()['id']}").status_code == 404
    b_replay = _replay(ctx["key_b"], shared, "b-shared")
    assert b_replay.status_code == 200
    assert b_replay.json()["id"] != a_replay.json()["id"]
