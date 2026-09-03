"""Live V3 acceptance tests; run only with an explicitly configured PostgreSQL URL."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import sessionmaker

from agentguard.config import AgentGuardConfig
from agentguard.exporter import HttpBatchExporter
from agentguard_server.config import Settings
from agentguard_server.models import EventLog, IntegrityChainHead, IntegrityRecord, Tenant, Trace
from agentguard_server.schemas.events import Event
from agentguard_server.services.auth import create_api_key, create_tenant
from agentguard_server.services.ingestion import ingest_events
from agentguard_server.services.integrity import verify_trace_integrity


@pytest.fixture()
def live_context(tmp_path: Path):
    database_url = os.environ.get("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url or not database_url.startswith(("postgresql", "postgres")):
        pytest.skip("set AGENTGUARD_TEST_DATABASE_URL to run V3 live acceptance")
    engine = create_engine(database_url, future=True, pool_size=20, max_overflow=10, pool_pre_ping=True)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    try:
        db.execute(select(1))
        tenant_a = create_tenant(db, f"v3-a-{uuid4().hex[:12]}", "V3 temporary tenant A")
        tenant_b = create_tenant(db, f"v3-b-{uuid4().hex[:12]}", "V3 temporary tenant B")
        pepper = os.environ["AGENTGUARD_KEY_PEPPER"]
        _, key_a = create_api_key(db, tenant_a, ["ingest:write", "traces:read"], "v3-a", pepper)
        _, key_b = create_api_key(db, tenant_b, ["ingest:write", "traces:read"], "v3-b", pepper)
        yield {"engine": engine, "Session": Session, "db": db, "a": tenant_a, "b": tenant_b, "key_a": key_a, "key_b": key_b, "tmp": tmp_path}
    finally:
        db.rollback()
        db.execute(delete(Tenant).where(Tenant.id.in_([tenant_a.id, tenant_b.id])))
        db.commit()
        db.close()
        engine.dispose()


def _event(event_type: str, event_id: str, trace_id: str, **data) -> dict:
    return {"event_type": event_type, "event_id": event_id, "schema_version": "0.1", "data": {"trace_id": trace_id, **data}}


def _post(key: str, events: list[dict]) -> httpx.Response:
    with httpx.Client(base_url=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000"), headers={"Authorization": f"Bearer {key}"}) as client:
        return client.post("/v1/ingest", json={"schema_version": "0.1", "events": events})


def _integrity(key: str, trace_id: str) -> dict:
    with httpx.Client(base_url=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000"), headers={"Authorization": f"Bearer {key}"}) as client:
        response = client.get(f"/v1/traces/{trace_id}/integrity")
    assert response.status_code == 200
    return response.json()


def test_live_tamper_modes_duplicate_and_tenant_isolation(live_context):
    ctx = live_context
    trace_id = f"v3-tamper-{uuid4().hex}"
    events = [_event("trace.started", trace_id, trace_id, metadata={"owner": "a"}),
              _event("span.started", f"root-{trace_id}", trace_id, span_id=f"root-{trace_id}", name="root"),
              _event("span.started", f"child-{trace_id}", trace_id, span_id=f"child-{trace_id}", parent_span_id=f"root-{trace_id}", attributes={"json": {"ok": True}})]
    assert _post(ctx["key_a"], events).json() == {"accepted": 3, "duplicates": 0}
    assert _post(ctx["key_a"], [events[2]]).json() == {"accepted": 0, "duplicates": 1}
    assert _integrity(ctx["key_a"], trace_id)["status"] == "valid"

    db = ctx["db"]
    payload_row = db.scalar(select(EventLog).where(EventLog.tenant_id == ctx["a"].id, EventLog.trace_id == trace_id, EventLog.event_type == "trace.started"))
    assert payload_row is not None
    payload_row.payload_json = {"data": {"trace_id": trace_id, "metadata": {"owner": "tampered"}}, "schema_version": "0.1"}
    db.commit()
    assert _integrity(ctx["key_a"], trace_id)["first_failure"] == "event_digest_mismatch"

    mac_trace = f"v3-mac-{uuid4().hex}"
    assert _post(ctx["key_a"], [_event("trace.started", mac_trace, mac_trace)]).status_code == 202
    mac = db.scalar(select(IntegrityRecord).where(IntegrityRecord.tenant_id == ctx["a"].id, IntegrityRecord.trace_id == mac_trace))
    mac.chain_mac = "0" * 64
    db.commit()
    assert _integrity(ctx["key_a"], mac_trace)["first_failure"] == "chain_mac_mismatch"

    gap_trace = f"v3-gap-{uuid4().hex}"
    gap_events = [_event("trace.started", gap_trace, gap_trace), _event("span.started", f"r-{gap_trace}", gap_trace, span_id=f"r-{gap_trace}")]
    assert _post(ctx["key_a"], gap_events).status_code == 202
    gap = db.scalar(select(IntegrityRecord).where(IntegrityRecord.tenant_id == ctx["a"].id, IntegrityRecord.trace_id == gap_trace, IntegrityRecord.sequence == 2))
    db.delete(gap)
    db.commit()
    assert _integrity(ctx["key_a"], gap_trace)["first_failure"] == "missing_integrity_record"

    link_trace = f"v3-link-{uuid4().hex}"
    assert _post(ctx["key_a"], [_event("trace.started", link_trace, link_trace), _event("span.started", f"r-{link_trace}", link_trace, span_id=f"r-{link_trace}")]).status_code == 202
    link = db.scalar(select(IntegrityRecord).where(IntegrityRecord.tenant_id == ctx["a"].id, IntegrityRecord.trace_id == link_trace, IntegrityRecord.sequence == 2))
    link.previous_chain_mac = "0" * 64
    db.commit()
    assert _integrity(ctx["key_a"], link_trace)["first_failure"] == "previous_chain_mismatch"

    projection_trace = f"v3-projection-{uuid4().hex}"
    assert _post(ctx["key_a"], [_event("trace.started", projection_trace, projection_trace)]).status_code == 202
    projection = db.scalar(select(Trace).where(Trace.tenant_id == ctx["a"].id, Trace.trace_id == projection_trace))
    projection.status = "tampered"
    db.commit()
    projection_result = _integrity(ctx["key_a"], projection_trace)
    assert projection_result["chain_valid"] is True
    assert projection_result["projection_consistent"] is False

    shared = f"v3-shared-{uuid4().hex}"
    assert _post(ctx["key_a"], [_event("trace.started", shared, shared, metadata={"owner": "a"})]).status_code == 202
    assert _post(ctx["key_b"], [_event("trace.started", shared, shared, metadata={"owner": "b"})]).status_code == 202
    with httpx.Client(base_url=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000")) as client:
        a_response = client.get(f"/v1/traces/{shared}", headers={"Authorization": f"Bearer {ctx['key_a']}"})
        b_response = client.get(f"/v1/traces/{shared}", headers={"Authorization": f"Bearer {ctx['key_b']}"})
    assert a_response.json()["trace"]["metadata"]["owner"] == "a"
    assert b_response.json()["trace"]["metadata"]["owner"] == "b"
    assert _integrity(ctx["key_a"], shared)["status"] == "valid"
    assert _integrity(ctx["key_b"], shared)["status"] == "valid"


def test_live_concurrent_append_and_missing_key(live_context):
    ctx = live_context
    trace_id = f"v3-concurrent-{uuid4().hex}"
    assert _post(ctx["key_a"], [_event("trace.started", trace_id, trace_id)]).status_code == 202

    def append(index: int):
        session = ctx["Session"]()
        try:
            ingest_events(session, [Event(event_type="span.started", event_id=f"concurrent-{index}-{trace_id}", data={"trace_id": trace_id, "span_id": f"concurrent-{index}-{trace_id}", "name": "concurrent"})], ctx["a"].id)
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(append, range(24)))
    records = list(ctx["db"].scalars(select(IntegrityRecord).where(IntegrityRecord.tenant_id == ctx["a"].id, IntegrityRecord.trace_id == trace_id).order_by(IntegrityRecord.sequence)))
    assert [record.sequence for record in records] == list(range(1, 26))
    assert len({record.sequence for record in records}) == 25
    from agentguard_server.config import get_settings
    settings = get_settings()
    key_id = ctx["db"].scalar(select(IntegrityRecord.key_id).where(IntegrityRecord.tenant_id == ctx["a"].id, IntegrityRecord.trace_id == trace_id))
    verification = verify_trace_integrity(ctx["db"], ctx["a"].id, trace_id)
    assert key_id == settings.integrity_key_id, (key_id, settings.integrity_key_id, len(settings.integrity_key or ""))
    assert verification.status == "valid", verification.first_failure
    settings = Settings()
    settings.integrity_key = None
    settings.integrity_verify_keys = None
    assert verify_trace_integrity(ctx["db"], ctx["a"].id, trace_id, settings).first_failure == "UNVERIFIABLE_KEY_MISSING"


def test_live_spool_recovery(live_context):
    ctx = live_context
    trace_id = f"v3-spool-{uuid4().hex}"
    path = ctx["tmp"] / "v3-spool.sqlite3"
    config = AgentGuardConfig(ingest_url=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000") + "/v1/ingest", api_key=ctx["key_a"], spool_path=str(path), batch_size=2, max_retries=5,
                              allow_insecure_http=bool(os.getenv("AGENTGUARD_TEST_SERVER_URL")))
    failed = HttpBatchExporter(config, send_batch=lambda batch: (_ for _ in ()).throw(RuntimeError("simulated outage")))
    assert failed.submit(_event("trace.started", trace_id, trace_id))
    assert failed.force_flush(2)
    failed._stop_event.set()
    failed._wake()
    failed._worker.join(2)
    failed.spool.close()

    recovered = HttpBatchExporter(config)
    assert recovered.force_flush(5)
    assert recovered.diagnostics()["pending_events"] == 0
    recovered.shutdown()
    assert _integrity(ctx["key_a"], trace_id)["status"] == "valid"


def test_live_cli_integrity_verify(live_context):
    ctx = live_context
    trace_id = f"v3-cli-{uuid4().hex}"
    ingest_events(ctx["db"], [Event(event_type="trace.started", event_id=trace_id, data={"trace_id": trace_id})], ctx["a"].id)
    env = os.environ.copy()
    # Live fixtures use the migration DSN for isolated setup/cleanup; the CLI
    # must prove the runtime role independently. The caller supplies the
    # protected runtime DSN without copying credentials in test code.
    env["DATABASE_URL"] = env.get("AGENTGUARD_RUNTIME_DATABASE_URL", "").strip()
    assert env["DATABASE_URL"].startswith(("postgresql", "postgres"))
    result = subprocess.run([sys.executable, "-m", "agentguard_server.cli", "integrity", "verify", "--tenant", ctx["a"].slug, "--trace-id", trace_id], env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert f"trace_id={trace_id}" in result.stdout
    assert "status=valid" in result.stdout
    assert "chain_mac" not in result.stdout
