"""V10 live acceptance against the running AgentGuard PostgreSQL/API stack."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import os
import time
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import sessionmaker

from agentguard_server.models import Incident, IncidentEvent, IncidentOccurrence, Span, Tenant
from agentguard_server.services.auth import create_api_key, create_tenant
from agentguard_server.services.incidents import incident_trend, process_finding


@pytest.fixture()
def v10_live_context():
    database_url = os.environ.get("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url or not database_url.startswith(("postgresql", "postgres")):
        pytest.skip("set AGENTGUARD_TEST_DATABASE_URL to run V10 PostgreSQL live acceptance")
    engine = create_engine(database_url, future=True, pool_size=20, max_overflow=20, pool_pre_ping=True)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    tenant_ids = []
    try:
        db.execute(select(1))
        tenant_a = create_tenant(db, f"v10-a-{uuid4().hex[:12]}", "V10 temporary tenant A")
        tenant_b = create_tenant(db, f"v10-b-{uuid4().hex[:12]}", "V10 temporary tenant B")
        tenant_ids.extend([tenant_a.id, tenant_b.id])
        pepper = os.environ["AGENTGUARD_KEY_PEPPER"]
        scopes = ["ingest:write", "traces:read", "analysis:run", "incidents:read", "incidents:manage"]
        _, key_a = create_api_key(db, tenant_a, scopes, "v10-a", pepper)
        _, key_b = create_api_key(db, tenant_b, scopes, "v10-b", pepper)
        yield {"engine": engine, "Session": Session, "db": db, "a": tenant_a, "b": tenant_b,
               "key_a": key_a, "key_b": key_b}
    finally:
        db.rollback()
        if tenant_ids:
            db.execute(delete(Tenant).where(Tenant.id.in_(tenant_ids)))
            db.commit()
        db.close()
        engine.dispose()


def _event(event_type: str, event_id: str, trace_id: str, **data) -> dict:
    return {"event_type": event_type, "event_id": event_id, "schema_version": "0.1",
            "data": {"trace_id": trace_id, **data}}


def _client(key: str) -> httpx.Client:
    return httpx.Client(base_url=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000"), headers={"Authorization": f"Bearer {key}"})


def _timeout_trace(trace_id: str) -> list[dict]:
    return [
        _event("trace.started", f"start-{trace_id}", trace_id, workflow_name="weather", provider="test-provider"),
        _event("span.started", f"span-{trace_id}", trace_id, span_id=f"span-{trace_id}", span_type="tool",
               name="get_weather", status="running"),
        _event("span.ended", f"span-end-{trace_id}", trace_id, span_id=f"span-{trace_id}",
               status="error", error_type="TimeoutError"),
        _event("trace.ended", f"end-{trace_id}", trace_id, status="error"),
    ]


def test_live_v5_projection_lifecycle_and_tenant_isolation(v10_live_context):
    ctx = v10_live_context
    shared = f"v10-shared-{uuid4().hex}"
    with _client(ctx["key_a"]) as client:
        assert client.post("/v1/ingest", json={"schema_version": "0.1", "events": _timeout_trace(shared)}).status_code == 202
        projected_span = ctx["db"].scalar(select(Span).where(Span.tenant_id == ctx["a"].id, Span.trace_id == shared))
        assert projected_span is not None and projected_span.error_type == "TimeoutError"
        analyzed = client.post(f"/v1/traces/{shared}/analysis", json={"mode": "deterministic"},
                               headers={"Idempotency-Key": f"analysis-{shared}"})
        assert analyzed.status_code == 200
        categories = {item["category"] for item in analyzed.json()["findings"]}
        assert "TIMEOUT" in categories, categories
        incidents = client.get("/v1/incidents")
        assert incidents.status_code == 200
        rows = [row for row in incidents.json() if row["title"] == "TIMEOUT in get_weather"]
        assert len(rows) == 1
        incident_id = rows[0]["id"]
        detail = client.get(f"/v1/incidents/{incident_id}")
        assert detail.status_code == 200
        assert detail.json()["occurrence_count"] == 1
        assert detail.json()["findings"][0]["source"] == "DETERMINISTIC"
        assert "reason" not in detail.text
        assert client.post(f"/v1/incidents/{incident_id}/resolve").json()["status"] == "RESOLVED"

        second = f"v10-second-{uuid4().hex}"
        assert client.post("/v1/ingest", json={"schema_version": "0.1", "events": _timeout_trace(second)}).status_code == 202
        assert client.post(f"/v1/traces/{second}/analysis", json={"mode": "deterministic"},
                           headers={"Idempotency-Key": f"analysis-{second}"}).status_code == 200
        reopened = client.get(f"/v1/incidents/{incident_id}").json()
        assert reopened["status"] == "OPEN" and reopened["occurrence_count"] == 2
        assert any(event["event_type"] == "REOPENED" for event in reopened["history"])

    # Same trace identifier under tenant B is a different source and cannot be
    # queried through tenant A's incident resource.
    with _client(ctx["key_b"]) as client:
        assert client.post("/v1/ingest", json={"schema_version": "0.1", "events": _timeout_trace(shared)}).status_code == 202
        assert client.post(f"/v1/traces/{shared}/analysis", json={"mode": "deterministic"},
                           headers={"Idempotency-Key": f"analysis-b-{shared}"}).status_code == 200
        b_rows = [row for row in client.get("/v1/incidents").json() if row["title"] == "TIMEOUT in get_weather"]
        assert len(b_rows) == 1 and b_rows[0]["id"] != incident_id
        assert client.get(f"/v1/incidents/{incident_id}").status_code == 404


def test_live_postgres_incident_idempotency_and_concurrency(v10_live_context):
    ctx = v10_live_context
    tenant_id = ctx["a"].id
    finding = SimpleNamespace(detector_id="timeout", category="TIMEOUT", severity="HIGH",
                              source="DETERMINISTIC", root_cause_span_id="span", symptom_span_id="span")

    def append(index: int):
        session = ctx["Session"]()
        try:
            analysis = SimpleNamespace(id=uuid4(), trace_id=f"v10-concurrent-{index}", tenant_id=tenant_id)
            return process_finding(session, tenant_id, analysis, finding, observed_at=datetime.now(timezone.utc)).id
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=12) as pool:
        incident_ids = list(pool.map(append, range(50)))
    assert len(set(incident_ids)) == 1
    incident = ctx["db"].get(Incident, incident_ids[0])
    assert incident is not None and incident.occurrence_count == 50
    assert incident.affected_trace_count == 50
    occurrence_count = ctx["db"].scalar(select(IncidentOccurrence.id).where(
        IncidentOccurrence.incident_id == incident.id).order_by(IncidentOccurrence.id).limit(51))
    assert occurrence_count is not None
    # Repeating one exact analysis/finding is a no-op and adds no lifecycle event.
    analysis = SimpleNamespace(id=uuid4(), trace_id="v10-idempotent", tenant_id=tenant_id)
    first = process_finding(ctx["db"], tenant_id, analysis, finding)
    before = ctx["db"].scalar(select(Incident.occurrence_count).where(Incident.id == first.id))
    process_finding(ctx["db"], tenant_id, analysis, finding)
    after = ctx["db"].scalar(select(Incident.occurrence_count).where(Incident.id == first.id))
    assert before == after


def test_live_v10_bounded_1000_occurrence_corpus(v10_live_context):
    ctx = v10_live_context
    tenant_id = ctx["a"].id
    finding = SimpleNamespace(detector_id="corpus", category="TIMEOUT", severity="HIGH",
                              source="DETERMINISTIC", root_cause_span_id="span", symptom_span_id="span")
    first = process_finding(ctx["db"], tenant_id,
                            SimpleNamespace(id=uuid4(), trace_id="v10-corpus-0", tenant_id=tenant_id), finding)
    rows = [IncidentOccurrence(tenant_id=tenant_id, incident_id=first.id, trace_id=f"v10-corpus-{i}",
                               analysis_id=uuid4(), finding_key=f"corpus-key-{i}", failure_category="TIMEOUT",
                               observed_at=datetime.now(timezone.utc)) for i in range(1, 1000)]
    ctx["db"].add_all(rows)
    ctx["db"].commit()
    first.occurrence_count = 1000
    first.affected_trace_count = 1000
    ctx["db"].commit()
    started = time.perf_counter()
    assert incident_trend(ctx["db"], first) in {"INCREASING", "STABLE", "DECREASING", "INSUFFICIENT_DATA"}
    bounded = list(ctx["db"].scalars(select(IncidentOccurrence).where(
        IncidentOccurrence.tenant_id == tenant_id, IncidentOccurrence.incident_id == first.id
    ).order_by(IncidentOccurrence.observed_at.desc()).limit(100)))
    assert len(bounded) == 100 and time.perf_counter() - started < 5
