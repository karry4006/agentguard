"""Live V5 acceptance; requires AGENTGUARD_TEST_DATABASE_URL for the Compose DB."""

import os
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import sessionmaker

from agentguard_server.models import EventLog, Tenant
from agentguard_server.schemas.events import Event
from agentguard_server.services.analysis import AnalysisRefused, analyze_trace, validate_ai_judgment
from agentguard_server.services.auth import create_api_key, create_tenant
from agentguard_server.services.ingestion import ingest_events


@pytest.fixture()
def v5_context():
    database_url = os.environ.get("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url or not database_url.startswith(("postgresql", "postgres")):
        pytest.skip("set AGENTGUARD_TEST_DATABASE_URL to run V5 live acceptance")
    from sqlalchemy import create_engine

    engine = create_engine(database_url, future=True, pool_size=10, max_overflow=5, pool_pre_ping=True)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    tenants = []
    try:
        tenants = [create_tenant(db, f"v5-{suffix}-{uuid4().hex[:10]}", f"V5 {suffix}") for suffix in ("a", "b")]
        pepper = os.environ["AGENTGUARD_KEY_PEPPER"]
        scopes = ["ingest:write", "traces:read", "analysis:run"]
        _, key_a = create_api_key(db, tenants[0], scopes, "v5-a", pepper)
        _, key_b = create_api_key(db, tenants[1], scopes, "v5-b", pepper)
        yield {"db": db, "Session": Session, "a": tenants[0], "b": tenants[1], "key_a": key_a, "key_b": key_b}
    finally:
        db.rollback()
        if tenants:
            db.execute(delete(Tenant).where(Tenant.id.in_([tenant.id for tenant in tenants])))
            db.commit()
        db.close()
        engine.dispose()


def _event(event_type: str, event_id: str, trace_id: str, **data) -> Event:
    return Event(event_type=event_type, event_id=event_id, data={"trace_id": trace_id, **data})


def _trace(trace_id: str, *, status="success", attrs=None, name="tool") -> list[Event]:
    return [
        _event("trace.started", f"{trace_id}-start", trace_id),
        _event("span.started", f"{trace_id}-span", trace_id, span_id=f"{trace_id}-span", span_type="tool",
               name=name, status=status, attributes=attrs or {}),
        _event("trace.ended", f"{trace_id}-end", trace_id, status="success"),
    ]


def _analyze(key: str, trace_id: str, mode="deterministic", idem=None):
    headers = {"Authorization": f"Bearer {key}"}
    if idem:
        headers["Idempotency-Key"] = idem
    with httpx.Client(base_url=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000"), headers=headers, timeout=10) as client:
        return client.post(f"/v1/traces/{trace_id}/analysis", json={"mode": mode})


def test_v5_live_deterministic_taxonomy_tamper_and_tenant_isolation(v5_context):
    ctx = v5_context
    db = ctx["db"]
    timeout_trace = f"v5-timeout-{uuid4().hex}"
    ingest_events(db, _trace(timeout_trace, status="timeout"), ctx["a"].id, capture_content=True)
    timeout = _analyze(ctx["key_a"], timeout_trace, idem="timeout-once")
    assert timeout.status_code == 200, timeout.json()
    assert timeout.json()["findings"][0]["category"] == "TIMEOUT"
    assert timeout.json()["findings"][0]["source"] == "DETERMINISTIC"
    retry = _analyze(ctx["key_a"], timeout_trace, idem="timeout-once")
    assert retry.json()["id"] == timeout.json()["id"]

    auth_trace = f"v5-auth-{uuid4().hex}"
    ingest_events(db, _trace(auth_trace, attrs={"status_code": 401}), ctx["a"].id, capture_content=True)
    assert "AUTHENTICATION" in {item["category"] for item in _analyze(ctx["key_a"], auth_trace).json()["findings"]}

    selection_trace = f"v5-selection-{uuid4().hex}"
    ingest_events(db, _trace(selection_trace, attrs={"wrong_tool": True}, name="bad-tool"), ctx["a"].id, capture_content=True)
    assert "TOOL_SELECTION" in {item["category"] for item in _analyze(ctx["key_a"], selection_trace).json()["findings"]}

    tamper_trace = f"v5-tamper-{uuid4().hex}"
    ingest_events(db, _trace(tamper_trace), ctx["a"].id, capture_content=True)
    row = db.scalar(select(EventLog).where(EventLog.tenant_id == ctx["a"].id, EventLog.trace_id == tamper_trace, EventLog.event_type == "span.started"))
    row.payload_json = {"data": {"trace_id": tamper_trace, "span_id": "forged"}, "schema_version": "0.1"}
    db.commit()
    refused = _analyze(ctx["key_a"], tamper_trace)
    assert refused.status_code == 409 and refused.json()["failure_reason"] == "ANALYSIS_REFUSED_INTEGRITY"

    shared = f"v5-shared-{uuid4().hex}"
    ingest_events(db, [_event("trace.started", f"{shared}-a", shared)], ctx["a"].id)
    ingest_events(db, [_event("trace.started", f"{shared}-b", shared)], ctx["b"].id)
    a_result = _analyze(ctx["key_a"], shared)
    with httpx.Client(base_url=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000"), headers={"Authorization": f"Bearer {ctx['key_b']}"}) as client:
        assert client.get(f"/v1/analyses/{a_result.json()['id']}").status_code == 404


def test_v5_live_fake_judge_and_provider_failure_fallback(v5_context):
    ctx = v5_context
    trace_id = f"v5-ai-{uuid4().hex}"
    ingest_events(ctx["db"], _trace(trace_id, attrs={"wrong_tool": True}), ctx["a"].id, capture_content=True)
    report, packet = analyze_trace(ctx["db"], ctx["a"].id, trace_id)
    assert report.deterministic_status == "completed"
    assert packet["span_ids"]

    class FakeJudge:
        def analyze(self, evidence):
            span_id = next(iter(evidence["span_ids"]))
            return {"category": "TOOL_SELECTION", "model_confidence": 0.8, "root_cause_span_id": span_id,
                    "symptom_span_id": span_id, "evidence_span_ids": [span_id], "evidence_event_ids": [], "reason": "fixture"}

    ai_report, _ = analyze_trace(ctx["db"], ctx["a"].id, trace_id, mode="ai_assisted", judge=FakeJudge())
    assert ai_report.ai_status == "completed"
    assert any(f.source.value == "AI" for f in ai_report.findings)

    class FailingJudge:
        def analyze(self, evidence):
            raise TimeoutError

    fallback, _ = analyze_trace(ctx["db"], ctx["a"].id, trace_id, mode="ai_assisted", judge=FailingJudge())
    assert fallback.ai_status == "failed" and fallback.deterministic_status == "completed"
    with pytest.raises(ValueError, match="evidence"):
        validate_ai_judgment({"category": "TIMEOUT", "model_confidence": 0.5, "root_cause_span_id": "fake",
                              "symptom_span_id": "fake", "evidence_span_ids": ["fake"], "evidence_event_ids": [], "reason": "x"}, packet)
