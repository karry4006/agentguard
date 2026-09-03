"""V8 live acceptance against the running Compose PostgreSQL/server stack."""

import os
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import create_engine, delete, update
from sqlalchemy.orm import sessionmaker

from agentguard_server.models import EventLog, Tenant
from agentguard_server.services.auth import create_api_key, create_tenant


pytestmark = pytest.mark.skipif(
    not os.getenv("AGENTGUARD_TEST_DATABASE_URL"),
    reason="AGENTGUARD_TEST_DATABASE_URL is required for live PostgreSQL acceptance",
)


class _LiveContext(dict):
    def __repr__(self) -> str:
        return "<V8 live context redacted>"


def _event(event_type: str, event_id: str, data: dict) -> dict:
    return {"event_type": event_type, "event_id": event_id, "schema_version": "0.1", "data": data}


@pytest.fixture(scope="module")
def live_context():
    engine = create_engine(os.environ["AGENTGUARD_TEST_DATABASE_URL"], future=True, pool_pre_ping=True)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    db = session_factory()
    tenant_a = create_tenant(db, f"v8-a-{uuid4().hex[:12]}", "V8 temporary tenant A")
    tenant_b = create_tenant(db, f"v8-b-{uuid4().hex[:12]}", "V8 temporary tenant B")
    scopes = ["ingest:write", "traces:read", "evaluations:read", "evaluations:run", "evaluations:manage"]
    _, key_a = create_api_key(db, tenant_a, scopes, "v8-live-a", os.environ["AGENTGUARD_KEY_PEPPER"])
    _, key_b = create_api_key(db, tenant_b, scopes, "v8-live-b", os.environ["AGENTGUARD_KEY_PEPPER"])
    db.close()
    try:
        with httpx.Client(base_url=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000"), timeout=20.0) as client:
            yield _LiveContext(client=client, db_factory=session_factory, tenant_a=tenant_a, tenant_b=tenant_b,
                               key_a=key_a, key_b=key_b)
    finally:
        cleanup = session_factory()
        try:
            cleanup.execute(delete(Tenant).where(Tenant.id.in_([tenant_a.id, tenant_b.id])))
            cleanup.commit()
        finally:
            cleanup.close()


def _ingest(client: httpx.Client, key: str, trace_id: str, *, failed: bool = False) -> None:
    prefix = uuid4().hex
    terminal = "timeout" if failed else "success"
    span_end = {"trace_id": trace_id, "span_id": f"{prefix}-span", "status": terminal, "duration_ms": 25}
    if failed:
        span_end["error_type"] = "TimeoutError"
    response = client.post("/v1/ingest", headers={"Authorization": f"Bearer {key}"}, json={"events": [
        _event("trace.started", f"{prefix}-trace-start", {"trace_id": trace_id, "status": "running"}),
        _event("span.started", f"{prefix}-span-start", {"trace_id": trace_id, "span_id": f"{prefix}-span", "span_type": "tool", "name": "tool"}),
        _event("span.ended", f"{prefix}-span-end", span_end),
        _event("trace.ended", f"{prefix}-trace-end", {"trace_id": trace_id, "status": terminal}),
    ]})
    assert response.status_code == 202, response.text


def _create_run(client: httpx.Client, key: str, suite_id: str, variant: str, cases: list[dict], version: str) -> dict:
    response = client.post("/v1/evaluation-runs", headers={"Authorization": f"Bearer {key}"}, json={
        "suite_id": suite_id, "variant": variant, "agent_version": version,
        "environment": {"source": "v8-live", "credential": "must-be-redacted"}, "cases": cases,
    })
    assert response.status_code == 201, response.text
    return response.json()


def _compare(client: httpx.Client, key: str, suite_id: str, baseline_id: str, candidate_id: str) -> dict:
    response = client.post("/v1/evaluation-comparisons", headers={"Authorization": f"Bearer {key}"}, json={
        "suite_id": suite_id, "baseline_run_id": baseline_id, "candidate_run_id": candidate_id,
    })
    assert response.status_code == 201, response.text
    return response.json()


def test_v8_live_release_gate_with_20_paired_cases_and_tamper(live_context):
    client = live_context["client"]
    key_a = live_context["key_a"]
    tenant_a = live_context["tenant_a"]
    case_ids = [f"case-{index:02d}" for index in range(20)]
    baseline_cases, candidate_cases, failing_cases = [], [], []
    for index, case_id in enumerate(case_ids):
        baseline_trace = f"v8-baseline-{index:02d}"
        candidate_trace = f"v8-candidate-{index:02d}"
        failing_trace = f"v8-failing-{index:02d}"
        _ingest(client, key_a, baseline_trace)
        _ingest(client, key_a, candidate_trace)
        _ingest(client, key_a, failing_trace, failed=index < 4)
        baseline_cases.append({"case_id": case_id, "trace_id": baseline_trace})
        candidate_cases.append({"case_id": case_id, "trace_id": candidate_trace})
        failing_cases.append({"case_id": case_id, "trace_id": failing_trace})

    suite_response = client.post("/v1/evaluation-suites", headers={"Authorization": f"Bearer {key_a}"}, json={
        "name": "v8-live-release", "version": uuid4().hex[:8], "configuration": {
            "minimum_cases": 20, "minimum_pair_coverage": 1.0,
            "rules": [
                {"metric": "candidate_success_rate", "operator": ">=", "value": 0.9},
                {"metric": "candidate_timeout_rate", "operator": "<=", "value": 0.1},
                {"metric": "candidate_p95_latency_seconds", "operator": ">=", "baseline_metric": "baseline_p95_latency_seconds", "offset": -1},
            ],
        },
    })
    assert suite_response.status_code == 201, suite_response.text
    suite_id = suite_response.json()["id"]
    baseline = _create_run(client, key_a, suite_id, "baseline", baseline_cases, "agent-v8-base")
    candidate = _create_run(client, key_a, suite_id, "candidate", candidate_cases, "agent-v8-candidate")
    passing = _compare(client, key_a, suite_id, baseline["id"], candidate["id"])
    assert passing["decision"] == "PASS"
    assert passing["metrics"]["matched_cases"] == 20
    assert all(item["integrity_status"] == "valid" for item in baseline["cases"] + candidate["cases"])
    assert all(item["environment"] == {"source": "v8-live", "credential": "[REDACTED]"} for item in [baseline, candidate])

    failing = _create_run(client, key_a, suite_id, "candidate", failing_cases, "agent-v8-regressed")
    failed_comparison = _compare(client, key_a, suite_id, baseline["id"], failing["id"])
    assert failed_comparison["decision"] == "FAIL"
    assert {reason["reason"] for reason in failed_comparison["reasons"]} >= {"success_rate_regression", "timeout_rate_regression"}

    tamper_trace = "v8-tamper"
    _ingest(client, key_a, tamper_trace)
    db = live_context["db_factory"]()
    try:
        db.execute(update(EventLog).where(EventLog.tenant_id == tenant_a.id, EventLog.trace_id == tamper_trace)
                   .values(payload_json={"data": {"trace_id": tamper_trace, "tampered": True}, "schema_version": "0.1"}))
        db.commit()
    finally:
        db.close()
    tamper_run = _create_run(client, key_a, suite_id, "candidate", [{"case_id": "tamper", "trace_id": tamper_trace}], "agent-v8-tampered")
    assert tamper_run["cases"][0]["status"] == "rejected"
    assert tamper_run["cases"][0]["integrity_status"] != "valid"

    assert client.get(f"/v1/evaluation-suites/{suite_id}", headers={"Authorization": f"Bearer {live_context['key_b']}"}).status_code == 404
