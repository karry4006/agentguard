"""API-level regression evaluation tests; all data belongs to a per-test tenant."""

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from agentguard_server.api.routes import db_session as api_db_session
from agentguard_server.main import app
from agentguard_server.services.auth import create_api_key, create_tenant


def _event(event_type: str, event_id: str, data: dict) -> dict:
    return {"event_type": event_type, "event_id": event_id, "schema_version": "0.1", "data": data}


@pytest.fixture()
def evaluation_client(db_session):
    def override():
        yield db_session

    app.dependency_overrides[api_db_session] = override
    tenant = create_tenant(db_session, f"eval-{uuid4().hex[:12]}", "Evaluation tenant")
    scopes = ["ingest:write", "traces:read", "evaluations:read", "evaluations:run", "evaluations:manage"]
    _, api_key = create_api_key(db_session, tenant, scopes, "evaluation-test", os.environ["AGENTGUARD_KEY_PEPPER"])
    with TestClient(app) as test_client:
        test_client.headers.update({"Authorization": f"Bearer {api_key}"})
        yield test_client, db_session, tenant
    app.dependency_overrides.clear()


def _ingest(client: TestClient, trace_id: str, *, failed: bool = False) -> None:
    prefix = uuid4().hex
    status = "error" if failed else "success"
    response = client.post("/v1/ingest", json={"events": [
        _event("trace.started", f"{prefix}-trace-start", {"trace_id": trace_id, "status": "running"}),
        _event("span.started", f"{prefix}-span-start", {"trace_id": trace_id, "span_id": f"{prefix}-span", "span_type": "agent", "name": "agent"}),
        _event("span.ended", f"{prefix}-span-end", {"trace_id": trace_id, "span_id": f"{prefix}-span", "status": status, "duration_ms": 20}),
        _event("trace.ended", f"{prefix}-trace-end", {"trace_id": trace_id, "status": status}),
    ]})
    assert response.status_code == 202, response.text


def test_evaluation_api_paired_comparison_and_idempotency(evaluation_client):
    client, _db, _tenant = evaluation_client
    _ingest(client, "baseline-trace")
    _ingest(client, "candidate-trace")
    suite = client.post("/v1/evaluation-suites", json={
        "name": "release", "version": "1", "configuration": {
            "minimum_cases": 1, "minimum_pair_coverage": 1,
            "rules": [{"metric": "candidate_success_rate", "operator": ">=", "value": 1}],
        },
    })
    assert suite.status_code == 201, suite.text
    suite_id = suite.json()["id"]
    baseline = client.post("/v1/evaluation-runs", headers={"Idempotency-Key": "baseline-once"}, json={
        "suite_id": suite_id, "variant": "baseline", "agent_version": "a1",
        "cases": [{"case_id": "case-1", "trace_id": "baseline-trace"}],
    })
    assert baseline.status_code == 201, baseline.text
    duplicate = client.post("/v1/evaluation-runs", headers={"Idempotency-Key": "baseline-once"}, json={
        "suite_id": suite_id, "variant": "baseline", "agent_version": "changed",
        "cases": [{"case_id": "case-1", "trace_id": "baseline-trace"}],
    })
    assert duplicate.status_code == 201
    assert duplicate.json()["id"] == baseline.json()["id"]
    candidate = client.post("/v1/evaluation-runs", json={
        "suite_id": suite_id, "variant": "candidate", "agent_version": "a2",
        "cases": [{"case_id": "case-1", "trace_id": "candidate-trace"}],
    })
    assert candidate.status_code == 201, candidate.text
    comparison = client.post("/v1/evaluation-comparisons", headers={"Idempotency-Key": "compare-once"}, json={
        "suite_id": suite_id, "baseline_run_id": baseline.json()["id"], "candidate_run_id": candidate.json()["id"],
    })
    assert comparison.status_code == 201, comparison.text
    assert comparison.json()["decision"] == "PASS"
    repeated = client.post("/v1/evaluation-comparisons", headers={"Idempotency-Key": "compare-once"}, json={
        "suite_id": suite_id, "baseline_run_id": baseline.json()["id"], "candidate_run_id": candidate.json()["id"],
    })
    assert repeated.status_code == 201
    assert repeated.json()["id"] == comparison.json()["id"]


def test_evaluation_api_missing_pair_is_insufficient_and_scope_isolated(evaluation_client, db_session):
    client, _db, tenant = evaluation_client
    _ingest(client, "only-baseline")
    suite = client.post("/v1/evaluation-suites", json={"name": "coverage", "version": "1"})
    assert suite.status_code == 201
    suite_id = suite.json()["id"]
    baseline = client.post("/v1/evaluation-runs", json={
        "suite_id": suite_id, "variant": "baseline", "agent_version": "a1",
        "cases": [{"case_id": "case-1", "trace_id": "only-baseline"}],
    })
    candidate = client.post("/v1/evaluation-runs", json={
        "suite_id": suite_id, "variant": "candidate", "agent_version": "a2",
        "cases": [{"case_id": "case-2", "trace_id": "only-baseline"}],
    })
    comparison = client.post("/v1/evaluation-comparisons", json={
        "suite_id": suite_id, "baseline_run_id": baseline.json()["id"], "candidate_run_id": candidate.json()["id"],
    })
    assert comparison.status_code == 201
    assert comparison.json()["decision"] == "INSUFFICIENT_DATA"

    _, read_key = create_api_key(db_session, tenant, ["evaluations:read"], "evaluation-read-only", os.environ["AGENTGUARD_KEY_PEPPER"])
    assert client.post("/v1/evaluation-suites", headers={"Authorization": f"Bearer {read_key}"}, json={"name": "denied", "version": "1"}).status_code == 403

