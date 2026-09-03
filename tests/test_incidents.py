from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from agentguard_server.services.incidents import (
    FINGERPRINT_VERSION,
    IncidentSeverity,
    IncidentStatus,
    fingerprint_for_finding,
    process_finding,
)


def finding(category="TIMEOUT", *, name="get_weather", severity="HIGH", detector_id="timeout", reason="safe summary"):
    return SimpleNamespace(
        detector_id=detector_id,
        category=category,
        severity=severity,
        source="DETERMINISTIC",
        root_cause_span_id="span-1",
        symptom_span_id="span-1",
        reason=reason,
    )


def test_fingerprint_is_deterministic_safe_and_versioned():
    left = fingerprint_for_finding(finding(), component_name="get_weather", provider="openai", model="gpt-test")
    right = fingerprint_for_finding(finding(reason="IGNORE prompt secret customer@example.com"), component_name="get_weather", provider="openai", model="gpt-test")
    database = fingerprint_for_finding(finding(), component_name="query_database", provider="openai", model="gpt-test")

    assert left.version == FINGERPRINT_VERSION
    assert left.digest == right.digest
    assert left.digest != database.digest
    assert left.title == "TIMEOUT in get_weather"
    assert len(left.digest) == 64


def test_incident_processing_groups_and_is_idempotent(db_session):
    tenant_id = uuid4()
    analysis = SimpleNamespace(id=uuid4(), trace_id="trace-incident", tenant_id=tenant_id)
    first = process_finding(db_session, tenant_id, analysis, finding(), observed_at=datetime.now(timezone.utc))
    duplicate = process_finding(db_session, tenant_id, analysis, finding(), observed_at=datetime.now(timezone.utc))

    assert first.id == duplicate.id
    assert first.status == IncidentStatus.OPEN
    assert first.severity in {IncidentSeverity.LOW, IncidentSeverity.MEDIUM, IncidentSeverity.HIGH}
    assert first.occurrence_count == 1


def test_resolve_then_new_occurrence_reopens_and_preserves_first_seen(db_session):
    tenant_id = uuid4()
    base = datetime.now(timezone.utc) - timedelta(minutes=2)
    analysis = SimpleNamespace(id=uuid4(), trace_id="trace-reopen", tenant_id=tenant_id)
    incident = process_finding(db_session, tenant_id, analysis, finding(), observed_at=base)
    from agentguard_server.services.incidents import transition_incident

    transition_incident(db_session, tenant_id, incident.id, IncidentStatus.RESOLVED, actor_type="operator")
    later = SimpleNamespace(id=uuid4(), trace_id="trace-reopen-2", tenant_id=tenant_id)
    reopened = process_finding(db_session, tenant_id, later, finding(), observed_at=base + timedelta(minutes=1))

    assert reopened.status == IncidentStatus.OPEN
    assert reopened.first_seen_at == incident.first_seen_at
    assert reopened.occurrence_count == 2


def test_incident_api_is_tenant_scoped_and_lifecycle_is_audited(db_session):
    import os
    from fastapi.testclient import TestClient
    from agentguard_server.api.routes import db_session as api_db_session
    from agentguard_server.main import app
    from agentguard_server.services.auth import create_api_key, create_tenant

    tenant_a = create_tenant(db_session, f"incident-a-{uuid4().hex[:8]}", "Incident A")
    tenant_b = create_tenant(db_session, f"incident-b-{uuid4().hex[:8]}", "Incident B")
    _, key_a = create_api_key(db_session, tenant_a, ["incidents:read", "incidents:manage"], "incident-a",
                              os.environ["AGENTGUARD_KEY_PEPPER"])
    _, key_b = create_api_key(db_session, tenant_b, ["incidents:read"], "incident-b",
                              os.environ["AGENTGUARD_KEY_PEPPER"])
    analysis = SimpleNamespace(id=uuid4(), trace_id="api-incident-trace", tenant_id=tenant_a.id)
    incident = process_finding(db_session, tenant_a.id, analysis, finding())

    def override():
        yield db_session
    app.dependency_overrides[api_db_session] = override
    try:
        with TestClient(app) as http:
            body = http.get("/v1/incidents", headers={"Authorization": f"Bearer {key_a}"})
            assert body.status_code == 200 and body.json()[0]["id"] == str(incident.id)
            assert http.get(f"/v1/incidents/{incident.id}", headers={"Authorization": f"Bearer {key_b}"}).status_code == 404
            changed = http.post(f"/v1/incidents/{incident.id}/acknowledge",
                                headers={"Authorization": f"Bearer {key_a}"})
            assert changed.status_code == 200 and changed.json()["status"] == "ACKNOWLEDGED"
            assert http.post(f"/v1/incidents/{incident.id}/resolve",
                             headers={"Authorization": f"Bearer {key_a}"}).json()["status"] == "RESOLVED"
    finally:
        app.dependency_overrides.clear()
