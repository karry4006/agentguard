import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from agentguard_server.api.routes import db_session as api_db_session
from agentguard_server.db.base import Base
from agentguard_server.main import app
from agentguard_server.models import ApiKey, Span, Tenant, Trace
from agentguard_server.schemas.events import Event
from agentguard_server.services.ingestion import ingest_events
from agentguard_server.services.query import get_trace
from agentguard_server.services.auth import create_api_key, create_tenant
from agentguard_server.services.integrity import verify_trace_integrity


@pytest.fixture()
def client(db_session):
    def override():
        yield db_session
    app.dependency_overrides[api_db_session] = override
    tenant = create_tenant(db_session, f"test-{uuid4().hex[:12]}", "Unit test tenant")
    _, api_key = create_api_key(db_session, tenant, ["ingest:write", "traces:read"], "unit-test", os.environ["AGENTGUARD_KEY_PEPPER"])
    test_client = TestClient(app)
    test_client.headers.update({"Authorization": f"Bearer {api_key}"})
    yield test_client
    app.dependency_overrides.clear()


def event(event_type, event_id, data):
    return {"event_type": event_type, "event_id": event_id, "schema_version": "0.1", "data": data}


def test_trace_and_span_ingest_query_and_parent_child(client):
    events = [
        event("trace.started", "trace-1", {"trace_id": "trace-1", "workflow_name": "weather", "status": "running", "metadata": {"env": "test"}}),
        event("span.started", "root", {"span_id": "root", "trace_id": "trace-1", "span_type": "agent", "name": "agent"}),
        event("span.started", "child", {"span_id": "child", "trace_id": "trace-1", "parent_span_id": "root", "span_type": "tool", "name": "get_weather"}),
        event("span.ended", "child", {"span_id": "child", "trace_id": "trace-1", "ended_at": "2026-01-01T00:00:01Z", "status": "success", "duration_ms": 1000}),
        event("trace.ended", "trace-1", {"trace_id": "trace-1", "ended_at": "2026-01-01T00:00:02Z", "status": "success"}),
    ]
    response = client.post("/v1/ingest", json={"schema_version": "0.1", "events": events})
    assert response.status_code == 202
    assert response.json() == {"accepted": 5, "duplicates": 0}
    duplicate = client.post("/v1/ingest", json={"schema_version": "0.1", "events": [events[2]]})
    assert duplicate.json() == {"accepted": 0, "duplicates": 1}

    listing = client.get("/v1/traces")
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    detail = client.get("/v1/traces/trace-1")
    assert detail.status_code == 200
    body = detail.json()
    assert len(body["spans"]) == 2
    assert body["span_tree"][0]["children"][0]["span"]["span_id"] == "child"
    assert body["trace"]["status"] == "success"


def test_invalid_payload_and_missing_trace(client):
    invalid = client.post("/v1/ingest", json={"schema_version": "0.1", "events": [{"event_type": "not.valid", "event_id": "x", "data": {}}]})
    assert invalid.status_code == 422
    missing = client.get("/v1/traces/no-such-trace")
    assert missing.status_code == 404


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_authentication_and_scope_enforcement(client, db_session):
    missing = client.get("/v1/traces/no-such-trace", headers={"Authorization": "Bearer malformed"})
    assert missing.status_code == 401

    tenant = create_tenant(db_session, f"scope-{uuid4().hex[:12]}", "Scope tenant")
    _, ingest_only = create_api_key(db_session, tenant, ["ingest:write"], "ingest-only", os.environ["AGENTGUARD_KEY_PEPPER"])
    _, read_only = create_api_key(db_session, tenant, ["traces:read"], "read-only", os.environ["AGENTGUARD_KEY_PEPPER"])
    payload = {"events": [event("trace.started", "scope-trace", {"trace_id": "scope-trace"})]}
    assert client.post("/v1/ingest", json=payload, headers={"Authorization": f"Bearer {read_only}"}).status_code == 403
    assert client.get("/v1/traces", headers={"Authorization": f"Bearer {ingest_only}"}).status_code == 403


def test_tenant_isolation_and_payload_tenant_is_ignored(db_session):
    tenant_a = create_tenant(db_session, f"tenant-a-{uuid4().hex[:8]}", "Tenant A")
    tenant_b = create_tenant(db_session, f"tenant-b-{uuid4().hex[:8]}", "Tenant B")
    _, key_a = create_api_key(db_session, tenant_a, ["ingest:write", "traces:read"], "a", os.environ["AGENTGUARD_KEY_PEPPER"])
    _, key_b = create_api_key(db_session, tenant_b, ["ingest:write", "traces:read"], "b", os.environ["AGENTGUARD_KEY_PEPPER"])
    def override():
        yield db_session
    app.dependency_overrides[api_db_session] = override
    try:
        with TestClient(app) as isolated_client:
            payload = {"events": [
                event("trace.started", "same-trace", {"trace_id": "same-trace", "tenant_id": str(tenant_b.id), "metadata": {"owner": "a"}}),
                event("span.started", "same-span", {"trace_id": "same-trace", "span_id": "same-span", "attributes": {"tenant": "a"}}),
            ]}
            assert isolated_client.post("/v1/ingest", json=payload, headers={"Authorization": f"Bearer {key_a}"}).json() == {"accepted": 2, "duplicates": 0}
            assert isolated_client.post("/v1/ingest", json=payload, headers={"Authorization": f"Bearer {key_b}"}).json() == {"accepted": 2, "duplicates": 0}
            assert isolated_client.get("/v1/traces", headers={"Authorization": f"Bearer {key_a}"}).json()["total"] == 1
            assert isolated_client.get("/v1/traces", headers={"Authorization": f"Bearer {key_b}"}).json()["total"] == 1
            assert isolated_client.get("/v1/traces/same-trace", headers={"Authorization": f"Bearer {key_a}"}).status_code == 200
            row = db_session.scalar(select(Trace).where(Trace.trace_id == "same-trace", Trace.tenant_id == tenant_a.id))
            assert row is not None and row.metadata_json == {"owner": "a"}
    finally:
        app.dependency_overrides.clear()


def test_key_expiry_revocation_rotation_and_secret_storage(client, db_session):
    tenant = create_tenant(db_session, f"keys-{uuid4().hex[:12]}", "Key lifecycle")
    expired_row, expired_key = create_api_key(db_session, tenant, ["traces:read"], "expired", os.environ["AGENTGUARD_KEY_PEPPER"], datetime.now(timezone.utc) - timedelta(seconds=1))
    revoked_row, revoked_key = create_api_key(db_session, tenant, ["traces:read"], "revoked", os.environ["AGENTGUARD_KEY_PEPPER"])
    db_session.refresh(revoked_row)
    revoked_row.revoked_at = datetime.now(timezone.utc)
    db_session.commit()
    _, replacement_key = create_api_key(db_session, tenant, ["ingest:write", "traces:read"], "replacement", os.environ["AGENTGUARD_KEY_PEPPER"])
    assert client.get("/v1/traces", headers={"Authorization": f"Bearer {expired_key}"}).status_code == 401
    assert client.get("/v1/traces", headers={"Authorization": f"Bearer {revoked_key}"}).status_code == 401
    assert client.post("/v1/ingest", json={"events": [event("trace.started", "rotated", {"trace_id": "rotated"})]}, headers={"Authorization": f"Bearer {replacement_key}"}).status_code == 202
    assert not expired_row.secret_digest.startswith("agk_")
    assert all("agk_" not in str(value) for value in db_session.scalars(select(ApiKey.secret_digest)))


def test_replay_requires_scope_is_idempotent_and_is_tenant_scoped(db_session):
    tenant = create_tenant(db_session, f"replay-api-{uuid4().hex[:12]}", "Replay API")
    _, replay_key = create_api_key(db_session, tenant, ["ingest:write", "traces:read", "replay:run"], "replay", os.environ["AGENTGUARD_KEY_PEPPER"])
    _, read_key = create_api_key(db_session, tenant, ["traces:read"], "read", os.environ["AGENTGUARD_KEY_PEPPER"])
    def override():
        yield db_session
    app.dependency_overrides[api_db_session] = override
    try:
        with TestClient(app) as replay_client:
            replay_client.headers.update({"Authorization": f"Bearer {replay_key}"})
            trace_id = f"replay-api-{uuid4().hex}"
            events = [
                event("trace.started", f"{trace_id}-start", {"trace_id": trace_id, "workflow_name": "replay"}),
                event("span.started", f"{trace_id}-span", {"trace_id": trace_id, "span_id": "replay-span", "span_type": "tool", "name": "get_weather"}),
                event("trace.ended", f"{trace_id}-end", {"trace_id": trace_id, "status": "success"}),
            ]
            assert replay_client.post("/v1/ingest", json={"events": events}, headers={"Authorization": f"Bearer {replay_key}"}).status_code == 202
            first = replay_client.post(f"/v1/traces/{trace_id}/replay", json={"mode": "dry_run"}, headers={"Idempotency-Key": "replay-once"})
            second = replay_client.post(f"/v1/traces/{trace_id}/replay", json={"mode": "dry_run"}, headers={"Idempotency-Key": "replay-once"})
            assert first.status_code == 200
            assert second.status_code == 200
            assert first.json()["id"] == second.json()["id"]
            assert replay_client.post(f"/v1/traces/{trace_id}/replay", json={"mode": "execute"}).status_code == 422
            assert replay_client.post(f"/v1/traces/{trace_id}/replay", json={"mode": "dry_run"}, headers={"Authorization": f"Bearer {read_key}"}).status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_analysis_is_deterministic_by_default_scoped_and_idempotent(db_session):
    tenant = create_tenant(db_session, f"analysis-api-{uuid4().hex[:12]}", "Analysis API")
    _, analysis_key = create_api_key(db_session, tenant, ["ingest:write", "traces:read", "analysis:run"], "analysis", os.environ["AGENTGUARD_KEY_PEPPER"])
    _, read_key = create_api_key(db_session, tenant, ["traces:read"], "analysis-read", os.environ["AGENTGUARD_KEY_PEPPER"])
    def override():
        yield db_session
    app.dependency_overrides[api_db_session] = override
    try:
        with TestClient(app) as analysis_client:
            headers = {"Authorization": f"Bearer {analysis_key}"}
            trace_id = f"analysis-api-{uuid4().hex}"
            events = [
                event("trace.started", f"{trace_id}-start", {"trace_id": trace_id}),
                event("span.started", f"{trace_id}-span", {"trace_id": trace_id, "span_id": "analysis-timeout", "span_type": "tool", "name": "tool", "status": "timeout"}),
                event("trace.ended", f"{trace_id}-end", {"trace_id": trace_id, "status": "success"}),
            ]
            assert analysis_client.post("/v1/ingest", json={"events": events}, headers=headers).status_code == 202
            first = analysis_client.post(f"/v1/traces/{trace_id}/analysis", json={"mode": "deterministic"}, headers={**headers, "Idempotency-Key": "analysis-once"})
            second = analysis_client.post(f"/v1/traces/{trace_id}/analysis", json={"mode": "deterministic"}, headers={**headers, "Idempotency-Key": "analysis-once"})
            assert first.status_code == 200 and second.status_code == 200
            assert first.json()["id"] == second.json()["id"]
            assert first.json()["findings"][0]["category"] == "TIMEOUT"
            assert analysis_client.post(f"/v1/traces/{trace_id}/analysis", json={"mode": "fully_autonomous"}, headers=headers).status_code == 422
            assert analysis_client.post(f"/v1/traces/{trace_id}/analysis", json={"mode": "deterministic"}, headers={"Authorization": f"Bearer {read_key}"}).status_code == 403
            assert analysis_client.get(f"/v1/analyses/{first.json()['id']}", headers={"Authorization": f"Bearer {read_key}"}).status_code == 200
    finally:
        app.dependency_overrides.clear()


@pytest.fixture()
def postgres_integration_session():
    runtime_url = (os.getenv("AGENTGUARD_TEST_RUNTIME_DATABASE_URL")
                   or os.getenv("AGENTGUARD_TEST_INTEGRATION_DATABASE_URL")
                   or os.getenv("AGENTGUARD_TEST_DATABASE_URL") or os.getenv("DATABASE_URL"))
    setup_url = (os.getenv("AGENTGUARD_TEST_SETUP_DATABASE_URL")
                 or os.getenv("AGENTGUARD_TEST_MIGRATION_DATABASE_URL"))
    if (not runtime_url or not runtime_url.startswith(("postgresql", "postgres"))
            or not setup_url or not setup_url.startswith(("postgresql", "postgres"))):
        pytest.skip("set AGENTGUARD_TEST_DATABASE_URL and AGENTGUARD_TEST_SETUP_DATABASE_URL to PostgreSQL URLs")

    setup_engine = create_engine(setup_url, future=True, pool_pre_ping=True)
    runtime_engine = create_engine(runtime_url, future=True, pool_pre_ping=True)
    try:
        with setup_engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except OperationalError as exc:
        setup_engine.dispose()
        runtime_engine.dispose()
        pytest.fail(f"PostgreSQL URL was provided but is not reachable: {exc}")

    with setup_engine.connect() as connection:
        migration = connection.execute(text("SELECT version_num FROM public.alembic_version")).scalar_one_or_none()
    assert migration == "0018_v20_archive_quorum_bindings", f"expected migration 0018_v20_archive_quorum_bindings, got {migration!r}"

    schema = f"agentguard_test_{uuid4().hex}"
    with setup_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    setup_schema_engine = setup_engine.execution_options(schema_translate_map={None: schema})
    Base.metadata.create_all(setup_schema_engine)
    with setup_engine.begin() as connection:
        connection.execute(text(f'GRANT USAGE ON SCHEMA "{schema}" TO agentguard_runtime'))
        connection.execute(text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "{schema}" TO agentguard_runtime'))
        connection.execute(text(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA "{schema}" TO agentguard_runtime'))
    runtime_schema_engine = runtime_engine.execution_options(schema_translate_map={None: schema})
    session = sessionmaker(bind=runtime_schema_engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        with setup_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        setup_engine.dispose()
        runtime_engine.dispose()

def test_postgresql_integration_trace_spans_jsonb_idempotency_and_query(postgres_integration_session):
    db = postgres_integration_session
    tenant = create_tenant(db, f"pg-{uuid4().hex[:12]}", "PostgreSQL isolation tenant")
    _, api_key = create_api_key(db, tenant, ["ingest:write", "traces:read"], "integration", os.environ["AGENTGUARD_KEY_PEPPER"])
    assert api_key.startswith("agk_")
    trace_id = f"integration-{uuid4().hex}"
    root_id = f"{trace_id}-root"
    child_id = f"{trace_id}-child"
    events = [
        Event(event_type="trace.started", event_id=trace_id, data={
            "trace_id": trace_id, "workflow_name": "postgres-integration", "status": "running",
            "metadata": {"nested": {"source": "pytest", "attempt": 1}},
        }),
        Event(event_type="span.started", event_id=root_id, data={
            "span_id": root_id, "trace_id": trace_id, "span_type": "agent", "name": "root",
        }),
        Event(event_type="span.started", event_id=child_id, data={
            "span_id": child_id, "trace_id": trace_id, "parent_span_id": root_id,
            "span_type": "tool", "name": "child", "attributes": {"json": {"ok": True, "count": 2}},
        }),
        Event(event_type="span.ended", event_id=child_id, data={
            "span_id": child_id, "trace_id": trace_id, "status": "success", "duration_ms": 12.5,
        }),
        Event(event_type="trace.ended", event_id=trace_id, data={
            "trace_id": trace_id, "status": "success",
        }),
    ]
    accepted, duplicates = ingest_events(db, events, tenant.id)
    assert (accepted, duplicates) == (5, 0)
    assert ingest_events(db, [events[2]], tenant.id) == (0, 1)

    trace, spans = get_trace(db, trace_id, tenant.id)
    assert trace is not None
    assert trace.status == "success"
    assert trace.metadata_json["nested"]["attempt"] == 1
    assert len(spans) == 2
    child = next(span for span in spans if span.span_id == child_id)
    assert child.parent_span_id == root_id
    assert child.attributes["json"]["ok"] is True
    assert child.duration_ms == 12.5

    stored_trace = db.get(Trace, trace.id)
    stored_child = db.get(Span, child.id)
    assert stored_trace is not None and stored_child is not None
    assert stored_child.trace_id == stored_trace.trace_id == trace_id
    assert stored_trace.tenant_id == stored_child.tenant_id == tenant.id
    assert db.scalar(select(Tenant).where(Tenant.id == tenant.id)) is not None
    integrity = verify_trace_integrity(db, tenant.id, trace_id)
    assert integrity.status == "valid"
    assert integrity.events_checked == 5
    assert integrity.chain_valid is True
    assert integrity.projection_consistent is True

