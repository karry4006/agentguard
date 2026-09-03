"""V6 end-to-end acceptance through the existing HTTP/PostgreSQL pipeline."""

import os
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import delete
from sqlalchemy.orm import sessionmaker

from agentguard import AgentGuardConfig
from agentguard.opentelemetry import AgentGuardOpenTelemetrySpanProcessor
from agentguard_server.models import Tenant
from agentguard_server.services.auth import create_api_key, create_tenant


@pytest.fixture()
def v6_context(tmp_path):
    database_url = os.environ.get("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url or not database_url.startswith(("postgresql", "postgres")):
        pytest.skip("set AGENTGUARD_TEST_DATABASE_URL to run V6 live acceptance")
    from sqlalchemy import create_engine

    engine = create_engine(database_url, future=True)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    db = session_factory()
    tenant = create_tenant(db, f"v6-{uuid4().hex[:12]}", "V6 live tenant")
    pepper = os.environ["AGENTGUARD_KEY_PEPPER"]
    _, api_key = create_api_key(db, tenant, ["ingest:write", "traces:read", "analysis:run"], "v6-live", pepper)
    try:
        yield {"db": db, "tenant": tenant, "api_key": api_key, "spool": tmp_path / "otel.sqlite3"}
    finally:
        db.rollback()
        db.execute(delete(Tenant).where(Tenant.id == tenant.id))
        db.commit()
        db.close()
        engine.dispose()


def test_v6_otel_trace_is_queryable_integrity_checked_and_analyzed(v6_context):
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.trace import Status, StatusCode

    config = AgentGuardConfig(
        ingest_url=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000") + "/v1/ingest", api_key=v6_context["api_key"],
        spool_path=str(v6_context["spool"]), capture_content=False, batch_size=50,
        allow_insecure_http=bool(os.getenv("AGENTGUARD_TEST_SERVER_URL")),
    )
    processor = AgentGuardOpenTelemetrySpanProcessor(config=config)
    provider = TracerProvider()
    provider.add_span_processor(processor)
    tracer = provider.get_tracer("agentguard-v6-live")
    with tracer.start_as_current_span("workflow", attributes={
        "gen_ai.operation.name": "invoke_workflow", "gen_ai.provider.name": "openai",
    }) as workflow:
        trace_id = f"{workflow.get_span_context().trace_id:032x}"
        with tracer.start_as_current_span("agent", attributes={"gen_ai.operation.name": "invoke_agent"}):
            with tracer.start_as_current_span("timed-out-tool", attributes={
                "gen_ai.operation.name": "execute_tool", "error.type": "TimeoutError",
                "gen_ai.input.messages": "must not be stored",
            }) as timed_out:
                timed_out.set_status(Status(StatusCode.ERROR))
    assert processor.force_flush(5000)
    processor.shutdown()

    with httpx.Client(base_url=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000"), headers={"Authorization": f"Bearer {v6_context['api_key']}"}, timeout=10) as client:
        trace_response = client.get(f"/v1/traces/{trace_id}")
        assert trace_response.status_code == 200
        body = trace_response.json()
        assert any(span["span_type"] == "tool" for span in body["spans"])
        assert all("must not be stored" not in repr(item) for item in body["spans"])
        integrity = client.get(f"/v1/traces/{trace_id}/integrity")
        assert integrity.status_code == 200
        assert integrity.json()["status"] == "valid"
        analysis = client.post(f"/v1/traces/{trace_id}/analysis", json={"mode": "deterministic"})
        assert analysis.status_code == 200
        assert "TIMEOUT" in {finding["category"] for finding in analysis.json()["findings"]}
