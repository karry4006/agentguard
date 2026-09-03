"""Protocol-level V7 acceptance using the official OTLP/HTTP exporter."""

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import httpx
import pytest
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http import Compression
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.trace import Status, StatusCode
from sqlalchemy import delete
from sqlalchemy.orm import sessionmaker

from agentguard_server.models import Tenant
from agentguard_server.services.auth import create_api_key, create_tenant


@pytest.fixture()
def v7_context(tmp_path):
    database_url = os.environ.get("AGENTGUARD_TEST_DATABASE_URL")
    if not database_url or not database_url.startswith(("postgresql", "postgres")):
        pytest.skip("set AGENTGUARD_TEST_DATABASE_URL to run V7 live acceptance")
    from sqlalchemy import create_engine

    engine = create_engine(database_url, future=True, pool_size=10, max_overflow=5, pool_pre_ping=True)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    db = session_factory()
    tenant = create_tenant(db, f"v7-{uuid4().hex[:12]}", "V7 temporary tenant")
    pepper = os.environ["AGENTGUARD_KEY_PEPPER"]
    _, api_key = create_api_key(db, tenant, ["ingest:write", "traces:read", "replay:run", "analysis:run"], "v7-live", pepper)
    try:
        yield {"db": db, "tenant": tenant, "api_key": api_key, "spool": tmp_path / "v7-spool.sqlite3"}
    finally:
        db.rollback()
        db.execute(delete(Tenant).where(Tenant.id == tenant.id))
        db.commit()
        db.close()
        engine.dispose()


def _exporter(api_key: str, *, gzip_enabled: bool = True) -> OTLPSpanExporter:
    return OTLPSpanExporter(
        endpoint=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000") + "/otlp/v1/traces",
        headers={"Authorization": f"Bearer {api_key}"},
        compression=Compression.Gzip if gzip_enabled else Compression.NoCompression,
        timeout=10,
    )


def test_v7_official_otlp_exporter_live_pipeline(v7_context):
    ctx = v7_context
    exporter = _exporter(ctx["api_key"])
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("agentguard-v7-live")

    with tracer.start_as_current_span("anthropic-workflow", attributes={
        "gen_ai.operation.name": "invoke_workflow", "gen_ai.provider.name": "anthropic",
        "tenant_id": "spoofed-tenant", "authorization": "Bearer synthetic-v7-token",
        "gen_ai.input.messages": "synthetic prompt must not persist",
    }) as workflow:
        trace_id = f"{workflow.get_span_context().trace_id:032x}"
        with tracer.start_as_current_span("get_weather", attributes={
            "gen_ai.operation.name": "execute_tool", "gen_ai.provider.name": "anthropic",
            "tool.name": "get_weather", "arguments": "synthetic city",
        }) as tool:
            tool.set_status(Status(StatusCode.OK))
    assert trace_id

    timeout_span = tracer.start_span("timeout", attributes={
        "gen_ai.operation.name": "text_completion", "gen_ai.provider.name": "openai",
        "error.type": "TimeoutError",
    })
    timeout_trace_id = f"{timeout_span.get_span_context().trace_id:032x}"
    timeout_span.set_status(Status(StatusCode.ERROR))
    timeout_span.end()

    auth_span = tracer.start_span("auth-failure", attributes={
        "gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
        "error.type": "AuthenticationError", "status_code": "401",
    })
    auth_trace_id = f"{auth_span.get_span_context().trace_id:032x}"
    auth_span.set_status(Status(StatusCode.ERROR))
    auth_span.end()
    assert provider.force_flush(10_000)
    provider.shutdown()

    # Retransmit the same ended SDK spans through a fresh official exporter.
    retry_exporter = _exporter(ctx["api_key"])
    assert retry_exporter.export([workflow, tool]).name == "SUCCESS"
    retry_exporter.shutdown()

    with httpx.Client(base_url=os.getenv("AGENTGUARD_TEST_SERVER_URL", "http://127.0.0.1:8000"), headers={"Authorization": f"Bearer {ctx['api_key']}"}, timeout=10) as client:
        body = client.get(f"/v1/traces/{trace_id}").json()
        assert {span["span_type"] for span in body["spans"]} >= {"agent", "tool"}
        tool_rows = [span for span in body["spans"] if span["span_type"] == "tool"]
        assert tool_rows[0]["parent_span_id"] == body["spans"][0]["span_id"]
        assert "synthetic-v7-token" not in repr(body)
        assert "synthetic prompt must not persist" not in repr(body)
        assert client.get(f"/v1/traces/{trace_id}/integrity").json()["status"] == "valid"
        replay = client.post(f"/v1/traces/{trace_id}/replay", json={"mode": "dry_run"})
        assert replay.status_code == 200
        assert replay.json()["mode"] == "dry_run"
        assert replay.json()["integrity_status"] == "valid"
        timeout = client.post(f"/v1/traces/{timeout_trace_id}/analysis", json={"mode": "deterministic"})
        auth = client.post(f"/v1/traces/{auth_trace_id}/analysis", json={"mode": "deterministic"})
        assert timeout.status_code == 200 and "TIMEOUT" in {item["category"] for item in timeout.json()["findings"]}
        assert auth.status_code == 200 and "AUTHENTICATION" in {item["category"] for item in auth.json()["findings"]}

        def resend():
            return _exporter(ctx["api_key"], gzip_enabled=False).export([workflow, tool]).name

        with ThreadPoolExecutor(max_workers=4) as pool:
            assert set(pool.map(lambda _: resend(), range(4))) == {"SUCCESS"}
        assert client.get(f"/v1/traces/{trace_id}/integrity").json()["status"] == "valid"
