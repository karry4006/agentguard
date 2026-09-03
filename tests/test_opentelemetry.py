import threading

import pytest

from agentguard import AgentGuardConfig
from agentguard.exporter import HttpBatchExporter
from agentguard.opentelemetry import (
    AGENTGUARD_MAPPING_VERSION,
    AgentGuardOpenTelemetrySpanProcessor,
    normalize_otel_span,
)


def _sdk():
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    return trace, TracerProvider


class RecordingExporter:
    def __init__(self):
        self.events = []

    def submit(self, event):
        self.events.append(event)
        return True

    def force_flush(self):
        return True

    def shutdown(self):
        pass

    def diagnostics(self):
        return {}


def test_otel_workflow_agent_model_tool_mapping_and_lifecycle():
    trace, TracerProvider = _sdk()
    exporter = RecordingExporter()
    processor = AgentGuardOpenTelemetrySpanProcessor(exporter=exporter)
    provider = TracerProvider()
    provider.add_span_processor(processor)
    tracer = provider.get_tracer("v6-test")

    with tracer.start_as_current_span("workflow", attributes={
        "gen_ai.operation.name": "invoke_workflow",
        "gen_ai.provider.name": "openai",
    }):
        with tracer.start_as_current_span("agent", attributes={"gen_ai.operation.name": "invoke_agent"}):
            with tracer.start_as_current_span("model", attributes={
                "gen_ai.operation.name": "chat",
                "gen_ai.provider.name": "anthropic",
            }):
                with tracer.start_as_current_span("tool", attributes={
                    "gen_ai.operation.name": "execute_tool",
                }):
                    pass
    provider.shutdown()

    types = {event["event_type"] for event in exporter.events}
    assert {"trace.started", "trace.ended", "span.started", "span.ended"} <= types
    ended = [event for event in exporter.events if event["event_type"] == "span.ended"]
    by_name = {event["data"]["name"]: event["data"] for event in ended}
    assert by_name["workflow"]["span_type"] == "agent"
    assert by_name["agent"]["span_type"] == "agent"
    assert by_name["model"]["span_type"] == "llm"
    assert by_name["model"]["attributes"]["gen_ai.provider.name"] == "anthropic"
    assert by_name["tool"]["span_type"] == "tool"
    assert by_name["tool"]["parent_span_id"] == by_name["model"]["span_id"]
    assert all(len(event["data"]["trace_id"]) == 32 for event in ended)
    assert all(len(event["data"]["span_id"]) == 16 for event in ended)
    assert by_name["model"]["attributes"]["agentguard_mapping_version"] == AGENTGUARD_MAPPING_VERSION


def test_anthropic_openai_mcp_and_unknown_operations_are_observational():
    trace, TracerProvider = _sdk()
    exporter = RecordingExporter()
    processor = AgentGuardOpenTelemetrySpanProcessor(exporter=exporter)
    provider = TracerProvider()
    provider.add_span_processor(processor)
    tracer = provider.get_tracer("v6-test")
    with tracer.start_as_current_span("anthropic", attributes={
        "gen_ai.operation.name": "chat", "gen_ai.provider.name": "anthropic",
    }):
        pass
    with tracer.start_as_current_span("mcp", attributes={
        "gen_ai.operation.name": "execute_tool", "gen_ai.provider.name": "generic",
        "mcp.method.name": "tools/call",
    }):
        pass
    with tracer.start_as_current_span("future", attributes={
        "gen_ai.operation.name": "future_operation_xyz", "gen_ai.provider.name": "future_provider_xyz",
    }):
        pass
    provider.shutdown()
    ended = [event["data"] for event in exporter.events if event["event_type"] == "span.ended"]
    assert next(item for item in ended if item["name"] == "anthropic")["span_type"] == "llm"
    assert next(item for item in ended if item["name"] == "mcp")["span_type"] == "tool"
    future = next(item for item in ended if item["name"] == "future")
    assert future["span_type"] == "unknown"
    assert future["attributes"]["otel.operation.name"] == "future_operation_xyz"
    assert future["attributes"]["gen_ai.provider.name"] == "future_provider_xyz"


def test_otel_content_secret_and_tenant_spoof_protection():
    trace, TracerProvider = _sdk()
    exporter = RecordingExporter()
    processor = AgentGuardOpenTelemetrySpanProcessor(exporter=exporter)
    provider = TracerProvider()
    provider.add_span_processor(processor)
    tracer = provider.get_tracer("v6-test")
    with tracer.start_as_current_span("sensitive", attributes={
        "gen_ai.operation.name": "chat",
        "gen_ai.input.messages": "private prompt",
        "gen_ai.output.messages": "private completion",
        "Authorization": "Bearer top-secret",
        "OPENAI_API_KEY": "sk-test-secret-value",
        "anthropic_api_key": "sk-ant-api03-secret-value",
        "database_password": "db-secret",
        "integrity_key": "integrity-secret",
        "tenant_id": "other-tenant",
    }):
        pass
    provider.shutdown()
    payload = repr(exporter.events)
    assert "private prompt" not in payload
    assert "private completion" not in payload
    assert "top-secret" not in payload
    assert "sk-test-secret-value" not in payload
    assert "sk-ant-api03-secret-value" not in payload
    assert "db-secret" not in payload
    assert "integrity-secret" not in payload
    assert "other-tenant" not in payload


def test_otel_attributes_are_bounded_and_unknown_values_do_not_crash():
    trace, TracerProvider = _sdk()
    exporter = RecordingExporter()
    processor = AgentGuardOpenTelemetrySpanProcessor(
        exporter=exporter, max_attributes=4, max_attribute_value_length=20, max_metadata_bytes=300
    )
    provider = TracerProvider()
    provider.add_span_processor(processor)
    tracer = provider.get_tracer("v6-test")
    attrs = {f"future.{i}": "x" * 100 for i in range(100)}
    with tracer.start_as_current_span("bounded", attributes=attrs):
        pass
    provider.shutdown()
    ended = next(event["data"] for event in exporter.events if event["event_type"] == "span.ended")
    assert len(ended["attributes"]) <= 4
    assert len(repr(ended["attributes"]).encode()) <= 300


def test_otel_processor_is_fail_open_and_durable_exporter_is_reused(tmp_path):
    class BrokenExporter:
        def submit(self, _event):
            raise RuntimeError("exporter unavailable")

        def force_flush(self):
            return False

        def shutdown(self):
            pass

        def diagnostics(self):
            return {"errors": 1}

    processor = AgentGuardOpenTelemetrySpanProcessor(exporter=BrokenExporter())
    fake = type("Span", (), {
        "name": "synthetic", "attributes": {"gen_ai.operation.name": "chat"},
        "context": type("Context", (), {"trace_id": 1, "span_id": 2, "is_valid": True})(),
        "parent": None, "start_time": None, "end_time": None,
    })()
    processor.on_start(fake)
    processor.on_end(fake)
    assert processor.diagnostics()["errors"] >= 1

    calls = []
    def unavailable(_batch):
        calls.append(True)
        raise ConnectionError("offline")
    exporter = HttpBatchExporter(AgentGuardConfig(spool_path=str(tmp_path / "otel.sqlite3"), max_retries=2), send_batch=unavailable)
    processor = AgentGuardOpenTelemetrySpanProcessor(exporter=exporter)
    processor.on_end(fake)
    assert processor.force_flush(2)
    assert exporter.diagnostics()["pending_events"] >= 1
    processor.shutdown()
    assert calls


def test_otel_normalization_is_thread_safe_for_distinct_spans():
    trace, TracerProvider = _sdk()
    exporter = RecordingExporter()
    processor = AgentGuardOpenTelemetrySpanProcessor(exporter=exporter)
    provider = TracerProvider()
    provider.add_span_processor(processor)
    tracer = provider.get_tracer("v6-test")

    def emit(index):
        with tracer.start_as_current_span(f"tool-{index}", attributes={"gen_ai.operation.name": "execute_tool"}):
            pass

    threads = [threading.Thread(target=emit, args=(index,)) for index in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    provider.shutdown()
    ended = [event for event in exporter.events if event["event_type"] == "span.ended"]
    assert len({event["event_id"] for event in ended}) == 20
    assert all(event["data"]["span_type"] == "tool" for event in ended)


def test_otel_duplicate_end_is_idempotent_and_missing_start_does_not_invent_trace_success():
    trace, TracerProvider = _sdk()
    exporter = RecordingExporter()
    processor = AgentGuardOpenTelemetrySpanProcessor(exporter=exporter)
    provider = TracerProvider()
    provider.add_span_processor(processor)
    tracer = provider.get_tracer("v6-test")
    with tracer.start_as_current_span("normal", attributes={"gen_ai.operation.name": "chat"}) as span:
        pass
    processor.on_end(span)
    provider.shutdown()
    ended = [event for event in exporter.events if event["event_type"] == "span.ended"]
    assert len(ended) == 1
    assert processor.diagnostics()["duplicate_ends"] == 1

    orphan_exporter = RecordingExporter()
    orphan_processor = AgentGuardOpenTelemetrySpanProcessor(exporter=orphan_exporter)
    orphan_processor.on_end(span)
    assert [event for event in orphan_exporter.events if event["event_type"] == "trace.ended"] == []
