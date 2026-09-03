import threading

import pytest

from agentguard import AgentGuardConfig, AgentGuardTracingProcessor, Span, SpanType, Trace
from agentguard.exporter import HttpBatchExporter
from agentguard.redaction import redact


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


def test_trace_and_span_serialization():
    trace = Trace(trace_id="t-1", workflow_name="demo")
    span = Span(span_id="s-1", trace_id="t-1", span_type=SpanType.TOOL, name="get_weather")
    assert trace.model_dump()["schema_version"] == "0.1"
    assert span.model_dump()["span_type"] == "tool"


def test_processor_mapping_and_unknown_span():
    exporter = RecordingExporter()
    processor = AgentGuardTracingProcessor(AgentGuardConfig(capture_content=False), exporter=exporter)
    processor.on_trace_start({"trace_id": "t-1", "name": "demo"})
    processor.on_span_start({"span_id": "s-1", "trace_id": "t-1", "type": "generation", "name": "model"})
    processor.on_span_end({"span_id": "s-1", "trace_id": "t-1", "type": "generation", "name": "model", "status": "success"})
    processor.on_span_start({"span_id": "s-2", "trace_id": "t-1", "type": "vendor_magic"})
    assert [event["event_type"] for event in exporter.events] == ["trace.started", "span.started", "span.ended", "span.started"]
    assert exporter.events[1]["data"]["span_type"] == "llm"
    assert exporter.events[3]["data"]["span_type"] == "unknown"
    assert exporter.events[3]["data"]["attributes"]["provider_span_type"] == "vendor_magic"


def test_sensitive_redaction_and_content_default():
    data = {"Authorization": "Bearer abc", "api_key": "sk-test-secret", "agentguard_key": "agk_0123456789abcdef_abcdefghijklmnopqrstuvwxyz1234567890ABCDE", "prompt": "hello", "nested": "token=sk-another-secret"}
    output = redact(data)
    assert output["Authorization"] == "[REDACTED]"
    assert output["api_key"] == "[REDACTED]"
    assert output["agentguard_key"] == "[REDACTED]"
    assert output["prompt"] == "[CONTENT_CAPTURE_DISABLED]"
    assert "[REDACTED]" in output["nested"]


def test_remote_http_endpoint_requires_explicit_insecure_opt_in():
    with pytest.raises(ValueError, match="HTTPS"):
        AgentGuardConfig(ingest_url="http://telemetry.example/v1/ingest")
    assert AgentGuardConfig(ingest_url="http://telemetry.example/v1/ingest", allow_insecure_http=True).ingest_url.startswith("http://")


def test_export_failure_is_bounded_and_does_not_raise():
    calls = []

    def fail(batch):
        calls.append(batch)
        raise RuntimeError("offline")

    exporter = HttpBatchExporter(AgentGuardConfig(batch_size=1, max_retries=1, flush_interval_seconds=0.01, spool_enabled=False), send_batch=fail)
    assert exporter.submit({"event_type": "trace.started", "event_id": "t"})
    assert exporter.force_flush(2)
    exporter.shutdown()
    assert len(calls) >= 1


def test_queue_overflow_is_non_blocking_and_counted():
    entered = threading.Event()
    release = threading.Event()

    def block(batch):
        entered.set()
        release.wait(2)

    exporter = HttpBatchExporter(AgentGuardConfig(queue_size=1, batch_size=1, max_retries=0, spool_enabled=False), send_batch=block)
    assert exporter.submit({"event_id": "id-1", "id": 1})
    assert entered.wait(1)
    assert exporter.submit({"event_id": "id-2", "id": 2}) is True
    assert exporter.submit({"event_id": "id-3", "id": 3}) is False
    assert exporter.dropped_events == 1
    release.set()
    exporter.shutdown()
