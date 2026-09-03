"""Public-seam tests for the OTLP/HTTP protobuf ingestion gateway."""

import gzip

from opentelemetry.proto.collector.trace.v1 import trace_service_pb2
from opentelemetry.proto.common.v1 import common_pb2
from opentelemetry.proto.resource.v1 import resource_pb2
from opentelemetry.proto.trace.v1 import trace_pb2


def _span(trace_id: bytes, span_id: bytes, *, parent: bytes = b"", name: str = "workflow", attributes=None) -> trace_pb2.Span:
    span = trace_pb2.Span(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent,
        name=name,
        start_time_unix_nano=1_700_000_000_000_000_000,
        end_time_unix_nano=1_700_000_001_000_000_000,
        status=trace_pb2.Status(code=trace_pb2.Status.STATUS_CODE_OK),
    )
    for key, value in {"gen_ai.operation.name": "invoke_workflow", **(attributes or {})}.items():
        span.attributes.append(common_pb2.KeyValue(key=key, value=common_pb2.AnyValue(string_value=value)))
    return span


def _span_request(*spans: trace_pb2.Span) -> bytes:
    request = trace_service_pb2.ExportTraceServiceRequest(
        resource_spans=[trace_pb2.ResourceSpans(
            resource=resource_pb2.Resource(attributes=[common_pb2.KeyValue(
                key="service.name", value=common_pb2.AnyValue(string_value="otlp-test")
            )]),
            scope_spans=[trace_pb2.ScopeSpans(spans=list(spans))],
        )]
    )
    return request.SerializeToString()


def test_otlp_http_protobuf_ingest_returns_standard_response(client):
    trace_id = bytes.fromhex("11" * 16)
    span_id = bytes.fromhex("22" * 8)
    response = client.post(
        "/otlp/v1/traces",
        content=_span_request(_span(trace_id, span_id)),
        headers={"Content-Type": "application/x-protobuf"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-protobuf")
    decoded = trace_service_pb2.ExportTraceServiceResponse()
    decoded.ParseFromString(response.content)
    assert decoded.ByteSize() == 0


def test_otlp_gzip_parent_child_and_multiple_traces_are_queryable(client):
    trace_a = bytes.fromhex("31" * 16)
    trace_b = bytes.fromhex("32" * 16)
    root = _span(trace_a, bytes.fromhex("41" * 8), name="root")
    child = _span(trace_a, bytes.fromhex("42" * 8), parent=bytes.fromhex("41" * 8), name="child")
    other = _span(trace_b, bytes.fromhex("43" * 8), name="other")
    response = client.post(
        "/otlp/v1/traces", content=gzip.compress(_span_request(root, child, other)),
        headers={"Content-Type": "application/x-protobuf", "Content-Encoding": "gzip"},
    )
    assert response.status_code == 200
    body = client.get(f"/v1/traces/{trace_a.hex()}").json()
    assert {span["span_id"] for span in body["spans"]} == {"41" * 8, "42" * 8}
    assert body["span_tree"][0]["children"][0]["span"]["span_id"] == "42" * 8
    assert client.get(f"/v1/traces/{trace_b.hex()}").status_code == 200


def test_otlp_retry_is_idempotent_and_content_is_redacted(client):
    trace_id = bytes.fromhex("51" * 16)
    payload = _span_request(_span(trace_id, bytes.fromhex("52" * 8), attributes={
        "authorization": "Bearer synthetic-otlp-token",
        "openai_key": "sk-synthetic-secret-value",
        "gen_ai.input.messages": "prompt must not persist",
    }))
    assert client.post("/otlp/v1/traces", content=payload, headers={"Content-Type": "application/x-protobuf"}).status_code == 200
    assert client.post("/otlp/v1/traces", content=payload, headers={"Content-Type": "application/x-protobuf"}).status_code == 200
    response = client.get(f"/v1/traces/{trace_id.hex()}")
    assert response.status_code == 200
    assert len(response.json()["spans"]) == 1
    assert "synthetic-otlp-token" not in response.text
    assert "synthetic-secret-value" not in response.text
    assert "prompt must not persist" not in response.text


def test_otlp_malformed_content_and_limits_fail_safely(client, monkeypatch):
    bad = client.post("/otlp/v1/traces", content=b"not protobuf", headers={"Content-Type": "application/x-protobuf"})
    assert bad.status_code == 400
    bad_gzip = client.post("/otlp/v1/traces", content=b"not gzip", headers={
        "Content-Type": "application/x-protobuf", "Content-Encoding": "gzip",
    })
    assert bad_gzip.status_code == 400
    wrong_type = client.post("/otlp/v1/traces", content=b"x", headers={"Content-Type": "application/json"})
    assert wrong_type.status_code == 415

    from agentguard_server.config import get_settings
    settings = get_settings()
    old = settings.otlp_max_decompressed_bytes
    settings.otlp_max_decompressed_bytes = 32
    try:
        limited = client.post("/otlp/v1/traces", content=gzip.compress(_span_request(_span(bytes.fromhex("61" * 16), bytes.fromhex("62" * 8)))), headers={
            "Content-Type": "application/x-protobuf", "Content-Encoding": "gzip",
        })
        assert limited.status_code == 413
    finally:
        settings.otlp_max_decompressed_bytes = old


def test_otlp_rejects_zero_ids_and_deep_anyvalue_without_auth(client):
    zero_id = client.post("/otlp/v1/traces", content=_span_request(_span(b"\x00" * 16, bytes.fromhex("72" * 8))), headers={
        "Content-Type": "application/x-protobuf",
    })
    assert zero_id.status_code == 400

    value = common_pb2.AnyValue(string_value="leaf")
    for _ in range(10):
        value = common_pb2.AnyValue(array_value=common_pb2.ArrayValue(values=[value]))
    span = _span(bytes.fromhex("73" * 16), bytes.fromhex("74" * 8))
    span.attributes.append(common_pb2.KeyValue(key="nested", value=value))
    deep = client.post("/otlp/v1/traces", content=_span_request(span), headers={"Content-Type": "application/x-protobuf"})
    assert deep.status_code == 413

    client.headers.pop("Authorization")
    unauthenticated = client.post("/otlp/v1/traces", content=b"x", headers={"Content-Type": "application/x-protobuf"})
    assert unauthenticated.status_code == 401


def test_otlp_unknown_provider_and_operation_are_observational(client):
    trace_id = bytes.fromhex("81" * 16)
    response = client.post("/otlp/v1/traces", content=_span_request(_span(
        trace_id, bytes.fromhex("82" * 8), name="future-operation",
        attributes={"gen_ai.operation.name": "future_operation", "gen_ai.provider.name": "future-provider"},
    )), headers={"Content-Type": "application/x-protobuf"})
    assert response.status_code == 200
    body = client.get(f"/v1/traces/{trace_id.hex()}").json()
    assert body["spans"][0]["span_type"] == "unknown"
    assert body["spans"][0]["attributes"]["otel.operation.name"] == "future_operation"
