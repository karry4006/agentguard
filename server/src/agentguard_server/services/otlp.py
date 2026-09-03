"""Bounded OTLP/HTTP protobuf decoding into AgentGuard's event interface."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import json
import math
from typing import Any

from opentelemetry.proto.collector.trace.v1 import trace_service_pb2
from opentelemetry.proto.trace.v1 import trace_pb2

from agentguard.opentelemetry import normalize_otel_span
from agentguard_server.schemas.events import Event


class OTLPDecodeError(ValueError):
    def __init__(self, detail: str, *, limit: bool = False) -> None:
        super().__init__(detail)
        self.limit = limit


@dataclass(frozen=True)
class OTLPSettings:
    max_compressed_bytes: int = 1024 * 1024
    max_decompressed_bytes: int = 4 * 1024 * 1024
    max_resource_spans: int = 100
    max_scope_spans: int = 1000
    max_spans: int = 1000
    max_attributes: int = 64
    max_events: int = 128
    max_links: int = 128
    max_attribute_key_length: int = 128
    max_attribute_value_length: int = 2048
    max_metadata_bytes: int = 16 * 1024
    max_anyvalue_depth: int = 8
    max_anyvalue_items: int = 128


class _Context:
    is_valid = True

    def __init__(self, trace_id: int, span_id: int) -> None:
        self.trace_id = trace_id
        self.span_id = span_id


class _Parent:
    def __init__(self, span_id: int) -> None:
        self.span_id = span_id


class _Status:
    def __init__(self, code: str) -> None:
        self.status_code = code


class _ReadableSpan:
    def __init__(self, span: trace_pb2.Span, attributes: dict[str, Any]) -> None:
        self.name = span.name[:255] or "unknown"
        self.attributes = attributes
        self.start_time = span.start_time_unix_nano or None
        self.end_time = span.end_time_unix_nano or None
        self.status = _Status({trace_pb2.Status.STATUS_CODE_ERROR: "ERROR"}.get(span.status.code, "OK"))
        self._context = _Context(int.from_bytes(span.trace_id, "big"), int.from_bytes(span.span_id, "big"))
        self.parent = _Parent(int.from_bytes(span.parent_span_id, "big")) if span.parent_span_id else None

    def get_span_context(self) -> _Context:
        return self._context


def decompress_body(body: bytes, content_encoding: str | None, settings: OTLPSettings) -> bytes:
    if len(body) > settings.max_compressed_bytes:
        raise OTLPDecodeError("OTLP request exceeds compressed size limit", limit=True)
    encoding = (content_encoding or "identity").strip().lower()
    if encoding in {"", "identity"}:
        if len(body) > settings.max_decompressed_bytes:
            raise OTLPDecodeError("OTLP request exceeds decompressed size limit", limit=True)
        return body
    if encoding != "gzip":
        raise OTLPDecodeError("unsupported OTLP content encoding")
    try:
        decompressor = gzip.GzipFile(fileobj=__import__("io").BytesIO(body))
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = decompressor.read(min(64 * 1024, settings.max_decompressed_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > settings.max_decompressed_bytes:
                raise OTLPDecodeError("OTLP request exceeds decompressed size limit", limit=True)
            chunks.append(chunk)
        return b"".join(chunks)
    except OTLPDecodeError:
        raise
    except (OSError, EOFError, ValueError) as exc:
        raise OTLPDecodeError("malformed gzip payload") from exc


def _any_value(value: Any, settings: OTLPSettings, depth: int = 0) -> Any:
    if depth > settings.max_anyvalue_depth:
        raise OTLPDecodeError("OTLP AnyValue nesting limit exceeded", limit=True)
    choice = value.WhichOneof("value")
    if choice is None:
        return None
    if choice == "string_value":
        if len(value.string_value) > settings.max_attribute_value_length:
            raise OTLPDecodeError("OTLP attribute value is too long", limit=True)
        return value.string_value
    if choice == "bool_value":
        return bool(value.bool_value)
    if choice == "int_value":
        return int(value.int_value)
    if choice == "double_value":
        if not math.isfinite(value.double_value):
            raise OTLPDecodeError("OTLP floating-point value is not finite")
        return float(value.double_value)
    if choice == "bytes_value":
        if len(value.bytes_value) > settings.max_attribute_value_length:
            raise OTLPDecodeError("OTLP byte value is too long", limit=True)
        return value.bytes_value.hex()
    if choice == "array_value":
        if len(value.array_value.values) > settings.max_anyvalue_items:
            raise OTLPDecodeError("OTLP AnyValue array is too large", limit=True)
        return [_any_value(item, settings, depth + 1) for item in value.array_value.values]
    if choice == "kvlist_value":
        if len(value.kvlist_value.values) > settings.max_anyvalue_items:
            raise OTLPDecodeError("OTLP AnyValue map is too large", limit=True)
        return _key_values(value.kvlist_value.values, settings, depth + 1)
    return None


def _key_values(values: Any, settings: OTLPSettings, depth: int = 0) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in values:
        key = item.key
        if not key or len(key) > settings.max_attribute_key_length:
            raise OTLPDecodeError("OTLP attribute key is invalid", limit=True)
        if key in result:
            raise OTLPDecodeError("duplicate OTLP attribute key")
        result[key] = _any_value(item.value, settings, depth)
    return result


def _attributes(values: Any, settings: OTLPSettings) -> dict[str, Any]:
    if len(values) > settings.max_attributes:
        raise OTLPDecodeError("OTLP attribute count limit exceeded", limit=True)
    result = _key_values(values, settings)
    if len(json.dumps(result, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")) > settings.max_metadata_bytes:
        raise OTLPDecodeError("OTLP normalized metadata limit exceeded", limit=True)
    return result


def _id(value: bytes, length: int, label: str) -> str:
    if len(value) != length or not any(value):
        raise OTLPDecodeError(f"invalid OTLP {label}")
    return value.hex()


def _datetime(nanos: int) -> datetime | None:
    if not nanos:
        return None
    try:
        return datetime.fromtimestamp(nanos / 1_000_000_000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise OTLPDecodeError("invalid OTLP timestamp") from exc


def _event_attributes(span: trace_pb2.Span, settings: OTLPSettings) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if len(span.events) > settings.max_events:
        raise OTLPDecodeError("OTLP event count limit exceeded", limit=True)
    if len(span.links) > settings.max_links:
        raise OTLPDecodeError("OTLP link count limit exceeded", limit=True)
    events: list[dict[str, Any]] = []
    for event in span.events:
        events.append({"name": event.name[:settings.max_attribute_value_length],
                       "time_unix_nano": int(event.time_unix_nano),
                       "attributes": _attributes(event.attributes, settings)})
    links: list[dict[str, Any]] = []
    for link in span.links:
        links.append({"trace_id": _id(link.trace_id, 16, "link trace_id"),
                      "span_id": _id(link.span_id, 8, "link span_id"),
                      "attributes": _attributes(link.attributes, settings)})
    if events:
        result["otel.events"] = events
    if links:
        result["otel.links"] = links
    return result


def _resource_attributes(resource: Any, settings: OTLPSettings) -> dict[str, Any]:
    values = _attributes(resource.attributes, settings)
    return {f"otel.resource.{key}": value for key, value in values.items()}


def _scope_attributes(scope: Any, settings: OTLPSettings) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if scope.name:
        result["otel.scope.name"] = scope.name[:settings.max_attribute_value_length]
    if scope.version:
        result["otel.scope.version"] = scope.version[:settings.max_attribute_value_length]
    return result


def decode_request(body: bytes, *, content_encoding: str | None, settings: OTLPSettings) -> list[Event]:
    payload = decompress_body(body, content_encoding, settings)
    request = trace_service_pb2.ExportTraceServiceRequest()
    try:
        request.ParseFromString(payload)
    except Exception as exc:
        raise OTLPDecodeError("malformed OTLP protobuf") from exc
    if len(request.resource_spans) > settings.max_resource_spans:
        raise OTLPDecodeError("OTLP ResourceSpans limit exceeded", limit=True)

    events: list[Event] = []
    seen_spans: set[tuple[str, str]] = set()
    seen_traces: set[str] = set()
    total_scope_spans = 0
    total_spans = 0
    for resource_spans in request.resource_spans:
        resource_attrs = _resource_attributes(resource_spans.resource, settings)
        if len(resource_spans.scope_spans) > settings.max_scope_spans:
            raise OTLPDecodeError("OTLP ScopeSpans limit exceeded", limit=True)
        total_scope_spans += len(resource_spans.scope_spans)
        if total_scope_spans > settings.max_scope_spans:
            raise OTLPDecodeError("OTLP ScopeSpans limit exceeded", limit=True)
        for scope_spans in resource_spans.scope_spans:
            scope_attrs = _scope_attributes(scope_spans.scope, settings)
            if len(scope_spans.spans) > settings.max_spans:
                raise OTLPDecodeError("OTLP span limit exceeded", limit=True)
            total_spans += len(scope_spans.spans)
            if total_spans > settings.max_spans:
                raise OTLPDecodeError("OTLP span limit exceeded", limit=True)
            for span in scope_spans.spans:
                trace_id = _id(span.trace_id, 16, "trace_id")
                span_id = _id(span.span_id, 8, "span_id")
                key = (trace_id, span_id)
                if key in seen_spans:
                    raise OTLPDecodeError("duplicate OTLP span identity")
                seen_spans.add(key)
                if span.parent_span_id:
                    _id(span.parent_span_id, 8, "parent_span_id")
                attrs = _attributes(span.attributes, settings)
                attrs.update(resource_attrs)
                attrs.update(scope_attrs)
                attrs.update(_event_attributes(span, settings))
                normalized = normalize_otel_span(
                    _ReadableSpan(span, attrs), capture_content=False,
                    max_attributes=settings.max_attributes,
                    max_attribute_key_length=settings.max_attribute_key_length,
                    max_attribute_value_length=settings.max_attribute_value_length,
                    max_metadata_bytes=settings.max_metadata_bytes,
                )
                # Keep the existing replay/analysis event vocabulary available
                # when an OTLP producer uses the corresponding observational
                # attributes. These fields remain telemetry, never policy.
                tool_name = attrs.get("tool.name") or attrs.get("gen_ai.tool.name")
                if isinstance(tool_name, str) and tool_name:
                    normalized["tool_name"] = tool_name[:settings.max_attribute_value_length]
                if "arguments" in attrs:
                    normalized["arguments"] = attrs["arguments"]
                if "result" in attrs:
                    normalized["result"] = attrs["result"]
                if trace_id not in seen_traces:
                    seen_traces.add(trace_id)
                    events.append(Event(
                        event_type="trace.started", event_id=f"otlp-trace-{trace_id}",
                        # A trace may arrive in multiple OTLP requests.  The
                        # synthetic event ID is trace-scoped, so binding its
                        # digest to whichever span happens to be first in
                        # this request would turn a valid retransmission into
                        # an idempotency conflict.  Trace timing remains in
                        # the span projections; this marker is deliberately
                        # timestamp-free and therefore stable across requests.
                        occurred_at=None,
                        data={"trace_id": trace_id, "status": "running", "schema_version": "0.1"},
                    ))
                started_id = f"otlp-span-{trace_id}-{span_id}-started"
                ended_id = f"otlp-span-{trace_id}-{span_id}-ended"
                events.append(Event(event_type="span.started", event_id=started_id,
                                    occurred_at=_datetime(span.start_time_unix_nano), data=normalized))
                events.append(Event(event_type="span.ended", event_id=ended_id,
                                    occurred_at=_datetime(span.end_time_unix_nano), data=normalized))
    if not events:
        raise OTLPDecodeError("OTLP request contains no spans")
    return events


def success_response() -> bytes:
    return trace_service_pb2.ExportTraceServiceResponse().SerializeToString()
