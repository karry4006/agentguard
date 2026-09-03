"""OpenTelemetry GenAI bridge for the existing AgentGuard event pipeline.

This module is deliberately a deep adapter: callers provide an OpenTelemetry
``ReadableSpan`` and receive the same normalized events used by the native
AgentGuard tracing processor.  It never assigns tenant identity, authorization,
or policy from telemetry.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import threading
from typing import Any, Mapping

from opentelemetry.sdk.trace import SpanProcessor

from .config import AgentGuardConfig
from .diagnostics import Diagnostics
from .exporter import HttpBatchExporter
from .redaction import redact
from .schemas import SCHEMA_VERSION, SpanType, iso, utc_now


logger = logging.getLogger("agentguard.opentelemetry")

OTEL_SEMCONV_VERSION = "otel-genai-evolving"
AGENTGUARD_MAPPING_VERSION = "otel-genai-v1"

_OPERATION_TYPES = {
    "invoke_agent": SpanType.AGENT,
    "invoke_workflow": SpanType.AGENT,
    "plan": SpanType.AGENT,
    "execute_tool": SpanType.TOOL,
    "chat": SpanType.LLM,
    "generate_content": SpanType.LLM,
    "text_completion": SpanType.LLM,
    "retrieval": SpanType.CUSTOM,
}
_MCP_OPERATION_KEYS = {"mcp.method.name", "mcp.tool.name", "mcp.tool_call.name"}


def _text(value: Any, default: str | None = None, *, limit: int = 255) -> str | None:
    if value is None:
        return default
    return str(value)[:limit]


def _context(span: Any) -> Any:
    getter = getattr(span, "get_span_context", None)
    if callable(getter):
        return getter()
    return getattr(span, "context", None)


def _valid_context(context: Any) -> bool:
    value = getattr(context, "is_valid", False)
    return bool(value() if callable(value) else value)


def _stable_id(value: Any, width: int, fallback: str) -> str:
    if isinstance(value, int) and value > 0:
        return f"{value:0{width}x}"[-width:]
    if isinstance(value, str) and value:
        return value[:255]
    return fallback


def _parent_id(span: Any) -> str | None:
    parent = getattr(span, "parent", None)
    if parent is None:
        return None
    parent_id = getattr(parent, "span_id", None)
    if not parent_id:
        return None
    return _stable_id(parent_id, 16, "") or None


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, int) and value > 0:
        try:
            return datetime.fromtimestamp(value / 1_000_000_000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    return None


def _json_safe(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "[TRUNCATED]"
    if isinstance(value, Mapping):
        return {str(key)[:128]: _json_safe(item, depth + 1) for key, item in list(value.items())[:50]}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item, depth + 1) for item in list(value)[:50]]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value if not isinstance(value, str) else value[:2048]
    return str(value)[:2048]


def _bounded_attributes(raw: Mapping[Any, Any], *, operation: str | None, provider: str,
                        max_attributes: int, max_attribute_key_length: int,
                        max_attribute_value_length: int, max_metadata_bytes: int) -> dict[str, Any]:
    """Redact and bound untrusted OTel attributes deterministically."""
    candidates: list[tuple[str, Any]] = []
    for key, value in raw.items():
        key_text = str(key)[:max_attribute_key_length]
        if key_text.lower() == "tenant_id":
            continue
        candidates.append((key_text, _json_safe(redact(value))))

    priority = {"gen_ai.operation.name", "gen_ai.provider.name", "error.type"} | _MCP_OPERATION_KEYS
    candidates.sort(key=lambda item: (item[0] not in priority, item[0]))
    result: dict[str, Any] = {
        "agentguard_mapping_version": AGENTGUARD_MAPPING_VERSION,
        "otel_semconv_version": OTEL_SEMCONV_VERSION,
    }
    for key, value in candidates:
        if key in result or len(result) >= max(0, max_attributes):
            continue
        if isinstance(value, str):
            value = value[:max_attribute_value_length]
        encoded = dict(result)
        encoded[key] = value
        if len(json.dumps(encoded, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")) > max_metadata_bytes:
            continue
        result[key] = value
    if operation and operation not in _OPERATION_TYPES and len(result) < max(0, max_attributes):
        result.setdefault("otel.operation.name", operation[:max_attribute_value_length])
    if provider and provider != "unknown" and "gen_ai.provider.name" not in result and len(result) < max(0, max_attributes):
        result["gen_ai.provider.name"] = provider[:max_attribute_value_length]
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
    if len(encoded) > max_metadata_bytes:
        return {"agentguard_mapping_version": AGENTGUARD_MAPPING_VERSION}
    return result


def normalize_otel_span(span: Any, *, capture_content: bool = False,
                        max_attributes: int = 64, max_attribute_key_length: int = 128,
                        max_attribute_value_length: int = 2048,
                        max_metadata_bytes: int = 16 * 1024) -> dict[str, Any]:
    """Normalize one public OpenTelemetry span without side effects."""
    context = _context(span)
    if not _valid_context(context):
        raise ValueError("OpenTelemetry span has no valid context")
    trace_id = _stable_id(getattr(context, "trace_id", None), 32, "unknown")
    span_id = _stable_id(getattr(context, "span_id", None), 16, "unknown")
    raw_attributes = getattr(span, "attributes", {}) or {}
    attrs = dict(raw_attributes) if isinstance(raw_attributes, Mapping) else {}
    operation = _text(attrs.get("gen_ai.operation.name"), limit=128)
    provider = _text(attrs.get("gen_ai.provider.name"), "unknown", limit=100) or "unknown"
    operation_key = operation.lower() if operation else None
    normalized_type = _OPERATION_TYPES.get(operation_key or "")
    if normalized_type is None and any(key in attrs for key in _MCP_OPERATION_KEYS):
        normalized_type = SpanType.TOOL
    normalized_type = normalized_type or SpanType.UNKNOWN
    started = _timestamp(getattr(span, "start_time", None)) or utc_now()
    ended = _timestamp(getattr(span, "end_time", None))
    error_type = _text(attrs.get("error.type"), limit=255)
    status_obj = getattr(span, "status", None)
    status_code = getattr(status_obj, "status_code", None)
    status_name = str(getattr(status_code, "name", status_code or "")).lower()
    if error_type and "timeout" in error_type.lower():
        status = "timeout"
    else:
        status = "error" if status_name == "error" or "error.type" in attrs else ("success" if ended else "running")
    duration_ms = None
    if ended:
        duration_ms = max(0.0, (ended - started).total_seconds() * 1000)
    if normalized_type == SpanType.UNKNOWN and operation:
        attrs.setdefault("otel.operation.name", operation)
    normalized_attributes = _bounded_attributes(
        attrs, operation=operation, provider=provider, max_attributes=max_attributes,
        max_attribute_key_length=max_attribute_key_length,
        max_attribute_value_length=max_attribute_value_length,
        max_metadata_bytes=max_metadata_bytes,
    )
    name = redact(_text(getattr(span, "name", None), "unknown") or "unknown", capture_content=capture_content)
    data = {
        "span_id": span_id,
        "trace_id": trace_id,
        "parent_span_id": _parent_id(span),
        "span_type": normalized_type.value,
        "name": name,
        "started_at": iso(started),
        "ended_at": iso(ended),
        "duration_ms": duration_ms,
        "status": status,
        "error_type": error_type,
        "error_message": None,
        "provider": provider,
        "attributes": redact(normalized_attributes, capture_content=capture_content),
        "schema_version": SCHEMA_VERSION,
    }
    # The existing ingestion contract treats bounded string fields as
    # string-only when present.  Omit absent optional values instead of
    # serializing JSON nulls into the event envelope.
    for optional in ("parent_span_id", "error_type", "ended_at"):
        if data.get(optional) is None:
            data.pop(optional, None)
    return data


class AgentGuardOpenTelemetrySpanProcessor(SpanProcessor):
    """Thread-safe OTel adapter that reuses AgentGuard's durable exporter."""

    def __init__(self, config: AgentGuardConfig | None = None, exporter: Any | None = None,
                 *, max_attributes: int = 64, max_attribute_key_length: int = 128,
                 max_attribute_value_length: int = 2048,
                 max_metadata_bytes: int = 16 * 1024):
        self.config = config or AgentGuardConfig.from_env()
        self.exporter = exporter or HttpBatchExporter(self.config)
        self.max_attributes = max_attributes
        self.max_attribute_key_length = max_attribute_key_length
        self.max_attribute_value_length = max_attribute_value_length
        self.max_metadata_bytes = max_metadata_bytes
        self._lock = threading.RLock()
        self._traces: set[str] = set()
        self._spans: dict[tuple[str, str], dict[str, Any]] = {}
        self._ended: set[tuple[str, str]] = set()
        self._diagnostics = Diagnostics()
        self._shutdown = False

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        try:
            data = self._normalize(span)
            key = (data["trace_id"], data["span_id"])
            with self._lock:
                first_trace = data["trace_id"] not in self._traces and data.get("parent_span_id") is None
                self._traces.add(data["trace_id"])
                self._spans[key] = data
            if first_trace:
                self._emit("trace.started", data["trace_id"], {
                    "trace_id": data["trace_id"], "workflow_name": data["name"],
                    "provider": data["provider"], "started_at": data["started_at"],
                    "ended_at": None, "status": "running", "metadata": {
                        "agentguard_mapping_version": AGENTGUARD_MAPPING_VERSION,
                        "otel_semconv_version": OTEL_SEMCONV_VERSION,
                    }, "schema_version": SCHEMA_VERSION,
                })
            self._emit("span.started", data["span_id"], data)
        except Exception as exc:  # instrumentation must fail open
            self._record_failure(exc)

    def on_end(self, span: Any) -> None:
        try:
            data = self._normalize(span)
            key = (data["trace_id"], data["span_id"])
            with self._lock:
                if key in self._ended:
                    self._diagnostics.increment("duplicate_ends")
                    return
                previous = dict(self._spans.get(key, {}))
                previous.update(data)
                self._spans[key] = previous
                self._ended.add(key)
                trace_started = data["trace_id"] in self._traces
            self._emit("span.ended", data["span_id"], previous)
            if trace_started and data.get("parent_span_id") is None:
                self._emit("trace.ended", data["trace_id"], {
                    "trace_id": data["trace_id"], "ended_at": data["ended_at"] or iso(utc_now()),
                    "status": data["status"], "schema_version": SCHEMA_VERSION,
                })
        except Exception as exc:  # instrumentation must fail open
            self._record_failure(exc)

    def shutdown(self) -> None:
        with self._lock:
            if self._shutdown:
                return
            self._shutdown = True
        try:
            self.exporter.shutdown()
        except Exception as exc:
            self._record_failure(exc)

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        try:
            return bool(self.exporter.force_flush(max(0.0, timeout_millis / 1000)))
        except Exception as exc:
            self._record_failure(exc)
            return False

    def diagnostics(self) -> dict[str, Any]:
        try:
            result = dict(self.exporter.diagnostics())
        except Exception:
            result = {}
        own = self._diagnostics.snapshot()
        for key, value in own.items():
            if key == "last_exporter_error":
                if value:
                    result[key] = value
            elif isinstance(value, int):
                result[key] = int(result.get(key, 0)) + value
            else:
                result[key] = value
        return result

    def _normalize(self, span: Any) -> dict[str, Any]:
        return normalize_otel_span(
            span, capture_content=self.config.capture_content,
            max_attributes=self.max_attributes,
            max_attribute_key_length=self.max_attribute_key_length,
            max_attribute_value_length=self.max_attribute_value_length,
            max_metadata_bytes=self.max_metadata_bytes,
        )

    def _emit(self, event_type: str, event_id: str, data: dict[str, Any]) -> None:
        event = {"event_type": event_type, "event_id": event_id, "occurred_at": iso(utc_now()),
                 "schema_version": SCHEMA_VERSION, "data": redact(data, capture_content=self.config.capture_content)}
        try:
            if not self.exporter.submit(event):
                self._diagnostics.increment("export_rejections")
        except Exception as exc:
            self._record_failure(exc)

    def _record_failure(self, exc: Exception) -> None:
        safe = redact(str(exc), capture_content=False)
        self._diagnostics.error(str(safe)[:512])
        logger.warning("AgentGuard OpenTelemetry instrumentation failure: %s", safe)
