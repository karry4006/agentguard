from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any
from uuid import uuid4

from .config import AgentGuardConfig
from .exporter import HttpBatchExporter
from .redaction import redact
from .schemas import SCHEMA_VERSION, SpanType, iso, utc_now

logger = logging.getLogger("agentguard.processor")

try:
    from agents.tracing import TracingProcessor as _OpenAITracingProcessor
except ImportError:  # optional dependency; the SDK remains usable standalone
    class _OpenAITracingProcessor:
        pass


def _get(value: Any, *names: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        for name in names:
            if name in value:
                return value[name]
    else:
        for name in names:
            if hasattr(value, name):
                return getattr(value, name)
    return default


def _text(value: Any, default: str | None = None) -> str | None:
    if value is None:
        return default
    return str(value)


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "__dict__"):
        return {key: item for key, item in vars(value).items() if not key.startswith("_")}
    return {}


def _time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


_SPAN_TYPES = {
    "agent": SpanType.AGENT,
    "llm": SpanType.LLM,
    "generation": SpanType.LLM,
    "model": SpanType.LLM,
    "tool": SpanType.TOOL,
    "function": SpanType.TOOL,
    "guardrail": SpanType.GUARDRAIL,
    "handoff": SpanType.HANDOFF,
    "custom": SpanType.CUSTOM,
}


class AgentGuardTracingProcessor(_OpenAITracingProcessor):
    """OpenAI Agents tracing processor backed by a non-blocking exporter."""

    def __init__(self, config: AgentGuardConfig | None = None, exporter: HttpBatchExporter | None = None):
        self.config = config or AgentGuardConfig.from_env()
        self.exporter = exporter or HttpBatchExporter(self.config)
        self._traces: dict[str, dict[str, Any]] = {}
        self._spans: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def on_trace_start(self, trace: Any) -> None:
        trace_id = _text(_get(trace, "trace_id", "id"), str(uuid4()))
        started = _time(_get(trace, "started_at", "start_time")) or utc_now()
        data = {
            "trace_id": trace_id,
            "workflow_name": _text(_get(trace, "workflow_name", "name"), "agent-run"),
            "group_id": _text(_get(trace, "group_id")),
            "provider": _text(_get(trace, "provider"), "openai"),
            "started_at": iso(started),
            "ended_at": None,
            "status": "running",
            "metadata": redact(_get(trace, "metadata", default={}) or {}, capture_content=self.config.capture_content),
            "schema_version": SCHEMA_VERSION,
        }
        with self._lock:
            self._traces[trace_id] = data
        self._emit("trace.started", trace_id, data)

    def on_trace_end(self, trace: Any) -> None:
        trace_id = _text(_get(trace, "trace_id", "id"), "unknown")
        with self._lock:
            data = dict(self._traces.get(trace_id, {"trace_id": trace_id}))
        data.update({
            "ended_at": iso(_time(_get(trace, "ended_at", "end_time")) or utc_now()),
            "status": _text(_get(trace, "status"), "error" if _get(trace, "error") else "success"),
        })
        if _get(trace, "error"):
            data["metadata"] = redact({**data.get("metadata", {}), "error": _get(trace, "error")}, capture_content=self.config.capture_content)
        with self._lock:
            self._traces[trace_id] = data
        self._emit("trace.ended", trace_id, data)

    def on_span_start(self, span: Any) -> None:
        data = self._normalize_span(span)
        with self._lock:
            self._spans[data["span_id"]] = data
        self._emit("span.started", data["span_id"], data)

    def on_span_end(self, span: Any) -> None:
        data = self._normalize_span(span)
        with self._lock:
            previous = dict(self._spans.get(data["span_id"], {}))
            previous.update(data)
        if previous.get("started_at") and previous.get("ended_at"):
            start = _time(previous["started_at"])
            end = _time(previous["ended_at"])
            if start and end:
                previous["duration_ms"] = max(0.0, (end - start).total_seconds() * 1000)
        with self._lock:
            self._spans[data["span_id"]] = previous
        self._emit("span.ended", data["span_id"], previous)

    def shutdown(self) -> None:
        self.exporter.shutdown()

    def force_flush(self) -> bool:
        return self.exporter.force_flush()

    def diagnostics(self) -> dict[str, Any]:
        return self.exporter.diagnostics()

    def _normalize_span(self, span: Any) -> dict[str, Any]:
        span_id = _text(_get(span, "span_id", "id"), str(uuid4()))
        span_data = _get(span, "span_data", "data")
        raw_type = _text(_get(span, "span_type", "type", "kind"), None)
        raw_type = raw_type or _text(_get(span_data, "type"), "unknown") or "unknown"
        normalized = _SPAN_TYPES.get(raw_type.lower(), SpanType.UNKNOWN)
        attrs = _mapping(_get(span, "attributes", "details", default={}) or {})
        if not attrs and span_data is not None:
            attrs = _mapping(span_data)
        if normalized == SpanType.UNKNOWN:
            attrs.setdefault("provider_span_type", raw_type)
        error = _get(span, "error")
        error_type = _text(_get(span, "error_type")) or (_text(_get(error, "type", "__class__")) if error else None)
        error_message = _text(_get(span, "error_message", "message")) or (_text(error) if error else None)
        return {
            "span_id": span_id,
            "trace_id": _text(_get(span, "trace_id"), "unknown"),
            "parent_span_id": _text(_get(span, "parent_span_id", "parent_id")),
            "span_type": normalized.value,
            "name": _text(_get(span, "name"), None) or _text(_get(span_data, "name"), "unknown"),
            "started_at": iso(_time(_get(span, "started_at", "start_time")) or utc_now()),
            "ended_at": iso(_time(_get(span, "ended_at", "end_time"))),
            "duration_ms": _get(span, "duration_ms"),
            "status": _text(_get(span, "status"), "error" if error else "running"),
            "error_type": error_type,
            "error_message": redact(error_message, capture_content=self.config.capture_content) if error_message else None,
            "attributes": redact(attrs, capture_content=self.config.capture_content),
            "schema_version": SCHEMA_VERSION,
        }

    def _emit(self, event_type: str, event_id: str, data: dict[str, Any]) -> None:
        self.exporter.submit({
            "event_type": event_type,
            "event_id": event_id,
            "occurred_at": iso(utc_now()),
            "schema_version": SCHEMA_VERSION,
            "data": redact(data, capture_content=self.config.capture_content),
        })
