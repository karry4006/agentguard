from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


SCHEMA_VERSION = "0.1"


class SpanType(StrEnum):
    AGENT = "agent"
    LLM = "llm"
    TOOL = "tool"
    GUARDRAIL = "guardrail"
    HANDOFF = "handoff"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class Trace(BaseModel):
    model_config = ConfigDict(extra="allow")
    trace_id: str
    workflow_name: str | None = None
    group_id: str | None = None
    provider: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    status: str = "running"
    metadata: dict[str, Any] = Field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION


class Span(BaseModel):
    model_config = ConfigDict(extra="allow")
    span_id: str
    trace_id: str
    parent_span_id: str | None = None
    span_type: SpanType = SpanType.UNKNOWN
    name: str = "unknown"
    started_at: datetime | None = None
    ended_at: datetime | None = None
    duration_ms: float | None = None
    status: str = "running"
    error_type: str | None = None
    error_message: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None

