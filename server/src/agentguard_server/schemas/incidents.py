from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class IncidentOccurrenceResponse(BaseModel):
    id: UUID
    trace_id: str
    analysis_id: UUID
    failure_category: str
    root_cause_span_id: str | None
    symptom_span_id: str | None
    observed_at: datetime
    agent_name: str | None
    workflow_name: str | None
    agent_version: str | None
    provider: str | None
    model: str | None


class IncidentEventResponse(BaseModel):
    id: UUID
    event_type: str
    actor_type: str
    actor_id: str | None
    metadata: dict[str, str]
    created_at: datetime


class IncidentSummaryResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    fingerprint: str
    fingerprint_version: str
    title: str
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity_policy_version: str
    primary_category: str
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    affected_trace_count: int
    trend: Literal["INCREASING", "STABLE", "DECREASING", "INSUFFICIENT_DATA"]


class IncidentDetailResponse(IncidentSummaryResponse):
    dimensions: dict[str, str] = Field(default_factory=dict)
    occurrences: list[IncidentOccurrenceResponse] = Field(default_factory=list, max_length=100)
    history: list[IncidentEventResponse] = Field(default_factory=list, max_length=100)
    findings: list[dict[str, str | None]] = Field(default_factory=list, max_length=100)
    v8_associations: list[dict[str, str]] = Field(default_factory=list, max_length=100)
    model_config = ConfigDict(extra="forbid")
