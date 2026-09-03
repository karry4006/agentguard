from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


EVENT_TYPES = {"trace.started", "trace.ended", "span.started", "span.ended"}
MAX_DATA_DEPTH = 20
MAX_DATA_BYTES = 64 * 1024
MAX_STRING_LENGTH = 16 * 1024
FIELD_LIMITS = {"trace_id": 255, "span_id": 255, "parent_span_id": 255, "workflow_name": 255, "group_id": 255, "provider": 100, "name": 255, "status": 32, "span_type": 32, "error_type": 255, "schema_version": 32}


def _validate_data(value: Any, depth: int = 0) -> Any:
    if depth > MAX_DATA_DEPTH:
        raise ValueError(f"event data nesting exceeds {MAX_DATA_DEPTH} levels")
    if isinstance(value, dict):
        if len(value) > 256:
            raise ValueError("event data has too many fields")
        for key, item in value.items():
            if len(str(key)) > 256:
                raise ValueError("event data key is too long")
            if str(key) in FIELD_LIMITS:
                if item is not None and not isinstance(item, str):
                    raise ValueError(f"event data field {key} must be a string")
                if isinstance(item, str) and len(item) > FIELD_LIMITS[str(key)]:
                    raise ValueError(f"event data field {key} is too long")
            _validate_data(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 1000:
            raise ValueError("event data list is too large")
        for item in value:
            _validate_data(item, depth + 1)
    elif isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
        raise ValueError("event data string is too long")
    return value


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_type: str
    event_id: str = Field(min_length=1, max_length=255)
    occurred_at: datetime | None = None
    schema_version: str = "0.1"
    data: dict[str, Any]

    @field_validator("data")
    @classmethod
    def bounded_data(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_data(value)
        if len(str(value).encode("utf-8")) > MAX_DATA_BYTES:
            raise ValueError(f"event data exceeds {MAX_DATA_BYTES} bytes")
        return value

    @field_validator("event_type")
    @classmethod
    def supported_event_type(cls, value: str) -> str:
        if value not in EVENT_TYPES:
            raise ValueError(f"unsupported event_type: {value}")
        return value


class IngestEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "0.1"
    events: list[Event] = Field(min_length=1, max_length=1000)


class IngestResponse(BaseModel):
    accepted: int
    duplicates: int


class SpanResponse(BaseModel):
    span_id: str
    trace_id: str
    parent_span_id: str | None
    span_type: str
    name: str
    started_at: datetime | None
    ended_at: datetime | None
    duration_ms: float | None
    status: str
    error_type: str | None
    error_message: str | None
    attributes: dict[str, Any]
    schema_version: str


class TraceResponse(BaseModel):
    trace_id: str
    workflow_name: str | None
    group_id: str | None
    provider: str | None
    started_at: datetime | None
    ended_at: datetime | None
    status: str
    metadata: dict[str, Any]
    schema_version: str


class TraceDetailResponse(BaseModel):
    trace: TraceResponse
    spans: list[SpanResponse]
    span_tree: list[dict[str, Any]]


class TraceListResponse(BaseModel):
    traces: list[TraceResponse]
    total: int


class IntegrityResponse(BaseModel):
    trace_id: str
    status: str
    events_checked: int
    chain_valid: bool
    projection_consistent: bool
    first_failure: str | None = None


class ReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["dry_run"] = "dry_run"


class ReplayStepResponse(BaseModel):
    sequence: int
    source_event_id: str
    source_span_id: str | None
    step_type: str
    tool_name: str | None
    classification: str
    decision: str
    recorded_input_digest: str | None
    simulated_input_digest: str | None
    recorded_output_digest: str | None
    simulated_output_digest: str | None
    comparison_status: str
    reason: str | None


class ReplayResponse(BaseModel):
    id: str
    tenant_id: str
    source_trace_id: str
    mode: str
    status: str
    integrity_status: str
    policy_version: str
    failure_reason: str | None = None
    steps: list[ReplayStepResponse] = Field(default_factory=list)


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["deterministic", "ai_assisted"] = "deterministic"


class AnalysisFindingResponse(BaseModel):
    detector_id: str
    category: str
    root_cause_span_id: str | None
    symptom_span_id: str | None
    severity: str
    model_confidence: float
    source: str
    reason: str
    recommended_next_step: str | None
    evidence_span_ids: list[str]
    evidence_event_ids: list[str]
    replay_ids: list[str]
    primary_hypothesis: bool


class AnalysisResponse(BaseModel):
    id: str
    tenant_id: str
    trace_id: str
    status: str
    taxonomy_version: str
    analysis_version: str
    provider: str | None
    model: str | None
    policy_version: str
    deterministic_status: str
    ai_status: str
    failure_reason: str | None = None
    findings: list[AnalysisFindingResponse] = Field(default_factory=list)


class EvaluationSuiteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=64)
    configuration: dict[str, Any] = Field(default_factory=dict)


class EvaluationSuiteResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    name: str
    version: str
    created_at: datetime
    configuration: dict[str, Any]


class EvaluationCaseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str = Field(min_length=1, max_length=255)
    trace_id: str = Field(min_length=1, max_length=255)


class EvaluationRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID
    variant: Literal["baseline", "candidate"]
    agent_version: str = Field(min_length=1, max_length=128)
    prompt_version: str | None = Field(default=None, max_length=128)
    model: str | None = Field(default=None, max_length=128)
    environment: dict[str, Any] = Field(default_factory=dict)
    cases: list[EvaluationCaseCreate] = Field(min_length=1, max_length=1000)


class EvaluationCaseResponse(BaseModel):
    case_id: str
    trace_id: str
    status: str
    integrity_status: str
    metrics: dict[str, Any]


class EvaluationRunResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    suite_id: UUID
    variant: str
    agent_version: str
    prompt_version: str | None
    model: str | None
    environment: dict[str, Any]
    status: str
    created_at: datetime
    completed_at: datetime | None
    cases: list[EvaluationCaseResponse]


class EvaluationComparisonCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite_id: UUID
    baseline_run_id: UUID
    candidate_run_id: UUID


class EvaluationComparisonResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    suite_id: UUID
    baseline_run_id: UUID
    candidate_run_id: UUID
    status: str
    metrics: dict[str, Any]
    reasons: list[dict[str, Any]]
    case_diffs: list[dict[str, Any]]
    rule_results: list[dict[str, Any]]
    decision: str
    created_at: datetime
