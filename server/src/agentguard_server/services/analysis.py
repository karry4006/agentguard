"""Evidence-grounded, deterministic-first failure analysis.

The public seam in this module accepts structured evidence and returns bounded
findings.  It deliberately has no command, tool, filesystem, or database
mutation adapter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from datetime import datetime, timezone
from contextlib import contextmanager
import json
from threading import Lock
import time
from typing import Any, Iterable, Protocol
from uuid import UUID
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentguard_server.config import Settings, get_settings
from agentguard_server.models import AnalysisFinding, AnalysisRun, EventLog, ReplaySession, ReplayStep, Span
from agentguard_server.services.integrity import verify_trace_integrity


logger = logging.getLogger("agentguard.security")


_analysis_slot_lock = Lock()
_active_analyses = 0


TAXONOMY_VERSION = "v1"
ANALYSIS_VERSION = "v1"


class FailureCategory(StrEnum):
    MODEL_REASONING = "MODEL_REASONING"
    TOOL_SELECTION = "TOOL_SELECTION"
    TOOL_EXECUTION = "TOOL_EXECUTION"
    TOOL_RESULT_INTERPRETATION = "TOOL_RESULT_INTERPRETATION"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    RATE_LIMIT = "RATE_LIMIT"
    TIMEOUT = "TIMEOUT"
    INVALID_INPUT = "INVALID_INPUT"
    INCOMPLETE_EXPLORATION = "INCOMPLETE_EXPLORATION"
    LOOP_OR_REPETITION = "LOOP_OR_REPETITION"
    HANDOFF_FAILURE = "HANDOFF_FAILURE"
    GUARDRAIL_FAILURE = "GUARDRAIL_FAILURE"
    ENVIRONMENT_DRIFT = "ENVIRONMENT_DRIFT"
    DATA_QUALITY = "DATA_QUALITY"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    PROJECTION_MISMATCH = "PROJECTION_MISMATCH"
    EVIDENCE_INTEGRITY = "EVIDENCE_INTEGRITY"
    UNKNOWN = "UNKNOWN"


class FindingSource(StrEnum):
    DETERMINISTIC = "DETERMINISTIC"
    AI = "AI"
    HYBRID = "HYBRID"


class FindingSeverity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class DetectorFinding:
    detector_id: str
    category: FailureCategory
    span_id: str | None
    event_ids: tuple[str, ...]
    severity: FindingSeverity
    confidence: float
    evidence_summary: str
    root_cause_span_id: str | None = None
    symptom_span_id: str | None = None
    source: FindingSource = FindingSource.DETERMINISTIC
    replay_ids: tuple[str, ...] = ()


class FailureJudge(Protocol):
    """Provider-neutral structured inference adapter; it has no tools."""

    def analyze(self, evidence_packet: dict[str, Any]) -> Any:
        ...


class AnalysisRefused(ValueError):
    def __init__(self, reason: str, integrity_status: str):
        super().__init__(reason)
        self.reason = reason
        self.integrity_status = integrity_status


class AnalysisResourceLimit(ValueError):
    pass


@dataclass(frozen=True)
class AnalysisReport:
    trace_id: str
    findings: tuple[DetectorFinding, ...]
    deterministic_status: str
    ai_status: str
    provider: str | None = None
    model: str | None = None
    model_calls: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None
    latency_ms: float | None = None
    failure_reason: str | None = None
    taxonomy_version: str = TAXONOMY_VERSION
    analysis_version: str = ANALYSIS_VERSION
    policy_version: str = "v1"


def _value(span: Any, name: str, default: Any = None) -> Any:
    return getattr(span, name, default)


def _attributes(span: Any) -> dict[str, Any]:
    value = _value(span, "attributes", {})
    return value if isinstance(value, dict) else {}


def _status_code(span: Any) -> int | None:
    attrs = _attributes(span)
    for key in ("status_code", "http_status", "status_code_int"):
        value = attrs.get(key)
        try:
            if value is not None:
                return int(value)
        except (TypeError, ValueError):
            return None
    return None


def _finding(detector: str, category: FailureCategory, span: Any, summary: str, *, severity=FindingSeverity.MEDIUM,
             confidence: float = 1.0, root: str | None = None, symptom: str | None = None,
             event_ids: Iterable[str] = ()) -> DetectorFinding:
    span_id = str(_value(span, "span_id")) if _value(span, "span_id") is not None else None
    return DetectorFinding(detector, category, span_id, tuple(str(item) for item in event_ids), severity,
                           confidence, summary, root or span_id, symptom or span_id)


def detect_findings(spans: Iterable[Any], *, loop_threshold: int = 3, max_tool_spans: int = 100) -> list[DetectorFinding]:
    """Apply structured rules; natural-language fields never select categories."""
    ordered = list(spans)
    findings: list[DetectorFinding] = []
    tools = [item for item in ordered if str(_value(item, "span_type", "")).lower() in {"tool", "function", "plugin", "mcp"}]
    for item in ordered:
        span_id = str(_value(item, "span_id", ""))
        status = str(_value(item, "status", "")).lower()
        error_type = str(_value(item, "error_type", "")).lower()
        code = _status_code(item)
        if code == 401:
            findings.append(_finding("http_authentication", FailureCategory.AUTHENTICATION, item, "structured status code 401", severity=FindingSeverity.HIGH))
        elif code == 403:
            findings.append(_finding("http_authorization", FailureCategory.AUTHORIZATION, item, "structured status code 403", severity=FindingSeverity.HIGH))
        elif code == 429:
            findings.append(_finding("http_rate_limit", FailureCategory.RATE_LIMIT, item, "structured status code 429"))
        if "timeout" in error_type or "timeout" in status:
            findings.append(_finding("timeout", FailureCategory.TIMEOUT, item, "structured timeout status", severity=FindingSeverity.HIGH))
        elif status in {"error", "failed", "failure"}:
            category = FailureCategory.TOOL_EXECUTION if str(_value(item, "span_type", "")).lower() in {"tool", "function", "plugin", "mcp"} else FailureCategory.DEPENDENCY_FAILURE
            findings.append(_finding("explicit_error", category, item, "span status is error"))
        attrs = _attributes(item)
        if attrs.get("guardrail_failed") is True or attrs.get("guardrail_status") in {"rejected", "failed"}:
            findings.append(_finding("guardrail", FailureCategory.GUARDRAIL_FAILURE, item, "structured guardrail rejection", severity=FindingSeverity.HIGH))
        if str(_value(item, "span_type", "")).lower() == "handoff" and not any(_value(child, "parent_span_id") == span_id for child in ordered):
            findings.append(_finding("handoff", FailureCategory.HANDOFF_FAILURE, item, "handoff has no downstream child"))
        if attrs.get("invalid_input") is True:
            findings.append(_finding("input_validation", FailureCategory.INVALID_INPUT, item, "structured invalid input marker"))
        if attrs.get("wrong_tool") is True:
            findings.append(_finding("tool_selection", FailureCategory.TOOL_SELECTION, item, "structured wrong-tool marker", confidence=1.0))
    groups: dict[tuple[str, str], list[Any]] = {}
    for item in tools:
        groups.setdefault((str(_value(item, "span_type", "")), str(_value(item, "name", ""))), []).append(item)
    for key, group in groups.items():
        if len(group) >= loop_threshold:
            findings.append(_finding("repetition", FailureCategory.LOOP_OR_REPETITION, group[-1],
                                    f"repeated structured tool pattern {key[1]}", confidence=0.95,
                                    root=str(_value(group[0], "span_id")), symptom=str(_value(group[-1], "span_id"))))
    if len(tools) > max_tool_spans:
        findings.append(_finding("tool_budget", FailureCategory.ENVIRONMENT_DRIFT, tools[-1], "tool span threshold exceeded", confidence=1.0,
                                root=str(_value(tools[0], "span_id")), symptom=str(_value(tools[-1], "span_id"))))
    return findings


def _safe(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key_text = str(key)
            if any(token in key_text.lower() for token in ("password", "secret", "token", "authorization", "pepper", "private_key")):
                result[key_text] = "[REDACTED]"
            else:
                result[key_text] = _safe(item, depth + 1)
        return result
    if isinstance(value, list):
        return [_safe(item, depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return value[:2048]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:2048]


def build_evidence_packet(*, spans: Iterable[Any], event_ids: Iterable[str] = (), replay_ids: Iterable[str] = (), max_bytes: int = 64 * 1024) -> dict[str, Any]:
    """Return an allowlisted, bounded packet; never raw ORM rows."""
    span_rows = []
    for item in list(spans)[:1000]:
        span_rows.append({key: _safe(_value(item, key)) for key in
                          ("span_id", "parent_span_id", "span_type", "name", "status", "error_type", "error_message", "attributes")})
    packet = {"taxonomy_version": TAXONOMY_VERSION, "span_ids": {str(row["span_id"]) for row in span_rows},
              "event_ids": {str(value) for value in event_ids}, "replay_ids": {str(value) for value in replay_ids},
              "spans": span_rows}
    encoded = str(packet).encode("utf-8")
    if len(encoded) > max_bytes:
        packet["spans"] = span_rows[: max(1, len(span_rows) // 2)]
        packet["truncated"] = True
    return packet


def validate_ai_judgment(value: Any, evidence_packet: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("AI judgment schema is invalid")
    allowed_spans = set(evidence_packet.get("span_ids", set()))
    allowed_events = set(evidence_packet.get("event_ids", set()))
    allowed_replays = set(evidence_packet.get("replay_ids", set()))
    refs = [value.get("root_cause_span_id"), value.get("symptom_span_id"), *(value.get("evidence_span_ids") or [])]
    if any(ref is not None and str(ref) not in allowed_spans for ref in refs):
        raise ValueError("AI judgment contains invalid evidence reference")
    if any(str(ref) not in allowed_events for ref in (value.get("evidence_event_ids") or [])):
        raise ValueError("AI judgment contains invalid evidence reference")
    if any(str(ref) not in allowed_replays for ref in (value.get("replay_ids") or [])):
        raise ValueError("AI judgment contains invalid evidence reference")
    try:
        category = FailureCategory(value.get("category"))
    except (TypeError, ValueError) as exc:
        raise ValueError("AI judgment category is not in taxonomy v1") from exc
    confidence = value.get("model_confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
        raise ValueError("AI judgment confidence must be between 0 and 1")
    result = dict(value)
    result["category"] = category.value
    result["taxonomy_version"] = TAXONOMY_VERSION
    return result


def _event_ids_for_span(events: list[EventLog], span_id: str | None) -> tuple[str, ...]:
    if span_id is None:
        return ()
    result: list[str] = []
    for event in events:
        payload = event.payload_json or {}
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        if isinstance(data, dict) and str(data.get("span_id", "")) == span_id:
            result.append(event.event_id)
    return tuple(result)


def _with_event_refs(finding: DetectorFinding, events: list[EventLog]) -> DetectorFinding:
    refs = finding.event_ids or _event_ids_for_span(events, finding.span_id)
    root_refs = _event_ids_for_span(events, finding.root_cause_span_id)
    return DetectorFinding(finding.detector_id, finding.category, finding.span_id, refs, finding.severity,
                           finding.confidence, finding.evidence_summary, finding.root_cause_span_id,
                           finding.symptom_span_id, finding.source, finding.replay_ids)


def _replay_findings(db: Session, tenant_id: UUID, trace_id: str) -> list[DetectorFinding]:
    rows = list(db.execute(select(ReplaySession, ReplayStep).join(
        ReplayStep, ReplayStep.replay_session_id == ReplaySession.id
    ).where(ReplaySession.tenant_id == tenant_id, ReplaySession.source_trace_id == trace_id)))
    findings: list[DetectorFinding] = []
    for session, step in rows:
        if step.comparison_status != "MISMATCH":
            continue
        findings.append(DetectorFinding(
            detector_id="replay_mismatch", category=FailureCategory.TOOL_RESULT_INTERPRETATION,
            span_id=step.source_span_id, event_ids=(step.source_event_id,), severity=FindingSeverity.MEDIUM,
            confidence=1.0, evidence_summary="V4 deterministic replay output mismatched recorded output",
            root_cause_span_id=step.source_span_id, symptom_span_id=step.source_span_id,
            source=FindingSource.DETERMINISTIC, replay_ids=(str(session.id),),
        ))
    return findings


def _analyze_trace(db: Session, tenant_id: UUID, trace_id: str, *, mode: str = "deterministic",
                   judge: FailureJudge | None = None, settings: Settings | None = None) -> tuple[AnalysisReport, dict[str, Any]]:
    """Analyze one verified trace; the only writes belong to ``persist_analysis``."""
    if mode not in {"deterministic", "ai_assisted"}:
        raise ValueError("unsupported analysis mode")
    settings = settings or get_settings()
    verification = verify_trace_integrity(db, tenant_id, trace_id, settings)
    if verification.status != "valid":
        raise AnalysisRefused("ANALYSIS_REFUSED_INTEGRITY", verification.status)
    spans = list(db.scalars(select(Span).where(Span.tenant_id == tenant_id, Span.trace_id == trace_id)
                            .order_by(Span.started_at, Span.span_id)))
    events = list(db.scalars(select(EventLog).where(EventLog.tenant_id == tenant_id, EventLog.trace_id == trace_id)
                             .order_by(EventLog.id)))
    if len(spans) > settings.analysis_max_spans or len(events) > settings.analysis_max_events:
        raise AnalysisResourceLimit("ANALYSIS_RESOURCE_LIMIT")
    findings = [_with_event_refs(item, events) for item in detect_findings(spans)]
    findings.extend(_replay_findings(db, tenant_id, trace_id))
    packet = build_evidence_packet(spans=spans, event_ids=(event.event_id for event in events),
                                   replay_ids=(str(row[0].id) for row in db.scalars(select(ReplaySession).where(
                                       ReplaySession.tenant_id == tenant_id, ReplaySession.source_trace_id == trace_id))),
                                   max_bytes=settings.analysis_max_input_bytes)
    ai_status = "not_requested"
    provider = model = None
    model_calls = 0
    failure_reason = None
    started = time.monotonic()
    if mode == "ai_assisted":
        if judge is None or not settings.analysis_enabled:
            ai_status = "unavailable"
        elif settings.analysis_max_model_calls < 1:
            ai_status = "unavailable"
            failure_reason = "ANALYSIS_RESOURCE_LIMIT"
        else:
            model_calls = 1
            provider = type(judge).__name__
            model = settings.analysis_model
            try:
                raw_judgment = judge.analyze(packet)
                if len(json.dumps(raw_judgment, default=str, separators=(",", ":")).encode("utf-8")) > settings.analysis_max_output_bytes:
                    raise AnalysisResourceLimit("ANALYSIS_RESOURCE_LIMIT")
                if (time.monotonic() - started) > settings.analysis_timeout_seconds:
                    raise TimeoutError("analysis judge timeout")
                judgment = validate_ai_judgment(raw_judgment, packet)
                evidence_spans = tuple(str(item) for item in (judgment.get("evidence_span_ids") or []))
                evidence_events = tuple(str(item) for item in (judgment.get("evidence_event_ids") or []))
                findings.append(DetectorFinding(
                    detector_id="failure_judge", category=FailureCategory(judgment["category"]),
                    span_id=judgment.get("symptom_span_id"), event_ids=evidence_events,
                    severity=FindingSeverity.MEDIUM, confidence=float(judgment["model_confidence"]),
                    evidence_summary=str(judgment.get("reason", ""))[:2048],
                    root_cause_span_id=judgment.get("root_cause_span_id"), symptom_span_id=judgment.get("symptom_span_id"),
                    source=FindingSource.AI, replay_ids=tuple(str(item) for item in (judgment.get("replay_ids") or [])),
                ))
                ai_status = "completed"
            except AnalysisResourceLimit:
                ai_status = "failed"
                failure_reason = "ANALYSIS_RESOURCE_LIMIT"
            except (TimeoutError, ValueError, OSError) as exc:
                ai_status = "failed"
                failure_reason = type(exc).__name__
    return AnalysisReport(trace_id=trace_id, findings=tuple(findings), deterministic_status="completed",
                          ai_status=ai_status, provider=provider, model=model, model_calls=model_calls,
                          latency_ms=(time.monotonic() - started) * 1000, failure_reason=failure_reason), packet


@contextmanager
def _analysis_slot(limit: int):
    global _active_analyses
    with _analysis_slot_lock:
        if limit < 1 or _active_analyses >= limit:
            raise AnalysisResourceLimit("ANALYSIS_RESOURCE_LIMIT")
        _active_analyses += 1
    try:
        yield
    finally:
        with _analysis_slot_lock:
            _active_analyses -= 1


def analyze_trace(db: Session, tenant_id: UUID, trace_id: str, *, mode: str = "deterministic",
                  judge: FailureJudge | None = None, settings: Settings | None = None) -> tuple[AnalysisReport, dict[str, Any]]:
    """Analyze one verified trace under the configured process-local concurrency bound."""
    effective_settings = settings or get_settings()
    with _analysis_slot(effective_settings.analysis_max_concurrent):
        return _analyze_trace(db, tenant_id, trace_id, mode=mode, judge=judge, settings=effective_settings)


def persist_analysis(db: Session, *, tenant_id: UUID, report: AnalysisReport, mode: str = "deterministic",
                     idempotency_key: str | None = None, integrity_status: str = "valid") -> AnalysisRun:
    now = datetime.now(timezone.utc)
    run = AnalysisRun(tenant_id=tenant_id, trace_id=report.trace_id, status="completed", taxonomy_version=report.taxonomy_version,
                      analysis_version=report.analysis_version, provider=report.provider, model=report.model,
                      policy_version=report.policy_version, started_at=now, completed_at=now,
                      deterministic_status=report.deterministic_status, ai_status=report.ai_status,
                      failure_reason=report.failure_reason, model_calls=report.model_calls,
                      input_tokens=report.input_tokens, output_tokens=report.output_tokens,
                      latency_ms=report.latency_ms, idempotency_key=idempotency_key)
    db.add(run)
    db.flush()
    for index, finding in enumerate(report.findings):
        db.add(AnalysisFinding(analysis_run_id=run.id, detector_id=finding.detector_id,
                               category=finding.category.value, root_cause_span_id=finding.root_cause_span_id,
                               symptom_span_id=finding.symptom_span_id, severity=finding.severity.value,
                               model_confidence=finding.confidence, source=finding.source.value,
                               reason=finding.evidence_summary, recommended_next_step=_recommendation(finding.category),
                               evidence_span_ids=list(dict.fromkeys([x for x in (finding.root_cause_span_id, finding.symptom_span_id) if x])),
                               evidence_event_ids=list(finding.event_ids), replay_ids=list(finding.replay_ids),
                               primary_hypothesis=index == 0))
    db.commit()
    db.refresh(run)
    logger.info("analysis_completed tenant_id=%s analysis_id=%s trace_id=%s mode=%s deterministic_status=%s ai_status=%s",
                tenant_id, run.id, report.trace_id, mode, report.deterministic_status, report.ai_status)
    return run


def persist_refused_analysis(db: Session, *, tenant_id: UUID, trace_id: str, reason: str,
                             idempotency_key: str | None = None) -> AnalysisRun:
    now = datetime.now(timezone.utc)
    run = AnalysisRun(tenant_id=tenant_id, trace_id=trace_id, status="blocked", taxonomy_version=TAXONOMY_VERSION,
                      analysis_version=ANALYSIS_VERSION, provider=None, model=None, policy_version="v1",
                      started_at=now, completed_at=now, deterministic_status="refused", ai_status="not_requested",
                      failure_reason=reason, model_calls=0, idempotency_key=idempotency_key)
    db.add(run)
    db.commit()
    db.refresh(run)
    logger.warning("analysis_refused_integrity tenant_id=%s analysis_id=%s trace_id=%s", tenant_id, run.id, trace_id)
    return run


def _recommendation(category: FailureCategory) -> str:
    recommendations = {
        FailureCategory.AUTHENTICATION: "Inspect credential configuration.",
        FailureCategory.AUTHORIZATION: "Review authorization scope and policy.",
        FailureCategory.RATE_LIMIT: "Check rate-limit configuration.",
        FailureCategory.TIMEOUT: "Inspect timeout and dependency latency.",
        FailureCategory.TOOL_SELECTION: "Review tool routing policy.",
        FailureCategory.TOOL_RESULT_INTERPRETATION: "Run dry-run replay.",
        FailureCategory.LOOP_OR_REPETITION: "Inspect loop termination policy.",
    }
    return recommendations.get(category, "Inspect the cited evidence and failure boundary.")
