"""Safe, deterministic replay policy primitives.

This module deliberately contains no execution adapter.  A replay can only
classify a recorded tool and, when an explicitly configured simulator exists,
produce a local deterministic result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import logging
from threading import Lock
import time
from typing import Any, Callable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentguard_server.config import Settings, get_settings
from agentguard_server.models import EventLog, IntegrityRecord, ReplaySession, ReplayStep
from agentguard_server.services.integrity import canonicalize_evidence, verify_trace_integrity


logger = logging.getLogger("agentguard.security")
_replay_slots_lock = Lock()
_active_replays = 0


class ToolClassification(StrEnum):
    READ_ONLY = "READ_ONLY"
    DETERMINISTIC = "DETERMINISTIC"
    MUTATING = "MUTATING"
    HIGH_IMPACT = "HIGH_IMPACT"
    UNKNOWN = "UNKNOWN"


class Decision(StrEnum):
    SIMULATE = "SIMULATE"
    BLOCK = "BLOCK"


class ComparisonStatus(StrEnum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    UNAVAILABLE = "UNAVAILABLE"
    BLOCKED = "BLOCKED"


Simulator = Callable[[dict[str, Any]], str]


@dataclass(frozen=True)
class ToolPolicy:
    name: str
    classification: ToolClassification
    simulator: Simulator | None = None


@dataclass(frozen=True)
class ToolDecision:
    classification: ToolClassification
    decision: Decision
    reason: str
    simulator: Simulator | None = None


def _weather_simulator(arguments: dict[str, Any]) -> str:
    city = arguments.get("city", "Kaohsiung")
    if not isinstance(city, str) or not city.strip() or len(city) > 128:
        raise ValueError("schema validation failed for get_weather")
    return f"{city}: sunny, 30C"


def simulate_tool(name: str, arguments: Any) -> str:
    """Run only a built-in deterministic fixture; never a recorded command."""
    if not isinstance(arguments, dict):
        raise ValueError("schema validation failed: simulator input must be an object")
    if name != "get_weather":
        raise ValueError(f"unknown simulator: {name}")
    return _weather_simulator(arguments)


class ToolPolicyRegistry:
    """Trusted application policy, intentionally independent of telemetry."""

    def __init__(self, policies: list[ToolPolicy]) -> None:
        self._policies: dict[str, ToolPolicy] = {}
        for policy in policies:
            if not policy.name or policy.name in self._policies:
                raise ValueError("tool policy names must be unique and non-empty")
            if not isinstance(policy.classification, ToolClassification):
                raise ValueError("tool policy classification is invalid")
            self._policies[policy.name] = policy

    def decide(self, name: str, *, recorded_classification: str | None = None) -> ToolDecision:
        # recorded_classification is accepted only to make the trust boundary
        # explicit: client/LLM telemetry can never influence this decision.
        del recorded_classification
        policy = self._policies.get(name)
        if policy is None:
            return ToolDecision(ToolClassification.UNKNOWN, Decision.BLOCK, "unknown tool")
        if policy.classification in {ToolClassification.READ_ONLY, ToolClassification.DETERMINISTIC}:
            simulator = policy.simulator or (simulate_tool if name == "get_weather" else None)
            if simulator is None:
                return ToolDecision(policy.classification, Decision.BLOCK, "simulator unavailable")
            return ToolDecision(policy.classification, Decision.SIMULATE, "simulation only", simulator)
        return ToolDecision(policy.classification, Decision.BLOCK, "tool policy blocks side effects")


def default_registry() -> ToolPolicyRegistry:
    return ToolPolicyRegistry([
        ToolPolicy("get_weather", ToolClassification.READ_ONLY, _weather_simulator),
    ])


class ReplayRefused(ValueError):
    def __init__(self, reason: str, integrity_status: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.integrity_status = integrity_status


@dataclass(frozen=True)
class ReplayPlanStep:
    sequence: int
    source_event_id: str
    source_span_id: str | None
    step_type: str
    tool_name: str | None
    classification: ToolClassification
    decision: Decision
    recorded_input_digest: str | None
    simulated_input_digest: str | None
    recorded_output_digest: str | None
    simulated_output_digest: str | None
    comparison_status: ComparisonStatus
    reason: str | None = None


@dataclass(frozen=True)
class ReplayPlan:
    trace_id: str
    integrity_status: str
    policy_version: str = "v1"
    steps: tuple[ReplayPlanStep, ...] = field(default_factory=tuple)
    blocked_reason: str | None = None


def _json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("replay input is not valid JSON") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _content_available(value: Any) -> bool:
    return value is not None and value != "[CONTENT_CAPTURE_DISABLED]" and value != "[REDACTED]"


def _bounded(value: Any, *, max_bytes: int, depth: int = 0) -> None:
    if depth > 20:
        raise ValueError("replay input schema depth exceeded")
    if isinstance(value, dict):
        if len(value) > 256:
            raise ValueError("replay input schema field limit exceeded")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 256:
                raise ValueError("replay input schema key is invalid")
            _bounded(item, max_bytes=max_bytes, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 1000:
            raise ValueError("replay input schema list limit exceeded")
        for item in value:
            _bounded(item, max_bytes=max_bytes, depth=depth + 1)
    elif isinstance(value, str) and len(value) > 16 * 1024:
        raise ValueError("replay input schema string limit exceeded")
    if len(_json_bytes(value)) > max_bytes:
        raise ValueError("replay input exceeds configured limit")


def _event_data(event: EventLog) -> dict[str, Any]:
    payload = event.payload_json or {}
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise ValueError("replay event payload is not an object")
    return data


def _build_replay_plan(db: Session, tenant_id: UUID, trace_id: str, *, registry: ToolPolicyRegistry | None = None,
                       settings: Settings | None = None) -> ReplayPlan:
    """Build a plan from verified ledger order; this function has no side effects."""
    settings = settings or get_settings()
    registry = registry or default_registry()
    verification = verify_trace_integrity(db, tenant_id, trace_id, settings)
    if verification.status != "valid" or not verification.chain_valid or not verification.projection_consistent:
        raise ReplayRefused("REPLAY_REFUSED_INTEGRITY", verification.status)

    events = list(db.scalars(select(EventLog).where(EventLog.tenant_id == tenant_id, EventLog.trace_id == trace_id)))
    by_key = {(event.event_type, event.event_id): event for event in events}
    records = list(db.scalars(select(IntegrityRecord).where(
        IntegrityRecord.tenant_id == tenant_id, IntegrityRecord.trace_id == trace_id
    ).order_by(IntegrityRecord.sequence)))
    steps: list[ReplayPlanStep] = []
    end_by_span: dict[str, EventLog] = {}
    for record in records:
        event = by_key.get((record.event_type, record.event_id))
        if event is None:
            continue
        data = _event_data(event)
        if event.event_type == "span.ended" and data.get("span_id"):
            end_by_span[str(data["span_id"])] = event
    started_spans: set[str] = set()
    total_input = 0
    started = time.monotonic()
    for record in records:
        event = by_key.get((record.event_type, record.event_id))
        if event is None or event.event_type != "span.started":
            continue
        data = _event_data(event)
        span_id = str(data.get("span_id") or event.event_id)
        if span_id in started_spans:
            continue
        started_spans.add(span_id)
        span_type = str(data.get("span_type", "unknown")).lower()
        if span_type not in {"tool", "function", "plugin", "mcp"} and not data.get("tool_name"):
            continue
        name = str(data.get("tool_name") or data.get("name") or "")
        decision = registry.decide(name, recorded_classification=data.get("classification"))
        input_value = data.get("input", data.get("arguments"))
        end_event = end_by_span.get(span_id)
        end_data = _event_data(end_event) if end_event is not None else {}
        output_value = end_data.get("output", end_data.get("result"))
        recorded_input = _content_available(input_value)
        recorded_output = _content_available(output_value)
        if recorded_input:
            _bounded(input_value, max_bytes=settings.replay_max_input_bytes)
            total_input += len(_json_bytes(input_value))
        if total_input > settings.replay_max_input_bytes:
            raise ReplayRefused("REPLAY_RESOURCE_LIMIT", "valid")
        simulated_input_digest = _digest(input_value) if recorded_input else None
        simulated_output_digest = None
        reason: str | None = decision.reason
        comparison = ComparisonStatus.BLOCKED if decision.decision == Decision.BLOCK else ComparisonStatus.UNAVAILABLE
        if decision.decision == Decision.SIMULATE:
            if not recorded_input:
                reason = "INSUFFICIENT_REPLAY_DATA"
            else:
                try:
                    simulated_output = decision.simulator(input_value)
                    simulated_output_digest = _digest(simulated_output)
                    if recorded_output:
                        _bounded(output_value, max_bytes=settings.replay_max_input_bytes)
                        comparison = ComparisonStatus.MATCH if _digest(output_value) == simulated_output_digest else ComparisonStatus.MISMATCH
                    else:
                        comparison = ComparisonStatus.UNAVAILABLE
                        reason = "INSUFFICIENT_REPLAY_DATA"
                except ValueError as exc:
                    comparison = ComparisonStatus.UNAVAILABLE
                    reason = str(exc)
        steps.append(ReplayPlanStep(
            sequence=len(steps) + 1, source_event_id=event.event_id, source_span_id=span_id,
            step_type="tool", tool_name=name, classification=decision.classification, decision=decision.decision,
            recorded_input_digest=_digest(input_value) if recorded_input else None,
            simulated_input_digest=simulated_input_digest, recorded_output_digest=_digest(output_value) if recorded_output else None,
            simulated_output_digest=simulated_output_digest, comparison_status=comparison, reason=reason,
        ))
        if len(steps) > settings.replay_max_steps:
            raise ReplayRefused("REPLAY_RESOURCE_LIMIT", "valid")
        if time.monotonic() - started > settings.replay_max_duration_seconds:
            raise ReplayRefused("REPLAY_RESOURCE_LIMIT", "valid")
    return ReplayPlan(trace_id=trace_id, integrity_status=verification.status, steps=tuple(steps))


@contextmanager
def _replay_slot(settings: Settings):
    global _active_replays
    with _replay_slots_lock:
        if _active_replays >= settings.replay_max_concurrent:
            raise ReplayRefused("REPLAY_RESOURCE_LIMIT", "valid")
        _active_replays += 1
    try:
        yield
    finally:
        with _replay_slots_lock:
            _active_replays -= 1


def build_replay_plan(db: Session, tenant_id: UUID, trace_id: str, *, registry: ToolPolicyRegistry | None = None,
                      settings: Settings | None = None) -> ReplayPlan:
    settings = settings or get_settings()
    with _replay_slot(settings):
        return _build_replay_plan(db, tenant_id, trace_id, registry=registry, settings=settings)


def persist_replay(db: Session, *, tenant_id: UUID, plan: ReplayPlan, idempotency_key: str | None = None) -> ReplaySession:
    now = datetime.now(timezone.utc)
    blocked = any(step.decision == Decision.BLOCK for step in plan.steps)
    session = ReplaySession(tenant_id=tenant_id, source_trace_id=plan.trace_id, mode="dry_run",
                            status="blocked" if blocked else "completed", created_at=now, started_at=now, completed_at=now,
                            integrity_status=plan.integrity_status, policy_version=plan.policy_version,
                            failure_reason="REPLAY_STEP_BLOCKED" if blocked else None, idempotency_key=idempotency_key)
    db.add(session)
    db.flush()
    for step in plan.steps:
        db.add(ReplayStep(replay_session_id=session.id, sequence=step.sequence,
                          source_event_id=step.source_event_id, source_span_id=step.source_span_id,
                          step_type=step.step_type, tool_name=step.tool_name,
                          classification=step.classification.value, decision=step.decision.value,
                          recorded_input_digest=step.recorded_input_digest, simulated_input_digest=step.simulated_input_digest,
                          recorded_output_digest=step.recorded_output_digest, simulated_output_digest=step.simulated_output_digest,
                          comparison_status=step.comparison_status.value, reason=step.reason, created_at=now))
    db.commit()
    db.refresh(session)
    logger.info("replay_completed tenant_id=%s replay_id=%s source_trace_id=%s mode=dry_run status=%s policy_version=%s",
                tenant_id, session.id, plan.trace_id, session.status, plan.policy_version)
    return session


def persist_blocked_replay(db: Session, *, tenant_id: UUID, trace_id: str, reason: str,
                           integrity_status: str, idempotency_key: str | None = None) -> ReplaySession:
    now = datetime.now(timezone.utc)
    session = ReplaySession(tenant_id=tenant_id, source_trace_id=trace_id, mode="dry_run", status="blocked",
                            created_at=now, completed_at=now, integrity_status=integrity_status,
                            policy_version="v1", failure_reason=reason, idempotency_key=idempotency_key)
    db.add(session)
    db.commit()
    db.refresh(session)
    logger.warning("replay_blocked tenant_id=%s replay_id=%s source_trace_id=%s mode=dry_run reason=%s",
                   tenant_id, session.id, trace_id, reason)
    return session
