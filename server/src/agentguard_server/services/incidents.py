"""Deterministic, tenant-scoped incident projection over verified V5 findings."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import unicodedata
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from agentguard_server.models import AnalysisFinding, AnalysisRun, Incident, IncidentEvent, IncidentOccurrence, Span, Trace
from agentguard_server.services.integrity import verify_trace_integrity


FINGERPRINT_VERSION = "incident-fingerprint-v1"
SEVERITY_POLICY_VERSION = "severity-v1"
MAX_DIMENSION_LENGTH = 96
MAX_OCCURRENCES_IN_RESPONSE = 100
MAX_HISTORY_IN_RESPONSE = 100


class IncidentStatus:
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class IncidentSeverity:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentTransitionError(ValueError):
    pass


@dataclass(frozen=True)
class Fingerprint:
    digest: str
    version: str
    title: str
    dimensions: dict[str, str]


def _safe_component(value: Any, *, default: str = "unknown", lower: bool = True) -> str:
    """Normalize metadata, never natural-language evidence, into a bounded token."""
    if value is None:
        return default
    value = unicodedata.normalize("NFKC", str(value)).strip()
    value = re.sub(r"[^A-Za-z0-9._:/-]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-._")[:MAX_DIMENSION_LENGTH]
    if not value:
        return default
    return value.lower() if lower else value


def _safe_dimension(value: Any) -> str | None:
    normalized = _safe_component(value, default="")
    return normalized or None


def fingerprint_for_finding(finding: Any, *, component_name: Any = None, provider: Any = None,
                            model: Any = None, workflow_name: Any = None, agent_name: Any = None,
                            agent_version: Any = None) -> Fingerprint:
    category = _safe_component(getattr(finding, "category", "UNKNOWN"), lower=False).upper()
    detector = _safe_component(getattr(finding, "detector_id", "unknown"))
    component = _safe_component(component_name)
    dimensions = {
        "category": category,
        "detector": detector,
        "component": component,
    }
    for key, value in (("provider", provider), ("model", model), ("workflow", workflow_name),
                       ("agent", agent_name), ("agent_version", agent_version)):
        safe = _safe_dimension(value)
        if safe:
            dimensions[key] = safe
    # The canonical input is an allowlisted set of structured identifiers. It
    # intentionally excludes reason, error_message, prompts, users, and tools.
    canonical = json.dumps({"version": FINGERPRINT_VERSION, **dimensions}, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    title = f"{category} in {_safe_component(component_name, lower=False)}"
    return Fingerprint(digest=digest, version=FINGERPRINT_VERSION, title=title[:255], dimensions=dimensions)


def _severity_rank(value: str) -> int:
    return {IncidentSeverity.LOW: 0, IncidentSeverity.MEDIUM: 1, IncidentSeverity.HIGH: 2,
            IncidentSeverity.CRITICAL: 3}.get(value, 0)


def _policy_severity(category: str, count: int) -> str:
    category = category.upper()
    if category in {"AUTHENTICATION", "AUTHORIZATION", "TIMEOUT", "GUARDRAIL_FAILURE"} or count >= 10:
        return IncidentSeverity.HIGH
    if count >= 3:
        return IncidentSeverity.MEDIUM
    return IncidentSeverity.LOW


def _effective_severity(finding: Any, count: int) -> str:
    declared = str(getattr(finding, "severity", IncidentSeverity.LOW)).upper()
    # No untrusted telemetry may create CRITICAL. V10 has no configured
    # trusted-critical condition; this makes the boundary explicit and safe.
    if declared == IncidentSeverity.CRITICAL:
        declared = IncidentSeverity.HIGH
    candidate = _policy_severity(str(getattr(finding, "category", "UNKNOWN")), count)
    return declared if _severity_rank(declared) >= _severity_rank(candidate) else candidate


def _now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    return current.replace(tzinfo=timezone.utc) if current.tzinfo is None else current.astimezone(timezone.utc)


def _source_context(db: Session, tenant_id: UUID, trace_id: str, finding: Any) -> tuple[Trace | None, Span | None]:
    trace = db.scalar(select(Trace).where(Trace.tenant_id == tenant_id, Trace.trace_id == trace_id))
    span_id = getattr(finding, "symptom_span_id", None) or getattr(finding, "root_cause_span_id", None)
    span = None
    if span_id:
        span = db.scalar(select(Span).where(Span.tenant_id == tenant_id, Span.trace_id == trace_id,
                                             Span.span_id == str(span_id)))
    return trace, span


def _context_values(trace: Trace | None, span: Span | None) -> dict[str, str | None]:
    attrs = (span.attributes or {}) if span is not None and isinstance(span.attributes, dict) else {}
    return {
        "component": span.name if span is not None else None,
        "provider": trace.provider if trace is not None else None,
        "workflow": trace.workflow_name if trace is not None else None,
        "agent": attrs.get("agent.name") or attrs.get("agent_name"),
        "agent_version": attrs.get("agent.version") or attrs.get("agent_version"),
        "model": attrs.get("gen_ai.request.model") or attrs.get("model"),
    }


def _finding_key(finding: Any) -> str:
    material = ":".join(_safe_component(getattr(finding, key, None)) for key in
                          ("detector_id", "category", "root_cause_span_id", "symptom_span_id"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:128]


def _append_event(db: Session, incident: Incident, event_type: str, *, actor_type: str = "system",
                  actor_id: str | None = None, metadata: dict[str, Any] | None = None,
                  created_at: datetime | None = None) -> None:
    safe_metadata = {str(key)[:48]: _safe_component(value, default="") for key, value in (metadata or {}).items()}
    db.add(IncidentEvent(tenant_id=incident.tenant_id, incident_id=incident.id, event_type=event_type,
                         actor_type=_safe_component(actor_type, default="system"),
                         actor_id=_safe_dimension(actor_id), metadata_json=safe_metadata,
                         created_at=_now(created_at)))


def _get_or_create_incident(db: Session, tenant_id: UUID, fp: Fingerprint, observed_at: datetime,
                            finding: Any) -> Incident:
    values = dict(tenant_id=tenant_id, fingerprint=fp.digest, fingerprint_version=fp.version,
                  title=fp.title, status=IncidentStatus.OPEN, severity=_effective_severity(finding, 1),
                  severity_policy_version=SEVERITY_POLICY_VERSION, first_seen_at=observed_at,
                  last_seen_at=observed_at, occurrence_count=0, affected_trace_count=0,
                  primary_category=_safe_component(getattr(finding, "category", "UNKNOWN"), lower=False).upper(),
                  dimensions=fp.dimensions, created_at=observed_at, updated_at=observed_at)
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        db.execute(pg_insert(Incident).values(**values).on_conflict_do_nothing(
            index_elements=["tenant_id", "fingerprint", "fingerprint_version"]))
    else:
        existing = db.scalar(select(Incident).where(Incident.tenant_id == tenant_id,
                                                     Incident.fingerprint == fp.digest,
                                                     Incident.fingerprint_version == fp.version))
        if existing is None:
            db.add(Incident(**values))
            db.flush()
    incident = db.scalar(select(Incident).where(Incident.tenant_id == tenant_id,
                                                Incident.fingerprint == fp.digest,
                                                Incident.fingerprint_version == fp.version).with_for_update())
    if incident is None:
        raise RuntimeError("incident creation failed")
    return incident


def process_finding(db: Session, tenant_id: UUID, analysis: Any, finding: Any,
                    *, observed_at: datetime | None = None) -> Incident:
    """Idempotently project one verified deterministic V5 finding into V10."""
    if str(getattr(finding, "source", "DETERMINISTIC")).upper() != "DETERMINISTIC":
        raise ValueError("only deterministic findings may create incidents")
    trace_id = str(getattr(analysis, "trace_id"))
    trace, span = _source_context(db, tenant_id, trace_id, finding)
    if trace is not None:
        verification = verify_trace_integrity(db, tenant_id, trace_id)
        if verification.status != "valid":
            raise ValueError("incident processing requires valid evidence integrity")
    context = _context_values(trace, span)
    when = _now(observed_at)
    fp = fingerprint_for_finding(finding, component_name=context["component"], provider=context["provider"],
                                 model=context["model"], workflow_name=context["workflow"],
                                 agent_name=context["agent"], agent_version=context["agent_version"])
    incident = _get_or_create_incident(db, tenant_id, fp, when, finding)
    finding_key = _finding_key(finding)
    analysis_id = UUID(str(analysis.id))
    occurrence = db.scalar(select(IncidentOccurrence).where(
        IncidentOccurrence.tenant_id == tenant_id, IncidentOccurrence.trace_id == trace_id,
        IncidentOccurrence.analysis_id == analysis_id, IncidentOccurrence.finding_key == finding_key))
    if occurrence is not None:
        db.commit()
        return incident
    occurrence_values = dict(tenant_id=tenant_id, incident_id=incident.id, trace_id=trace_id,
                             analysis_id=analysis_id, finding_key=finding_key,
                             failure_category=fp.dimensions["category"],
                             root_cause_span_id=getattr(finding, "root_cause_span_id", None),
                             symptom_span_id=getattr(finding, "symptom_span_id", None), observed_at=when,
                             agent_name=_safe_dimension(context["agent"]), workflow_name=_safe_dimension(context["workflow"]),
                             agent_version=_safe_dimension(context["agent_version"]), provider=_safe_dimension(context["provider"]),
                             model=_safe_dimension(context["model"]))
    if db.get_bind().dialect.name == "postgresql":
        db.execute(pg_insert(IncidentOccurrence).values(**occurrence_values).on_conflict_do_nothing(
            index_elements=["tenant_id", "trace_id", "analysis_id", "finding_key"]))
    else:
        db.add(IncidentOccurrence(**occurrence_values))
        db.flush()
    occurrence = db.scalar(select(IncidentOccurrence).where(
        IncidentOccurrence.tenant_id == tenant_id, IncidentOccurrence.trace_id == trace_id,
        IncidentOccurrence.analysis_id == analysis_id, IncidentOccurrence.finding_key == finding_key))
    if occurrence is None:
        raise RuntimeError("incident occurrence creation failed")
    if incident.occurrence_count == 0:
        _append_event(db, incident, "CREATED", metadata={"category": fp.dimensions["category"]}, created_at=when)
    else:
        _append_event(db, incident, "OCCURRENCE_RECORDED", metadata={"category": fp.dimensions["category"]}, created_at=when)
    if incident.status == IncidentStatus.RESOLVED:
        old = incident.status
        incident.status = IncidentStatus.OPEN
        incident.resolved_at = None
        _append_event(db, incident, "REOPENED", metadata={"from": old, "to": IncidentStatus.OPEN}, created_at=when)
    incident.occurrence_count = int(incident.occurrence_count or 0) + 1
    incident.affected_trace_count = int(db.scalar(select(func.count(func.distinct(IncidentOccurrence.trace_id))).where(
        IncidentOccurrence.tenant_id == tenant_id, IncidentOccurrence.incident_id == incident.id)) or 0)
    incident.first_seen_at = min(_now(incident.first_seen_at), when)
    incident.last_seen_at = max(_now(incident.last_seen_at), when)
    previous_severity = incident.severity
    incident.severity = _effective_severity(finding, incident.occurrence_count)
    if _severity_rank(incident.severity) > _severity_rank(previous_severity):
        _append_event(db, incident, "SEVERITY_INCREASED", metadata={"from": previous_severity, "to": incident.severity}, created_at=when)
    incident.updated_at = when
    db.commit()
    db.refresh(incident)
    return incident


def process_analysis_findings(db: Session, tenant_id: UUID, analysis: AnalysisRun) -> list[Incident]:
    if analysis.tenant_id != tenant_id or analysis.deterministic_status != "completed":
        return []
    findings = list(db.scalars(select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == analysis.id)))
    incidents: list[Incident] = []
    for finding in findings:
        if finding.source == "DETERMINISTIC":
            incidents.append(process_finding(db, tenant_id, analysis, finding))
    return incidents


def transition_incident(db: Session, tenant_id: UUID, incident_id: UUID, target: str, *, actor_type: str,
                        actor_id: str | None = None, now: datetime | None = None) -> Incident:
    target = str(target).upper()
    if target not in {IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED, IncidentStatus.RESOLVED}:
        raise IncidentTransitionError("invalid incident status")
    incident = db.scalar(select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id).with_for_update())
    if incident is None:
        raise LookupError("incident not found")
    if incident.status == target:
        return incident
    allowed = {(IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED),
               (IncidentStatus.ACKNOWLEDGED, IncidentStatus.RESOLVED),
               (IncidentStatus.OPEN, IncidentStatus.RESOLVED),
               (IncidentStatus.RESOLVED, IncidentStatus.OPEN)}
    if (incident.status, target) not in allowed:
        raise IncidentTransitionError("invalid incident transition")
    when = _now(now)
    old = incident.status
    incident.status = target
    incident.resolved_at = when if target == IncidentStatus.RESOLVED else None
    incident.updated_at = when
    _append_event(db, incident, target, actor_type=actor_type, actor_id=actor_id,
                  metadata={"from": old, "to": target}, created_at=when)
    db.commit()
    db.refresh(incident)
    return incident


def incident_trend(db: Session, incident: Incident, *, now: datetime | None = None) -> str:
    current = _now(now)
    rows = list(db.scalars(select(IncidentOccurrence.observed_at).where(
        IncidentOccurrence.tenant_id == incident.tenant_id, IncidentOccurrence.incident_id == incident.id,
        IncidentOccurrence.observed_at >= current - timedelta(hours=25),
        IncidentOccurrence.observed_at <= current).order_by(IncidentOccurrence.observed_at.desc()).limit(1001)))
    rows = [_now(value) for value in rows]
    if len(rows) < 2:
        return "INSUFFICIENT_DATA"
    recent_start = current - timedelta(hours=1)
    previous_start = current - timedelta(hours=2)
    recent = sum(when >= recent_start for when in rows)
    previous = sum(previous_start <= when < recent_start for when in rows)
    if recent > previous and recent >= max(2, previous * 2):
        return "INCREASING"
    if recent < previous:
        return "DECREASING"
    return "STABLE"


def incident_history(db: Session, incident: Incident) -> list[IncidentEvent]:
    return list(db.scalars(select(IncidentEvent).where(
        IncidentEvent.tenant_id == incident.tenant_id, IncidentEvent.incident_id == incident.id
    ).order_by(IncidentEvent.created_at.desc()).limit(MAX_HISTORY_IN_RESPONSE)))
