from __future__ import annotations

from typing import Any
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import Response
import logging
from sqlalchemy import or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agentguard_server.db.session import get_session_factory
from agentguard_server.config import get_settings, validate_configuration
from agentguard_server.provenance import build_metadata, migration_head
from agentguard_server.schemas.anchoring import AnchorStatusResponse, CheckpointCreate, CheckpointResponse, ContinuityResponse
from agentguard_server.schemas.events import (AnalysisFindingResponse, AnalysisRequest, AnalysisResponse,
    EvaluationCaseResponse, EvaluationComparisonCreate, EvaluationComparisonResponse, EvaluationRunCreate,
    EvaluationRunResponse, EvaluationSuiteCreate, EvaluationSuiteResponse, IntegrityResponse, IngestEnvelope,
    IngestResponse, ReplayRequest, ReplayResponse, ReplayStepResponse, SpanResponse, TraceDetailResponse,
    TraceListResponse, TraceResponse)
from agentguard_server.schemas.incidents import (IncidentDetailResponse, IncidentEventResponse,
    IncidentOccurrenceResponse, IncidentSummaryResponse)
from agentguard_server.schemas.notifications import (AlertPolicyCreate, AlertPolicyResponse,
    AlertPolicyUpdate, NotificationDeliveryResponse, NotificationDestinationCreate,
    NotificationDestinationResponse, NotificationDestinationUpdate)
from agentguard_server.schemas.retention import (ArchiveResponse, ArchiveRetrievalResponse, RetentionHoldCreate,
    RetentionHoldResponse, RetentionRunRequest, RetentionRunResponse, RetentionStatusResponse)
from agentguard_server.schemas.ledger import LedgerCompactRequest, LedgerEventLookup, LedgerSegmentResponse, LedgerVerificationResponse
from agentguard_server.schemas.integrity_segments import IntegritySegmentActionResponse, IntegritySegmentPlanRequest, IntegritySegmentRequest, IntegritySegmentResponse
from agentguard_server.schemas.replicas import ArchiveRepairRequest, ArchiveReplicaHealthResponse, ArchiveReplicaResponse
from agentguard_server.services.auth import AuthContext, authenticate
from agentguard_server.services.ingestion import IdempotencyConflict, ingest_events
from agentguard_server.services.integrity import verify_trace_integrity
from agentguard_server.services.anchoring import (AnchorPermanentError, HttpSignedWitnessProvider, IntegrityAnchorJob, anchor_job, create_checkpoint, freshness, remote_continuity, verify_checkpoint)
from agentguard_server.services.query import get_trace, list_traces, make_span_tree
from agentguard_server.services.rate_limit import RateLimitStorageError, rate_limiter
from agentguard_server.services.replay import ReplayRefused, build_replay_plan, persist_blocked_replay, persist_replay
from agentguard_server.services.analysis import AnalysisRefused, AnalysisResourceLimit, analyze_trace, persist_analysis, persist_refused_analysis
from agentguard_server.services.retention import create_hold, queue_retention_job, release_hold, retrieve_archive, retention_status
from agentguard_server.services.ledger import (LedgerError, LedgerVerificationError, authorize_ledger_compaction,
    create_ledger_segment_candidate, lookup_ledger_event, queue_ledger_compaction, verify_mixed_ledger)
from agentguard_server.services.archive import ArchiveKeyring
from agentguard_server.services.archive_store import S3ArchiveStore, archive_store_registry
from agentguard_server.services.replicas import (
    ArchiveReplica, INTEGRITY_SEGMENT, LEDGER_SEGMENT, TRACE_ARCHIVE, list_replicas, logical_archive_health,
    repair_missing_replica, scrub_replica, verify_replica,
)
from agentguard_server.services.otlp import OTLPDecodeError, OTLPSettings, decode_request, success_response
from agentguard_server.models import (AnalysisFinding, AnalysisRun, EvaluationCaseResult, EvaluationComparison,
    EvaluationRun, EvaluationSuite, Incident, IncidentEvent, IncidentOccurrence, ReplaySession,
    AlertPolicy, NotificationDelivery, NotificationDestination, IntegrityAnchorJob, IntegrityCheckpoint, ExternalAnchorReceipt, ArchiveRecord, RetentionHold, Trace, LedgerSegment, LedgerSegmentLifecycle, IntegrityArchiveSegment)
from agentguard_server.services.integrity_segments import (
    IntegritySegmentEligibilityError, IntegritySegmentVerificationError,
    archive_integrity_segment, authorize_integrity_compaction,
    compact_integrity_segment, create_integrity_segment_candidate,
    queue_integrity_compaction,
)
from agentguard_server.services.evaluation import (EvaluationValidationError, compare_runs, create_run,
    create_suite)
from agentguard_server.services.incidents import (IncidentStatus, IncidentTransitionError, incident_history,
    incident_trend, process_analysis_findings, transition_incident)
from agentguard_server.services.notifications import (create_destination, create_notification_intents,
    create_policy, dispatch_delivery)
from agentguard_server.models.quorum import CheckpointQuorumEvaluation, Witness, WitnessHealthSnapshot
from agentguard_server.services.quorum import evaluate_checkpoint_quorum

router = APIRouter()
logger = logging.getLogger("agentguard.security")


def db_session():
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()


def get_auth_context(authorization: str | None = Header(default=None), db: Session = Depends(db_session)) -> AuthContext:
    settings = get_settings()
    if not settings.auth_enabled:
        raise HTTPException(status_code=503, detail="authentication must remain enabled")
    if not settings.key_pepper:
        raise HTTPException(status_code=503, detail="authentication unavailable")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or malformed bearer credential", headers={"WWW-Authenticate": "Bearer"})
    token = authorization[7:].strip()
    context = authenticate(db, token, settings.key_pepper)
    if context is None:
        raise HTTPException(status_code=401, detail="invalid or inactive credential", headers={"WWW-Authenticate": "Bearer"})
    return context


def require_scope(scope: str):
    def dependency(context: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if scope not in context.scopes:
            logger.warning("authorization_denied tenant_id=%s scope=%s", context.tenant_id, scope)
            raise HTTPException(status_code=403, detail=f"missing required scope: {scope}")
        return context
    return dependency


def enforce_rate_limit(operation: str, limit_name: str):
    def dependency(db: Session = Depends(db_session),
                   context: AuthContext = Depends(get_auth_context)) -> AuthContext:
        settings = get_settings()
        limit = getattr(settings, limit_name)
        try:
            allowed, retry_after = rate_limiter.allow_shared(
                db, context.tenant_id, operation, limit, settings.rate_limit_window_seconds,
            )
        except RateLimitStorageError as exc:
            logger.error("coordination_operation=rate_limit result=unavailable operation=%s", operation)
            raise HTTPException(status_code=503, detail="rate-limit coordination unavailable") from exc
        if not allowed:
            logger.warning("rate_limit_triggered tenant_id=%s operation=%s", context.tenant_id, operation)
            raise HTTPException(status_code=429, detail="rate limit exceeded", headers={"Retry-After": str(max(1, int(retry_after + 0.999)))})
        return context
    return dependency


def require_otlp_access(db: Session = Depends(db_session),
                        context: AuthContext = Depends(get_auth_context)) -> AuthContext:
    if "ingest:write" not in context.scopes:
        logger.warning("authorization_denied tenant_id=%s scope=ingest:write", context.tenant_id)
        raise HTTPException(status_code=403, detail="missing required scope: ingest:write")
    settings = get_settings()
    try:
        allowed, retry_after = rate_limiter.allow_shared(
            db, context.tenant_id, "otlp", settings.ingest_rate_limit, settings.rate_limit_window_seconds,
        )
    except RateLimitStorageError as exc:
        logger.error("coordination_operation=rate_limit result=unavailable operation=otlp")
        raise HTTPException(status_code=503, detail="rate-limit coordination unavailable") from exc
    if not allowed:
        logger.warning("rate_limit_triggered tenant_id=%s operation=otlp", context.tenant_id)
        raise HTTPException(status_code=429, detail="rate limit exceeded", headers={"Retry-After": str(max(1, int(retry_after + 0.999)))})
    return context


def require_replay_access(context: AuthContext = Depends(get_auth_context)) -> AuthContext:
    if "traces:read" not in context.scopes or "replay:run" not in context.scopes:
        logger.warning("authorization_denied tenant_id=%s scope=replay", context.tenant_id)
        raise HTTPException(status_code=403, detail="missing required replay scopes")
    return context


def require_analysis_access(context: AuthContext = Depends(get_auth_context)) -> AuthContext:
    if "traces:read" not in context.scopes or "analysis:run" not in context.scopes:
        logger.warning("authorization_denied tenant_id=%s scope=analysis", context.tenant_id)
        raise HTTPException(status_code=403, detail="missing required analysis scopes")
    return context


def _queue_incident_notification(db: Session, incident: Incident, event_type: str) -> None:
    """Notification failures are isolated from the incident/evidence transaction."""
    try:
        lifecycle = db.scalar(select(text("count(*)")).select_from(IncidentEvent).where(
            IncidentEvent.tenant_id == incident.tenant_id, IncidentEvent.incident_id == incident.id)) or 1
        create_notification_intents(db, incident.tenant_id, incident, event_type, lifecycle_version=int(lifecycle))
    except Exception as exc:
        db.rollback()
        logger.error("notification_intent_failed tenant_id=%s incident_id=%s reason=%s", incident.tenant_id, incident.id, type(exc).__name__)


def require_evaluation_access(scope: str):
    return require_scope(scope)


def _evaluation_rate(context: AuthContext = Depends(enforce_rate_limit("evaluation", "evaluation_rate_limit"))) -> AuthContext:
    return context


def _incident_rate(context: AuthContext = Depends(enforce_rate_limit("incidents", "read_rate_limit"))) -> AuthContext:
    return context


def _incident_summary(db: Session, incident: Incident) -> IncidentSummaryResponse:
    return IncidentSummaryResponse(
        id=incident.id, tenant_id=incident.tenant_id, fingerprint=incident.fingerprint,
        fingerprint_version=incident.fingerprint_version, title=incident.title, status=incident.status,
        severity=incident.severity, severity_policy_version=incident.severity_policy_version,
        primary_category=incident.primary_category, first_seen_at=incident.first_seen_at,
        last_seen_at=incident.last_seen_at, occurrence_count=incident.occurrence_count,
        affected_trace_count=incident.affected_trace_count, trend=incident_trend(db, incident),
    )


def _incident_detail(db: Session, incident: Incident) -> IncidentDetailResponse:
    occurrences = list(db.scalars(select(IncidentOccurrence).where(
        IncidentOccurrence.tenant_id == incident.tenant_id, IncidentOccurrence.incident_id == incident.id
    ).order_by(IncidentOccurrence.observed_at.desc()).limit(100)))
    analysis_ids = [row.analysis_id for row in occurrences]
    findings: list[dict[str, str | None]] = []
    if analysis_ids:
        source_findings = list(db.scalars(select(AnalysisFinding).where(AnalysisFinding.analysis_run_id.in_(analysis_ids)).limit(100)))
        findings = [{"detector_id": row.detector_id, "category": row.category, "severity": row.severity,
                     "source": row.source, "root_cause_span_id": row.root_cause_span_id,
                     "symptom_span_id": row.symptom_span_id} for row in source_findings]
    trace_ids = {row.trace_id for row in occurrences}
    associations: list[dict[str, str]] = []
    if trace_ids:
        associations = [{"comparison_id": str(value), "relation": "associated_with"} for value in db.scalars(
            select(EvaluationComparison.id).join(
                EvaluationRun, or_(EvaluationRun.id == EvaluationComparison.baseline_run_id,
                                    EvaluationRun.id == EvaluationComparison.candidate_run_id)
            ).join(EvaluationCaseResult, EvaluationCaseResult.run_id == EvaluationRun.id
            ).where(EvaluationComparison.tenant_id == incident.tenant_id,
                    EvaluationCaseResult.tenant_id == incident.tenant_id,
                    EvaluationCaseResult.trace_id.in_(trace_ids)).limit(100)
        )]
    return IncidentDetailResponse(
        **_incident_summary(db, incident).model_dump(), dimensions=incident.dimensions or {},
        occurrences=[IncidentOccurrenceResponse.model_validate(row, from_attributes=True) for row in occurrences],
        history=[IncidentEventResponse(id=row.id, event_type=row.event_type, actor_type=row.actor_type,
                                       actor_id=row.actor_id, metadata=row.metadata_json or {}, created_at=row.created_at)
                 for row in incident_history(db, incident)],
        findings=findings, v8_associations=associations,
    )


def _trace(trace: Any) -> TraceResponse:
    return TraceResponse(trace_id=trace.trace_id, workflow_name=trace.workflow_name, group_id=trace.group_id,
                         provider=trace.provider, started_at=trace.started_at, ended_at=trace.ended_at,
                         status=trace.status, metadata=trace.metadata_json or {}, schema_version=trace.schema_version)


def _span(span: Any) -> SpanResponse:
    return SpanResponse(span_id=span.span_id, trace_id=span.trace_id, parent_span_id=span.parent_span_id,
                        span_type=span.span_type, name=span.name, started_at=span.started_at,
                        ended_at=span.ended_at, duration_ms=span.duration_ms, status=span.status,
                        error_type=span.error_type, error_message=span.error_message,
                        attributes=span.attributes or {}, schema_version=span.schema_version)


def _tree_node(node: dict[str, Any]) -> dict[str, Any]:
    root = {"span": _span(node["span"]).model_dump(mode="json"), "children": []}
    stack = [(node, root)]
    while stack:
        source, target = stack.pop()
        for child in source["children"]:
            child_target = {"span": _span(child["span"]).model_dump(mode="json"), "children": []}
            target["children"].append(child_target)
            stack.append((child, child_target))
    return root


@router.get("/health")
def health(db: Session = Depends(db_session)) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    return {"status": "healthy"}


@router.get("/health/live")
def liveness() -> dict[str, str]:
    return {"status": "alive"}


@router.get("/health/ready")
def readiness(db: Session = Depends(db_session)) -> dict[str, str]:
    try:
        validate_configuration()
        db.execute(text("SELECT 1"))
        current_head = db.execute(text("SELECT version_num FROM public.alembic_version")).scalar_one_or_none()
    except Exception as exc:
        logger.error("readiness_failed reason=%s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="AgentGuard is not ready") from exc
    expected_head = migration_head()
    if current_head != expected_head:
        logger.error("readiness_failed reason=migration_behind")
        raise HTTPException(status_code=503, detail="AgentGuard database schema is not ready")
    return {"status": "ready", "migration_head": current_head}


@router.get("/version")
def version() -> dict[str, str]:
    return build_metadata()


@router.post("/v1/ingest", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
def ingest(envelope: IngestEnvelope, db: Session = Depends(db_session), context: AuthContext = Depends(require_scope("ingest:write")), _rate: AuthContext = Depends(enforce_rate_limit("ingest", "ingest_rate_limit"))) -> IngestResponse:
    try:
        accepted, duplicates = ingest_events(db, envelope.events, context.tenant_id, capture_content=get_settings().capture_content)
    except IdempotencyConflict as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="event idempotency conflict") from exc
    return IngestResponse(accepted=accepted, duplicates=duplicates)


@router.post("/otlp/v1/traces", status_code=status.HTTP_200_OK)
async def otlp_traces(request: Request, db: Session = Depends(db_session), context: AuthContext = Depends(require_otlp_access)) -> Response:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-protobuf":
        return Response(status_code=415, content=b"unsupported OTLP content type")
    settings = get_settings()
    body = await request.body()
    decoder_settings = OTLPSettings(
        max_compressed_bytes=settings.otlp_max_compressed_bytes,
        max_decompressed_bytes=settings.otlp_max_decompressed_bytes,
        max_resource_spans=settings.otlp_max_resource_spans,
        max_scope_spans=settings.otlp_max_scope_spans,
        max_spans=settings.otlp_max_spans,
        max_attributes=settings.otlp_max_attributes,
        max_events=settings.otlp_max_events,
        max_links=settings.otlp_max_links,
        max_attribute_key_length=settings.otlp_max_attribute_key_length,
        max_attribute_value_length=settings.otlp_max_attribute_value_length,
        max_metadata_bytes=settings.otlp_max_metadata_bytes,
        max_anyvalue_depth=settings.otlp_max_anyvalue_depth,
        max_anyvalue_items=settings.otlp_max_anyvalue_items,
    )
    try:
        events = decode_request(body, content_encoding=request.headers.get("content-encoding"), settings=decoder_settings)
        ingest_events(db, events, context.tenant_id, capture_content=settings.capture_content)
    except OTLPDecodeError as exc:
        db.rollback()
        return Response(status_code=413 if exc.limit else 400, content=b"invalid OTLP request")
    except IdempotencyConflict as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="event idempotency conflict") from exc
    return Response(content=success_response(), media_type="application/x-protobuf")


@router.get("/v1/traces", response_model=TraceListResponse)
def traces(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0), db: Session = Depends(db_session), context: AuthContext = Depends(require_scope("traces:read")), _rate: AuthContext = Depends(enforce_rate_limit("read", "read_rate_limit"))) -> TraceListResponse:
    rows, total = list_traces(db, context.tenant_id, limit, offset)
    return TraceListResponse(traces=[_trace(row) for row in rows], total=total)


@router.get("/v1/traces/{trace_id}", response_model=TraceDetailResponse)
def trace_detail(trace_id: str, db: Session = Depends(db_session), context: AuthContext = Depends(require_scope("traces:read")), _rate: AuthContext = Depends(enforce_rate_limit("read", "read_rate_limit"))) -> TraceDetailResponse:
    trace, spans = get_trace(db, trace_id, context.tenant_id)
    if trace is None:
        raise HTTPException(status_code=404, detail="trace not found")
    return TraceDetailResponse(trace=_trace(trace), spans=[_span(span) for span in spans],
                               span_tree=[_tree_node(node) for node in make_span_tree(spans)])


@router.get("/v1/traces/{trace_id}/integrity", response_model=IntegrityResponse, response_model_exclude_none=True)
def trace_integrity(trace_id: str, db: Session = Depends(db_session), context: AuthContext = Depends(require_scope("traces:read")), _rate: AuthContext = Depends(enforce_rate_limit("read", "read_rate_limit"))) -> IntegrityResponse:
    trace, _ = get_trace(db, trace_id, context.tenant_id)
    if trace is None:
        raise HTTPException(status_code=404, detail="trace not found")
    compacted = db.scalar(select(LedgerSegment).join(LedgerSegmentLifecycle).where(
        LedgerSegment.tenant_id == context.tenant_id, LedgerSegment.trace_id == trace_id,
        LedgerSegmentLifecycle.status == "COMPACTED").limit(1))
    if compacted is not None:
        try:
            store, keyring = _ledger_store_and_keyring()
            mixed = verify_mixed_ledger(db, tenant_id=context.tenant_id, trace_id=trace_id, store=store, keyring=keyring)
            return IntegrityResponse(trace_id=trace_id, status=mixed.status, events_checked=mixed.events_checked,
                                     chain_valid=mixed.status == "VALID", projection_consistent=mixed.status == "VALID",
                                     first_failure=mixed.first_failure)
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning("ledger_integrity_failed tenant_id=%s trace_id=%s reason=%s", context.tenant_id, trace_id, type(exc).__name__)
            return IntegrityResponse(trace_id=trace_id, status="SEGMENT_OBJECT_MISSING", events_checked=0,
                                     chain_valid=False, projection_consistent=False, first_failure="SEGMENT_OBJECT_MISSING")
    result = verify_trace_integrity(db, context.tenant_id, trace_id)
    return IntegrityResponse(**result.as_dict(trace_id))


def _replay_response(session: ReplaySession) -> ReplayResponse:
    return ReplayResponse(
        id=str(session.id), tenant_id=str(session.tenant_id), source_trace_id=session.source_trace_id,
        mode=session.mode, status=session.status, integrity_status=session.integrity_status,
        policy_version=session.policy_version, failure_reason=session.failure_reason,
        steps=[ReplayStepResponse(
            sequence=step.sequence, source_event_id=step.source_event_id, source_span_id=step.source_span_id,
            step_type=step.step_type, tool_name=step.tool_name, classification=step.classification,
            decision=step.decision, recorded_input_digest=step.recorded_input_digest,
            simulated_input_digest=step.simulated_input_digest, recorded_output_digest=step.recorded_output_digest,
            simulated_output_digest=step.simulated_output_digest, comparison_status=step.comparison_status,
            reason=step.reason,
        ) for step in session.steps]
    )


@router.post("/v1/traces/{trace_id}/replay", response_model=ReplayResponse)
def replay_trace(trace_id: str, request: ReplayRequest, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
                 db: Session = Depends(db_session), context: AuthContext = Depends(require_replay_access),
                 _rate: AuthContext = Depends(enforce_rate_limit("replay", "replay_rate_limit"))) -> ReplayResponse:
    if idempotency_key is not None and (not idempotency_key.strip() or len(idempotency_key) > 255):
        raise HTTPException(status_code=400, detail="invalid Idempotency-Key")
    if idempotency_key:
        existing = db.scalar(select(ReplaySession).where(
            ReplaySession.tenant_id == context.tenant_id, ReplaySession.idempotency_key == idempotency_key
        ))
        if existing is not None:
            return _replay_response(existing)
    trace, _ = get_trace(db, trace_id, context.tenant_id)
    if trace is None:
        raise HTTPException(status_code=404, detail="trace not found")
    try:
        plan = build_replay_plan(db, context.tenant_id, trace_id)
        session = persist_replay(db, tenant_id=context.tenant_id, plan=plan, idempotency_key=idempotency_key)
    except ReplayRefused as exc:
        session = persist_blocked_replay(db, tenant_id=context.tenant_id, trace_id=trace_id, reason=exc.reason,
                                         integrity_status=exc.integrity_status, idempotency_key=idempotency_key)
        return Response(content=ReplayResponse.model_validate(_replay_response(session)).model_dump_json(),
                        status_code=status.HTTP_409_CONFLICT, media_type="application/json")
    return _replay_response(session)


@router.get("/v1/replays/{replay_id}", response_model=ReplayResponse)
def replay_detail(replay_id: str, db: Session = Depends(db_session), context: AuthContext = Depends(require_scope("traces:read")),
                  _rate: AuthContext = Depends(enforce_rate_limit("read", "read_rate_limit"))) -> ReplayResponse:
    try:
        replay_uuid = __import__("uuid").UUID(replay_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="replay not found") from exc
    session = db.scalar(select(ReplaySession).where(ReplaySession.id == replay_uuid, ReplaySession.tenant_id == context.tenant_id))
    if session is None:
        raise HTTPException(status_code=404, detail="replay not found")
    return _replay_response(session)


def _analysis_response(run: Any) -> AnalysisResponse:
    return AnalysisResponse(
        id=str(run.id), tenant_id=str(run.tenant_id), trace_id=run.trace_id, status=run.status,
        taxonomy_version=run.taxonomy_version, analysis_version=run.analysis_version,
        provider=run.provider, model=run.model, policy_version=run.policy_version,
        deterministic_status=run.deterministic_status, ai_status=run.ai_status,
        failure_reason=run.failure_reason,
        findings=[AnalysisFindingResponse(
            detector_id=finding.detector_id, category=finding.category,
            root_cause_span_id=finding.root_cause_span_id, symptom_span_id=finding.symptom_span_id,
            severity=finding.severity, model_confidence=finding.model_confidence, source=finding.source,
            reason=finding.reason, recommended_next_step=finding.recommended_next_step,
            evidence_span_ids=list(finding.evidence_span_ids or []), evidence_event_ids=list(finding.evidence_event_ids or []),
            replay_ids=list(finding.replay_ids or []), primary_hypothesis=finding.primary_hypothesis,
        ) for finding in run.findings]
    )


def _suite_response(suite: EvaluationSuite) -> EvaluationSuiteResponse:
    return EvaluationSuiteResponse(id=suite.id, tenant_id=suite.tenant_id, name=suite.name,
                                   version=suite.version, created_at=suite.created_at,
                                   configuration=suite.configuration or {})


def _run_response(run: EvaluationRun) -> EvaluationRunResponse:
    return EvaluationRunResponse(
        id=run.id, tenant_id=run.tenant_id, suite_id=run.suite_id, variant=run.variant,
        agent_version=run.agent_version, prompt_version=run.prompt_version, model=run.model,
        environment=run.environment or {}, status=run.status, created_at=run.created_at,
        completed_at=run.completed_at,
        cases=[EvaluationCaseResponse(case_id=item.case_id, trace_id=item.trace_id, status=item.status,
                                      integrity_status=item.integrity_status, metrics=item.metrics or {})
               for item in run.cases],
    )


def _comparison_response(comparison: EvaluationComparison) -> EvaluationComparisonResponse:
    return EvaluationComparisonResponse(
        id=comparison.id, tenant_id=comparison.tenant_id, suite_id=comparison.suite_id,
        baseline_run_id=comparison.baseline_run_id, candidate_run_id=comparison.candidate_run_id,
        status=comparison.status, metrics=comparison.metrics or {}, reasons=list(comparison.reasons or []),
        case_diffs=list(comparison.case_diffs or []), rule_results=list(comparison.rule_results or []),
        decision=comparison.status, created_at=comparison.created_at,
    )


def _evaluation_error(exc: EvaluationValidationError) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc))


@router.post("/v1/evaluation-suites", response_model=EvaluationSuiteResponse, status_code=status.HTTP_201_CREATED)
def evaluation_suite_create(request: EvaluationSuiteCreate, db: Session = Depends(db_session),
                            context: AuthContext = Depends(require_evaluation_access("evaluations:manage")),
                            _rate: AuthContext = Depends(_evaluation_rate)) -> EvaluationSuiteResponse:
    try:
        suite = create_suite(db, context.tenant_id, request.name, request.version, request.configuration)
    except EvaluationValidationError as exc:
        db.rollback()
        raise _evaluation_error(exc) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="evaluation suite already exists") from exc
    return _suite_response(suite)


@router.get("/v1/evaluation-suites/{suite_id}", response_model=EvaluationSuiteResponse)
def evaluation_suite_detail(suite_id: UUID, db: Session = Depends(db_session),
                            context: AuthContext = Depends(require_evaluation_access("evaluations:read")),
                            _rate: AuthContext = Depends(_evaluation_rate)) -> EvaluationSuiteResponse:
    suite = db.scalar(select(EvaluationSuite).where(EvaluationSuite.id == suite_id,
                                                   EvaluationSuite.tenant_id == context.tenant_id))
    if suite is None:
        raise HTTPException(status_code=404, detail="evaluation suite not found")
    return _suite_response(suite)


@router.get("/v1/evaluation-suites", response_model=list[EvaluationSuiteResponse])
def evaluation_suite_list(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(db_session),
                          context: AuthContext = Depends(require_evaluation_access("evaluations:read")),
                          _rate: AuthContext = Depends(_evaluation_rate)) -> list[EvaluationSuiteResponse]:
    rows = db.scalars(select(EvaluationSuite).where(EvaluationSuite.tenant_id == context.tenant_id)
                      .order_by(EvaluationSuite.created_at.desc()).limit(limit)).all()
    return [_suite_response(row) for row in rows]


@router.post("/v1/evaluation-runs", response_model=EvaluationRunResponse, status_code=status.HTTP_201_CREATED)
def evaluation_run_create(request: EvaluationRunCreate, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
                          db: Session = Depends(db_session),
                          context: AuthContext = Depends(require_evaluation_access("evaluations:run")),
                          _rate: AuthContext = Depends(_evaluation_rate)) -> EvaluationRunResponse:
    if idempotency_key is not None and (not idempotency_key.strip() or len(idempotency_key) > 255):
        raise HTTPException(status_code=400, detail="invalid Idempotency-Key")
    if idempotency_key:
        existing = db.scalar(select(EvaluationRun).where(EvaluationRun.tenant_id == context.tenant_id,
                                                          EvaluationRun.idempotency_key == idempotency_key))
        if existing is not None:
            return _run_response(existing)
    suite = db.scalar(select(EvaluationSuite).where(EvaluationSuite.id == request.suite_id,
                                                     EvaluationSuite.tenant_id == context.tenant_id))
    if suite is None:
        raise HTTPException(status_code=404, detail="evaluation suite not found")
    try:
        run = create_run(db, context.tenant_id, suite=suite, variant=request.variant,
                          agent_version=request.agent_version, prompt_version=request.prompt_version,
                          model=request.model, environment=request.environment,
                          cases=[item.model_dump() for item in request.cases],
                          idempotency_key=idempotency_key, max_cases=get_settings().evaluation_max_cases)
    except EvaluationValidationError as exc:
        db.rollback()
        raise _evaluation_error(exc) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="evaluation run already exists") from exc
    return _run_response(run)


@router.get("/v1/evaluation-runs/{run_id}", response_model=EvaluationRunResponse)
def evaluation_run_detail(run_id: UUID, db: Session = Depends(db_session),
                          context: AuthContext = Depends(require_evaluation_access("evaluations:read")),
                          _rate: AuthContext = Depends(_evaluation_rate)) -> EvaluationRunResponse:
    run = db.scalar(select(EvaluationRun).where(EvaluationRun.id == run_id, EvaluationRun.tenant_id == context.tenant_id))
    if run is None:
        raise HTTPException(status_code=404, detail="evaluation run not found")
    return _run_response(run)


@router.get("/v1/evaluation-runs", response_model=list[EvaluationRunResponse])
def evaluation_run_list(limit: int = Query(100, ge=1, le=1000), suite_id: UUID | None = Query(default=None),
                        db: Session = Depends(db_session),
                        context: AuthContext = Depends(require_evaluation_access("evaluations:read")),
                        _rate: AuthContext = Depends(_evaluation_rate)) -> list[EvaluationRunResponse]:
    query = select(EvaluationRun).where(EvaluationRun.tenant_id == context.tenant_id)
    if suite_id is not None:
        query = query.where(EvaluationRun.suite_id == suite_id)
    rows = db.scalars(query.order_by(EvaluationRun.created_at.desc()).limit(limit)).all()
    return [_run_response(row) for row in rows]


@router.post("/v1/evaluation-comparisons", response_model=EvaluationComparisonResponse, status_code=status.HTTP_201_CREATED)
def evaluation_comparison_create(request: EvaluationComparisonCreate,
                                 idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
                                 db: Session = Depends(db_session),
                                 context: AuthContext = Depends(require_evaluation_access("evaluations:run")),
                                 _rate: AuthContext = Depends(_evaluation_rate)) -> EvaluationComparisonResponse:
    if idempotency_key is not None and (not idempotency_key.strip() or len(idempotency_key) > 255):
        raise HTTPException(status_code=400, detail="invalid Idempotency-Key")
    if idempotency_key:
        existing = db.scalar(select(EvaluationComparison).where(EvaluationComparison.tenant_id == context.tenant_id,
                                                                 EvaluationComparison.idempotency_key == idempotency_key))
        if existing is not None:
            return _comparison_response(existing)
    suite = db.scalar(select(EvaluationSuite).where(EvaluationSuite.id == request.suite_id,
                                                     EvaluationSuite.tenant_id == context.tenant_id))
    baseline = db.scalar(select(EvaluationRun).where(EvaluationRun.id == request.baseline_run_id,
                                                      EvaluationRun.tenant_id == context.tenant_id))
    candidate = db.scalar(select(EvaluationRun).where(EvaluationRun.id == request.candidate_run_id,
                                                       EvaluationRun.tenant_id == context.tenant_id))
    if suite is None or baseline is None or candidate is None:
        raise HTTPException(status_code=404, detail="evaluation input not found")
    if baseline.suite_id != suite.id or candidate.suite_id != suite.id or baseline.variant != "baseline" or candidate.variant != "candidate":
        raise HTTPException(status_code=422, detail="evaluation runs do not match suite variants")
    try:
        comparison = compare_runs(db, context.tenant_id, suite=suite, baseline_run=baseline,
                                  candidate_run=candidate, idempotency_key=idempotency_key)
    except EvaluationValidationError as exc:
        db.rollback()
        raise _evaluation_error(exc) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="evaluation comparison already exists") from exc
    return _comparison_response(comparison)


@router.get("/v1/evaluation-comparisons/{comparison_id}", response_model=EvaluationComparisonResponse)
def evaluation_comparison_detail(comparison_id: UUID, db: Session = Depends(db_session),
                                 context: AuthContext = Depends(require_evaluation_access("evaluations:read")),
                                 _rate: AuthContext = Depends(_evaluation_rate)) -> EvaluationComparisonResponse:
    comparison = db.scalar(select(EvaluationComparison).where(EvaluationComparison.id == comparison_id,
                                                               EvaluationComparison.tenant_id == context.tenant_id))
    if comparison is None:
        raise HTTPException(status_code=404, detail="evaluation comparison not found")
    return _comparison_response(comparison)


@router.get("/v1/evaluation-comparisons", response_model=list[EvaluationComparisonResponse])
def evaluation_comparison_list(limit: int = Query(100, ge=1, le=1000), suite_id: UUID | None = Query(default=None),
                               db: Session = Depends(db_session),
                               context: AuthContext = Depends(require_evaluation_access("evaluations:read")),
                               _rate: AuthContext = Depends(_evaluation_rate)) -> list[EvaluationComparisonResponse]:
    query = select(EvaluationComparison).where(EvaluationComparison.tenant_id == context.tenant_id)
    if suite_id is not None:
        query = query.where(EvaluationComparison.suite_id == suite_id)
    rows = db.scalars(query.order_by(EvaluationComparison.created_at.desc()).limit(limit)).all()
    return [_comparison_response(row) for row in rows]


@router.post("/v1/traces/{trace_id}/analysis", response_model=AnalysisResponse)
def analyze_trace_route(trace_id: str, request: AnalysisRequest, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
                        db: Session = Depends(db_session), context: AuthContext = Depends(require_analysis_access),
                        _rate: AuthContext = Depends(enforce_rate_limit("analysis", "analysis_rate_limit"))) -> AnalysisResponse:
    if idempotency_key is not None and (not idempotency_key.strip() or len(idempotency_key) > 255):
        raise HTTPException(status_code=400, detail="invalid Idempotency-Key")
    if idempotency_key:
        existing = db.scalar(select(AnalysisRun).where(
            AnalysisRun.tenant_id == context.tenant_id, AnalysisRun.idempotency_key == idempotency_key
        ))
        if existing is not None:
            return _analysis_response(existing)
    trace, _ = get_trace(db, trace_id, context.tenant_id)
    if trace is None:
        raise HTTPException(status_code=404, detail="trace not found")
    try:
        report, _packet = analyze_trace(db, context.tenant_id, trace_id, mode=request.mode)
        run = persist_analysis(db, tenant_id=context.tenant_id, report=report, mode=request.mode, idempotency_key=idempotency_key)
        # V10 is a derived projection. Only persisted deterministic V5
        # findings can create incidents; the source evidence remains read-only.
        incidents = process_analysis_findings(db, context.tenant_id, run)
        for incident in incidents:
            latest = db.scalar(select(IncidentEvent).where(IncidentEvent.tenant_id == context.tenant_id,
                IncidentEvent.incident_id == incident.id).order_by(IncidentEvent.created_at.desc()).limit(1))
            event_map = {"CREATED": "INCIDENT_CREATED", "REOPENED": "INCIDENT_REOPENED", "SEVERITY_INCREASED": "SEVERITY_INCREASED"}
            if latest is not None and latest.event_type in event_map:
                _queue_incident_notification(db, incident, event_map[latest.event_type])
    except AnalysisRefused as exc:
        run = persist_refused_analysis(db, tenant_id=context.tenant_id, trace_id=trace_id,
                                       reason=exc.reason, idempotency_key=idempotency_key)
        return Response(content=_analysis_response(run).model_dump_json(), status_code=status.HTTP_409_CONFLICT,
                        media_type="application/json")
    except AnalysisResourceLimit as exc:
        raise HTTPException(status_code=413, detail="analysis resource limit") from exc
    return _analysis_response(run)


@router.get("/v1/analyses/{analysis_id}", response_model=AnalysisResponse)
def analysis_detail(analysis_id: str, db: Session = Depends(db_session), context: AuthContext = Depends(require_scope("traces:read")),
                    _rate: AuthContext = Depends(enforce_rate_limit("read", "read_rate_limit"))) -> AnalysisResponse:
    try:
        analysis_uuid = __import__("uuid").UUID(analysis_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="analysis not found") from exc
    run = db.scalar(select(AnalysisRun).where(AnalysisRun.id == analysis_uuid, AnalysisRun.tenant_id == context.tenant_id))
    if run is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return _analysis_response(run)


@router.get("/v1/incidents", response_model=list[IncidentSummaryResponse])
def incident_list(status_filter: str | None = Query(default=None, alias="status"),
                  severity: str | None = Query(default=None), category: str | None = Query(default=None),
                  since_minutes: int | None = Query(default=None, ge=5, le=10080),
                  workflow: str | None = Query(default=None, max_length=96),
                  agent_version: str | None = Query(default=None, max_length=96),
                  limit: int = Query(default=100, ge=1, le=100), offset: int = Query(default=0, ge=0, le=100000),
                  db: Session = Depends(db_session), context: AuthContext = Depends(require_scope("incidents:read")),
                  _rate: AuthContext = Depends(_incident_rate)) -> list[IncidentSummaryResponse]:
    query = select(Incident).where(Incident.tenant_id == context.tenant_id)
    if status_filter:
        value = status_filter.upper()
        if value not in {IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED, IncidentStatus.RESOLVED}:
            raise HTTPException(status_code=422, detail="invalid incident status filter")
        query = query.where(Incident.status == value)
    if severity:
        value = severity.upper()
        if value not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise HTTPException(status_code=422, detail="invalid incident severity filter")
        query = query.where(Incident.severity == value)
    if category:
        query = query.where(Incident.primary_category == category.upper()[:64])
    if since_minutes is not None:
        from datetime import datetime, timedelta, timezone
        query = query.where(Incident.last_seen_at >= datetime.now(timezone.utc) - timedelta(minutes=since_minutes))
    if workflow or agent_version:
        # Dimensions are JSONB in PostgreSQL; use a bounded occurrence join so
        # this filter never exposes another tenant's projection.
        query = query.join(IncidentOccurrence, IncidentOccurrence.incident_id == Incident.id).where(
            IncidentOccurrence.tenant_id == context.tenant_id)
        if workflow:
            query = query.where(IncidentOccurrence.workflow_name == workflow)
        if agent_version:
            query = query.where(IncidentOccurrence.agent_version == agent_version)
        query = query.distinct()
    rows = db.scalars(query.order_by(Incident.last_seen_at.desc()).offset(offset).limit(limit)).all()
    return [_incident_summary(db, row) for row in rows]


@router.get("/v1/incidents/{incident_id}", response_model=IncidentDetailResponse)
def incident_detail(incident_id: UUID, db: Session = Depends(db_session),
                    context: AuthContext = Depends(require_scope("incidents:read")),
                    _rate: AuthContext = Depends(_incident_rate)) -> IncidentDetailResponse:
    incident = db.scalar(select(Incident).where(Incident.id == incident_id, Incident.tenant_id == context.tenant_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return _incident_detail(db, incident)


def _change_incident(incident_id: UUID, target: str, db: Session, context: AuthContext) -> IncidentDetailResponse:
    try:
        incident = transition_incident(db, context.tenant_id, incident_id, target,
                                       actor_type="api_key", actor_id=context.public_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="incident not found") from exc
    except IncidentTransitionError as exc:
        raise HTTPException(status_code=409, detail="invalid incident transition") from exc
    if target == IncidentStatus.RESOLVED:
        _queue_incident_notification(db, incident, "INCIDENT_RESOLVED")
    elif target == IncidentStatus.OPEN:
        _queue_incident_notification(db, incident, "INCIDENT_REOPENED")
    return _incident_detail(db, incident)


@router.post("/v1/incidents/{incident_id}/acknowledge", response_model=IncidentDetailResponse)
def incident_acknowledge(incident_id: UUID, db: Session = Depends(db_session),
                         context: AuthContext = Depends(require_scope("incidents:manage"))) -> IncidentDetailResponse:
    return _change_incident(incident_id, IncidentStatus.ACKNOWLEDGED, db, context)


@router.post("/v1/incidents/{incident_id}/resolve", response_model=IncidentDetailResponse)
def incident_resolve(incident_id: UUID, db: Session = Depends(db_session),
                     context: AuthContext = Depends(require_scope("incidents:manage"))) -> IncidentDetailResponse:
    return _change_incident(incident_id, IncidentStatus.RESOLVED, db, context)


@router.post("/v1/incidents/{incident_id}/reopen", response_model=IncidentDetailResponse)
def incident_reopen(incident_id: UUID, db: Session = Depends(db_session),
                    context: AuthContext = Depends(require_scope("incidents:manage"))) -> IncidentDetailResponse:
    return _change_incident(incident_id, IncidentStatus.OPEN, db, context)


def _destination_response(row: NotificationDestination) -> NotificationDestinationResponse:
    return NotificationDestinationResponse.model_validate(row, from_attributes=True)


def _policy_response(row: AlertPolicy) -> AlertPolicyResponse:
    return AlertPolicyResponse.model_validate(row, from_attributes=True)


@router.post("/v1/notification-destinations", response_model=NotificationDestinationResponse, status_code=status.HTTP_201_CREATED)
def notification_destination_create(request: NotificationDestinationCreate, db: Session = Depends(db_session),
                                    context: AuthContext = Depends(require_scope("notifications:manage"))) -> NotificationDestinationResponse:
    try:
        return _destination_response(create_destination(db, context.tenant_id, name=request.name, url=request.url,
                                                        signing_secret_reference=request.signing_secret_reference,
                                                        enabled=request.enabled))
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail="invalid notification destination") from exc


@router.get("/v1/notification-destinations", response_model=list[NotificationDestinationResponse])
def notification_destination_list(db: Session = Depends(db_session),
                                  context: AuthContext = Depends(require_scope("notifications:read"))) -> list[NotificationDestinationResponse]:
    rows = db.scalars(select(NotificationDestination).where(NotificationDestination.tenant_id == context.tenant_id).order_by(NotificationDestination.created_at.desc()).limit(100)).all()
    return [_destination_response(row) for row in rows]


@router.patch("/v1/notification-destinations/{destination_id}", response_model=NotificationDestinationResponse)
def notification_destination_update(destination_id: UUID, request: NotificationDestinationUpdate,
                                    db: Session = Depends(db_session), context: AuthContext = Depends(require_scope("notifications:manage"))) -> NotificationDestinationResponse:
    row = db.scalar(select(NotificationDestination).where(NotificationDestination.id == destination_id,
                                                           NotificationDestination.tenant_id == context.tenant_id))
    if row is None:
        raise HTTPException(status_code=404, detail="notification destination not found")
    if request.url is not None:
        try:
            from agentguard_server.services.notifications import validate_webhook_url
            settings = get_settings()
            target = validate_webhook_url(request.url, allow_private_test=settings.allow_private_webhook_tests,
                environment=settings.environment, allowed_hosts={item.strip() for item in (settings.notification_allowed_webhook_hosts or "").split(",") if item.strip()} or None)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="invalid notification destination") from exc
        row.endpoint_scheme, row.endpoint_host, row.endpoint_port, row.endpoint_path = target.scheme, target.host, target.port, target.path
    if request.name is not None: row.name = request.name.strip()
    if request.signing_secret_reference is not None: row.signing_secret_reference = request.signing_secret_reference
    if request.enabled is not None: row.enabled = request.enabled
    from datetime import datetime, timezone
    row.updated_at = datetime.now(timezone.utc)
    db.commit(); db.refresh(row)
    return _destination_response(row)


@router.post("/v1/alert-policies", response_model=AlertPolicyResponse, status_code=status.HTTP_201_CREATED)
def alert_policy_create(request: AlertPolicyCreate, db: Session = Depends(db_session),
                        context: AuthContext = Depends(require_scope("notifications:manage"))) -> AlertPolicyResponse:
    try:
        return _policy_response(create_policy(db, context.tenant_id, name=request.name,
            minimum_severity=request.minimum_severity, incident_status_filter=request.incident_status_filter,
            failure_categories=request.failure_categories, event_types=request.event_types,
            cooldown_seconds=request.cooldown_seconds, enabled=request.enabled))
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail="invalid alert policy") from exc


@router.get("/v1/alert-policies", response_model=list[AlertPolicyResponse])
def alert_policy_list(db: Session = Depends(db_session),
                      context: AuthContext = Depends(require_scope("notifications:read"))) -> list[AlertPolicyResponse]:
    rows = db.scalars(select(AlertPolicy).where(AlertPolicy.tenant_id == context.tenant_id).order_by(AlertPolicy.created_at.desc()).limit(100)).all()
    return [_policy_response(row) for row in rows]


@router.patch("/v1/alert-policies/{policy_id}", response_model=AlertPolicyResponse)
def alert_policy_update(policy_id: UUID, request: AlertPolicyUpdate, db: Session = Depends(db_session),
                        context: AuthContext = Depends(require_scope("notifications:manage"))) -> AlertPolicyResponse:
    row = db.scalar(select(AlertPolicy).where(AlertPolicy.id == policy_id, AlertPolicy.tenant_id == context.tenant_id))
    if row is None:
        raise HTTPException(status_code=404, detail="alert policy not found")
    for field in ("name", "minimum_severity", "cooldown_seconds", "enabled"):
        value = getattr(request, field)
        if value is not None: setattr(row, field, value.strip() if isinstance(value, str) else value)
    for field in ("incident_status_filter", "failure_categories", "event_types"):
        value = getattr(request, field)
        if value is not None: setattr(row, field, [str(item).upper() for item in value])
    row.policy_version += 1
    from datetime import datetime, timezone
    row.updated_at = datetime.now(timezone.utc)
    db.commit(); db.refresh(row)
    return _policy_response(row)


@router.get("/v1/notification-deliveries", response_model=list[NotificationDeliveryResponse])
def notification_delivery_list(limit: int = Query(default=100, ge=1, le=100), db: Session = Depends(db_session),
                               context: AuthContext = Depends(require_scope("notifications:read"))) -> list[NotificationDeliveryResponse]:
    rows = db.scalars(select(NotificationDelivery).where(NotificationDelivery.tenant_id == context.tenant_id)
                      .order_by(NotificationDelivery.created_at.desc()).limit(limit)).all()
    return [NotificationDeliveryResponse.model_validate(row, from_attributes=True) for row in rows]


@router.get("/v1/notification-deliveries/{delivery_id}", response_model=NotificationDeliveryResponse)
def notification_delivery_detail(delivery_id: UUID, db: Session = Depends(db_session),
                                 context: AuthContext = Depends(require_scope("notifications:read"))) -> NotificationDeliveryResponse:
    row = db.scalar(select(NotificationDelivery).where(NotificationDelivery.id == delivery_id,
                                                        NotificationDelivery.tenant_id == context.tenant_id))
    if row is None:
        raise HTTPException(status_code=404, detail="notification delivery not found")
    return NotificationDeliveryResponse.model_validate(row, from_attributes=True)


@router.post("/v1/notification-deliveries/{delivery_id}/dispatch", response_model=NotificationDeliveryResponse)
def notification_delivery_dispatch(delivery_id: UUID, db: Session = Depends(db_session),
                                   context: AuthContext = Depends(require_scope("notifications:manage"))) -> NotificationDeliveryResponse:
    row = db.scalar(select(NotificationDelivery).where(NotificationDelivery.id == delivery_id,
                                                        NotificationDelivery.tenant_id == context.tenant_id))
    if row is None:
        raise HTTPException(status_code=404, detail="notification delivery not found")
    try:
        return NotificationDeliveryResponse.model_validate(dispatch_delivery(db, row.id), from_attributes=True)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail="notification destination is not permitted") from exc

@router.get("/v1/integrity/checkpoints", response_model=list[CheckpointResponse])
def integrity_checkpoint_list(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(db_session),
                              _context: AuthContext = Depends(require_scope("integrity:read"))) -> list[CheckpointResponse]:
    rows = list(db.scalars(select(IntegrityCheckpoint).order_by(IntegrityCheckpoint.checkpoint_sequence.desc()).limit(limit)))
    return [_anchor_checkpoint_response(row, None) for row in rows]


def _anchor_checkpoint_response(row: IntegrityCheckpoint, verification: dict[str, Any] | None) -> CheckpointResponse:
    return CheckpointResponse(id=row.id, namespace=row.namespace, checkpoint_sequence=row.checkpoint_sequence,
        checkpoint_version=row.checkpoint_version, manifest_digest=row.manifest_digest,
        previous_checkpoint_digest=row.previous_checkpoint_digest, checkpoint_digest=row.checkpoint_digest,
        entry_count=row.entry_count, created_at=row.created_at, verification=verification)


@router.get("/v1/integrity/checkpoints/{checkpoint_id}", response_model=CheckpointResponse)
def integrity_checkpoint_detail(checkpoint_id: UUID, db: Session = Depends(db_session),
                                _context: AuthContext = Depends(require_scope("integrity:read"))) -> CheckpointResponse:
    row = db.get(IntegrityCheckpoint, checkpoint_id)
    if row is None: raise HTTPException(status_code=404, detail="checkpoint not found")
    return _anchor_checkpoint_response(row, verify_checkpoint(db, row.id))


@router.post("/v1/integrity/checkpoints", response_model=CheckpointResponse, status_code=status.HTTP_201_CREATED)
def integrity_checkpoint_create(request: CheckpointCreate, db: Session = Depends(db_session),
                                _context: AuthContext = Depends(require_scope("integrity:anchor"))) -> CheckpointResponse:
    try: row = create_checkpoint(db, force=request.force)
    except (ValueError, RuntimeError) as exc:
        db.rollback(); raise HTTPException(status_code=409, detail="checkpoint could not be created") from exc
    if row is None: raise HTTPException(status_code=409, detail="checkpoint is not due or backlog is bounded")
    return _anchor_checkpoint_response(row, verify_checkpoint(db, row.id))


@router.post("/v1/integrity/checkpoints/{checkpoint_id}/verify", response_model=dict[str, Any])
def integrity_checkpoint_verify(checkpoint_id: UUID, db: Session = Depends(db_session),
                                _context: AuthContext = Depends(require_scope("integrity:read"))) -> dict[str, Any]:
    try: return verify_checkpoint(db, checkpoint_id)
    except LookupError as exc: raise HTTPException(status_code=404, detail="checkpoint not found") from exc


@router.post("/v1/integrity/checkpoints/{checkpoint_id}/anchor", response_model=dict[str, Any])
def integrity_checkpoint_anchor(checkpoint_id: UUID, db: Session = Depends(db_session),
                                _context: AuthContext = Depends(require_scope("integrity:anchor"))) -> dict[str, Any]:
    settings = get_settings()
    if not settings.anchor_enabled: raise HTTPException(status_code=503, detail="external anchoring is disabled")
    row = db.get(IntegrityCheckpoint, checkpoint_id)
    if row is None: raise HTTPException(status_code=404, detail="checkpoint not found")
    job = db.scalar(select(IntegrityAnchorJob).where(IntegrityAnchorJob.checkpoint_id == row.id))
    if job is None:
        now = datetime.now(timezone.utc)
        job = IntegrityAnchorJob(checkpoint_id=row.id, status="PENDING", created_at=now, updated_at=now)
        db.add(job); db.commit(); db.refresh(job)
    try: result = anchor_job(db, job.id, HttpSignedWitnessProvider(settings))
    except Exception as exc:
        logger.error("anchor_submission_failed checkpoint_id=%s reason=%s", checkpoint_id, type(exc).__name__)
        raise HTTPException(status_code=503, detail="witness unavailable") from exc
    return {"job_id": str(result.id), "status": result.status, "failure_category": result.last_failure_category}


@router.get("/v1/integrity/anchor-status", response_model=AnchorStatusResponse)
def integrity_anchor_status(db: Session = Depends(db_session),
                            _context: AuthContext = Depends(require_scope("integrity:read"))) -> AnchorStatusResponse:
    settings = get_settings(); latest = db.scalar(select(IntegrityCheckpoint).where(
        IntegrityCheckpoint.namespace == settings.anchor_namespace).order_by(IntegrityCheckpoint.checkpoint_sequence.desc()).limit(1))
    verification = verify_checkpoint(db, latest.id) if latest else {"status": "NOT_ANCHORED"}
    fresh = freshness(db)
    receipt = db.scalar(select(ExternalAnchorReceipt).where(
        ExternalAnchorReceipt.namespace == settings.anchor_namespace).order_by(ExternalAnchorReceipt.received_at.desc()).limit(1))
    return AnchorStatusResponse(namespace=settings.anchor_namespace,
        latest_checkpoint_sequence=latest.checkpoint_sequence if latest else None,
        latest_checkpoint_at=latest.created_at if latest else None,
        last_successful_anchor_at=receipt.received_at if receipt else None,
        verification_status=verification.get("status", "NOT_ANCHORED"), freshness=fresh["status"],
        signer_key_id=receipt.signer_key_id if receipt else None)


@router.get("/v1/integrity/remote-continuity", response_model=ContinuityResponse)
def integrity_remote_continuity(db: Session = Depends(db_session),
                                _context: AuthContext = Depends(require_scope("integrity:read"))) -> ContinuityResponse:
    settings = get_settings()
    if not settings.anchor_enabled: raise HTTPException(status_code=503, detail="external anchoring is disabled")
    result = remote_continuity(db, HttpSignedWitnessProvider(settings))
    return ContinuityResponse(**result.as_dict())


@router.get("/v1/integrity/witnesses", response_model=list[dict[str, Any]])
def integrity_witnesses(db: Session = Depends(db_session),
                        _context: AuthContext = Depends(require_scope("integrity:read"))) -> list[dict[str, Any]]:
    rows = list(db.scalars(select(Witness).where(Witness.enabled.is_(True)).order_by(Witness.witness_id)))
    return [{"witness_id": row.witness_id, "display_name": row.display_name,
             "verification_key_id": row.verification_key_id, "enabled": row.enabled,
             "endpoint_config_ref": row.endpoint_config_ref} for row in rows]


@router.get("/v1/integrity/quorum", response_model=dict[str, Any])
def integrity_quorum(db: Session = Depends(db_session),
                     _context: AuthContext = Depends(require_scope("integrity:read"))) -> dict[str, Any]:
    checkpoint = db.scalar(select(IntegrityCheckpoint).order_by(IntegrityCheckpoint.checkpoint_sequence.desc()).limit(1))
    if checkpoint is None or checkpoint.policy_epoch is None:
        return {"state": "QUORUM_POLICY_INVALID", "detail": "no V20 policy-bound checkpoint"}
    result = evaluate_checkpoint_quorum(db, checkpoint.id)
    return {"checkpoint_id": str(checkpoint.id), **result.as_dict()}


@router.get("/v1/integrity/quorum/{checkpoint_id}", response_model=dict[str, Any])
def integrity_quorum_detail(checkpoint_id: UUID, db: Session = Depends(db_session),
                            _context: AuthContext = Depends(require_scope("integrity:read"))) -> dict[str, Any]:
    try:
        result = evaluate_checkpoint_quorum(db, checkpoint_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="checkpoint not found") from exc
    return {"checkpoint_id": str(checkpoint_id), **result.as_dict()}


@router.get("/v1/integrity/witness-health", response_model=list[dict[str, Any]])
def integrity_witness_health(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(db_session),
                             _context: AuthContext = Depends(require_scope("integrity:read"))) -> list[dict[str, Any]]:
    rows = list(db.scalars(select(WitnessHealthSnapshot).order_by(WitnessHealthSnapshot.observed_at.desc()).limit(limit)))
    return [{"witness_id": row.witness_id, "policy_epoch": row.policy_epoch,
             "health_state": row.health_state, "observed_at": row.observed_at,
             "detail_code": row.detail_code} for row in rows]


def _ledger_response(row: LedgerSegment, db: Session) -> LedgerSegmentResponse:
    lifecycle = db.get(LedgerSegmentLifecycle, row.id)
    return LedgerSegmentResponse(
        id=row.id, tenant_id=row.tenant_id, trace_id=row.trace_id,
        segment_sequence=row.segment_sequence, segment_version=row.segment_version,
        start_event_sequence=row.start_event_sequence, end_event_sequence=row.end_event_sequence,
        start_previous_hash=row.start_previous_hash, end_event_hash=row.end_event_hash,
        event_count=row.event_count, events_manifest_digest=row.events_manifest_digest,
        segment_manifest_digest=row.segment_manifest_digest, archive_plaintext_sha256=row.archive_plaintext_sha256,
        archive_ciphertext_sha256=row.archive_ciphertext_sha256, archive_object_key=row.archive_object_key,
        covering_checkpoint_sequence=row.covering_checkpoint_sequence, covering_checkpoint_digest=row.covering_checkpoint_digest,
        created_at=row.created_at, archived_verified_at=row.archived_verified_at,
        status=lifecycle.status if lifecycle else "UNKNOWN",
    )


def _ledger_store_and_keyring() -> tuple[S3ArchiveStore, ArchiveKeyring]:
    settings = get_settings()
    try:
        store = archive_store_registry(settings) if settings.archive_replication_enabled else S3ArchiveStore(settings)
        return store, ArchiveKeyring.from_settings(settings)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="ledger archive storage is unavailable") from exc


@router.get("/v1/integrity/ledger/segments", response_model=list[LedgerSegmentResponse])
def ledger_segment_list(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(db_session),
                        context: AuthContext = Depends(require_scope("integrity:read"))) -> list[LedgerSegmentResponse]:
    rows = list(db.scalars(select(LedgerSegment).where(LedgerSegment.tenant_id == context.tenant_id)
                           .order_by(LedgerSegment.segment_sequence.desc()).limit(limit)))
    return [_ledger_response(row, db) for row in rows]


@router.get("/v1/integrity/ledger/segments/{segment_id}", response_model=LedgerSegmentResponse)
def ledger_segment_detail(segment_id: UUID, db: Session = Depends(db_session),
                          context: AuthContext = Depends(require_scope("integrity:read"))) -> LedgerSegmentResponse:
    row = db.scalar(select(LedgerSegment).where(LedgerSegment.id == segment_id, LedgerSegment.tenant_id == context.tenant_id))
    if row is None:
        raise HTTPException(status_code=404, detail="ledger segment not found")
    return _ledger_response(row, db)


@router.post("/v1/integrity/ledger/segments", response_model=LedgerSegmentResponse, status_code=status.HTTP_201_CREATED)
def ledger_segment_create(trace_id: str, db: Session = Depends(db_session),
                          context: AuthContext = Depends(require_scope("ledger:compact"))) -> LedgerSegmentResponse:
    try:
        row = create_ledger_segment_candidate(db, tenant_id=context.tenant_id, trace_id=trace_id)
    except LedgerError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=exc.reason if hasattr(exc, "reason") else str(exc)) from exc
    return _ledger_response(row, db)


@router.post("/v1/integrity/ledger/segments/{segment_id}/verify", response_model=LedgerVerificationResponse)
def ledger_segment_verify(segment_id: UUID, db: Session = Depends(db_session),
                          context: AuthContext = Depends(require_scope("integrity:read"))) -> LedgerVerificationResponse:
    row = db.scalar(select(LedgerSegment).where(LedgerSegment.id == segment_id, LedgerSegment.tenant_id == context.tenant_id))
    if row is None:
        raise HTTPException(status_code=404, detail="ledger segment not found")
    store, keyring = _ledger_store_and_keyring()
    result = verify_mixed_ledger(db, tenant_id=row.tenant_id, trace_id=row.trace_id, store=store, keyring=keyring)
    return LedgerVerificationResponse(segment_id=row.id, verification=result.as_dict())


@router.post("/v1/integrity/ledger/compact", response_model=dict[str, Any], status_code=status.HTTP_202_ACCEPTED)
def ledger_compact(request: LedgerCompactRequest, db: Session = Depends(db_session),
                   context: AuthContext = Depends(require_scope("ledger:compact"))) -> dict[str, Any]:
    row = db.scalar(select(LedgerSegment).where(LedgerSegment.id == request.segment_id,
                                                LedgerSegment.tenant_id == context.tenant_id))
    if row is None:
        raise HTTPException(status_code=404, detail="ledger segment not found")
    try:
        job = queue_ledger_compaction(db, segment_id=row.id, tenant_id=context.tenant_id)
    except LedgerError as exc:
        db.rollback(); raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"job_id": str(job.id), "segment_id": str(row.id), "status": job.status,
            "message": "compaction is performed only by the dedicated ledger compactor"}


@router.get("/v1/integrity/events/{event_id}", response_model=LedgerEventLookup)
def ledger_event_lookup(event_id: str, trace_id: str, db: Session = Depends(db_session),
                        context: AuthContext = Depends(require_scope("integrity:read"))) -> LedgerEventLookup:
    store, keyring = _ledger_store_and_keyring()
    try:
        event = lookup_ledger_event(db, tenant_id=context.tenant_id, trace_id=trace_id, event_id=event_id,
                                    store=store, keyring=keyring)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="ledger event not found") from exc
    except LedgerVerificationError as exc:
        raise HTTPException(status_code=503, detail=exc.status) from exc
    return LedgerEventLookup(tenant_id=context.tenant_id, trace_id=trace_id, event_id=str(event["event_id"]),
                             event_sequence=int(event["sequence"]), event_hash=str(event["event_digest"]),
                             source="ledger-segment", evidence=dict(event))


def _integrity_store_and_keyring() -> tuple[Any, ArchiveKeyring]:
    settings = get_settings()
    try:
        bindings = archive_store_registry(settings)
        binding = bindings.get(settings.archive_primary_store_id)
        if binding is None or not binding.write_enabled:
            raise RuntimeError("primary archive store is not writable")
        return binding.store, ArchiveKeyring.from_settings(settings)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="integrity segment storage is unavailable") from exc


def _integrity_segment_response(row: IntegrityArchiveSegment) -> IntegritySegmentResponse:
    return IntegritySegmentResponse.model_validate(row, from_attributes=True)


@router.get("/v1/integrity/segments", response_model=list[IntegritySegmentResponse])
def integrity_segment_list(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(db_session),
                           context: AuthContext = Depends(require_scope("integrity:read"))) -> list[IntegritySegmentResponse]:
    rows = list(db.scalars(select(IntegrityArchiveSegment).where(IntegrityArchiveSegment.tenant_id == context.tenant_id)
                           .order_by(IntegrityArchiveSegment.segment_sequence.desc()).limit(limit)))
    return [_integrity_segment_response(row) for row in rows]


@router.post("/v1/integrity/segments/plan", response_model=IntegritySegmentResponse, status_code=status.HTTP_201_CREATED)
def integrity_segment_plan(request: IntegritySegmentPlanRequest, db: Session = Depends(db_session),
                           context: AuthContext = Depends(require_scope("integrity:compact"))) -> IntegritySegmentResponse:
    try:
        row = create_integrity_segment_candidate(db, tenant_id=context.tenant_id, trace_id=request.trace_id)
    except IntegritySegmentEligibilityError as exc:
        db.rollback(); raise HTTPException(status_code=409, detail=exc.reason) from exc
    return _integrity_segment_response(row)


@router.get("/v1/integrity/segments/{segment_id}", response_model=IntegritySegmentResponse)
def integrity_segment_detail(segment_id: UUID, db: Session = Depends(db_session),
                              context: AuthContext = Depends(require_scope("integrity:read"))) -> IntegritySegmentResponse:
    row = db.scalar(select(IntegrityArchiveSegment).where(IntegrityArchiveSegment.id == segment_id,
                                                          IntegrityArchiveSegment.tenant_id == context.tenant_id))
    if row is None:
        raise HTTPException(status_code=404, detail="integrity segment not found")
    return _integrity_segment_response(row)


@router.post("/v1/integrity/segments/{segment_id}/archive", response_model=IntegritySegmentActionResponse)
def integrity_segment_archive(segment_id: UUID, db: Session = Depends(db_session),
                              context: AuthContext = Depends(require_scope("integrity:compact"))) -> IntegritySegmentActionResponse:
    row = db.scalar(select(IntegrityArchiveSegment).where(IntegrityArchiveSegment.id == segment_id,
                                                          IntegrityArchiveSegment.tenant_id == context.tenant_id))
    if row is None: raise HTTPException(status_code=404, detail="integrity segment not found")
    store, keyring = _integrity_store_and_keyring()
    try:
        archived = archive_integrity_segment(db, row.id, store, provider=HttpSignedWitnessProvider(get_settings()), keyring=keyring)
    except IntegritySegmentEligibilityError as exc:
        db.rollback(); raise HTTPException(status_code=409, detail=exc.reason) from exc
    except IntegritySegmentVerificationError as exc:
        db.rollback(); raise HTTPException(status_code=503, detail=exc.status) from exc
    return IntegritySegmentActionResponse(segment_id=archived.id, status=archived.state, records=archived.record_count)


@router.post("/v1/integrity/segments/{segment_id}/authorize", response_model=IntegritySegmentActionResponse)
def integrity_segment_authorize(segment_id: UUID, db: Session = Depends(db_session),
                                context: AuthContext = Depends(require_scope("integrity:compact"))) -> IntegritySegmentActionResponse:
    row = db.scalar(select(IntegrityArchiveSegment).where(IntegrityArchiveSegment.id == segment_id,
                                                          IntegrityArchiveSegment.tenant_id == context.tenant_id))
    if row is None: raise HTTPException(status_code=404, detail="integrity segment not found")
    try:
        auth = authorize_integrity_compaction(db, row.id, provider=HttpSignedWitnessProvider(get_settings()))
    except IntegritySegmentEligibilityError as exc:
        db.rollback(); raise HTTPException(status_code=409, detail=exc.reason) from exc
    return IntegritySegmentActionResponse(segment_id=row.id, status="READY_TO_COMPACT", detail={"authorization_id": str(auth.id), "expires_at": auth.expires_at.isoformat()})


@router.post("/v1/integrity/segments/compact", response_model=IntegritySegmentActionResponse, status_code=status.HTTP_202_ACCEPTED)
def integrity_segment_compact(request: IntegritySegmentRequest, db: Session = Depends(db_session),
                              context: AuthContext = Depends(require_scope("integrity:compact"))) -> IntegritySegmentActionResponse:
    row = db.scalar(select(IntegrityArchiveSegment).where(IntegrityArchiveSegment.id == request.segment_id,
                                                          IntegrityArchiveSegment.tenant_id == context.tenant_id))
    if row is None: raise HTTPException(status_code=404, detail="integrity segment not found")
    try:
        job = queue_integrity_compaction(db, tenant_id=context.tenant_id, segment_id=row.id)
    except Exception as exc:
        db.rollback(); raise HTTPException(status_code=409, detail="integrity compaction could not be queued") from exc
    return IntegritySegmentActionResponse(segment_id=row.id, status=job.status, detail={"job_id": str(job.id), "message": "compaction is performed only by the dedicated integrity compactor"})


def _archive_response(db: Session, row: ArchiveRecord) -> ArchiveResponse:
    lifecycle = row.lifecycle
    return ArchiveResponse(id=row.id, tenant_id=row.tenant_id, trace_id=row.trace_id,
        archive_version=row.archive_version, envelope_version=row.envelope_version, object_key=row.object_key,
        archive_encryption_key_id=row.archive_encryption_key_id, plaintext_sha256=row.plaintext_sha256,
        compressed_sha256=row.compressed_sha256, ciphertext_sha256=row.ciphertext_sha256,
        source_projection_digest=row.source_projection_digest, covering_checkpoint_sequence=row.covering_checkpoint_sequence,
        covering_checkpoint_digest=row.covering_checkpoint_digest, trace_span_count=row.trace_span_count,
        plaintext_size=row.plaintext_size, compressed_size=row.compressed_size, ciphertext_size=row.ciphertext_size,
        created_at=row.created_at, verified_at=row.verified_at, status=lifecycle.status if lifecycle else "PENDING")


def _hold_response(row: RetentionHold) -> RetentionHoldResponse:
    return RetentionHoldResponse(id=row.id, tenant_id=row.tenant_id, subject_type=row.subject_type,
        trace_id=row.trace_id, reason=row.reason, created_by_principal_type=row.created_by_principal_type,
        created_by_principal_id=row.created_by_principal_id, created_at=row.created_at, released_at=row.released_at,
        released_by_principal_type=row.released_by_principal_type, released_by_principal_id=row.released_by_principal_id)


@router.get("/v1/retention/status", response_model=RetentionStatusResponse)
def retention_status_route(db: Session = Depends(db_session),
                           context: AuthContext = Depends(require_scope("retention:manage"))) -> RetentionStatusResponse:
    return RetentionStatusResponse(**retention_status(db, tenant_id=context.tenant_id))


@router.get("/v1/archives", response_model=list[ArchiveResponse])
def archive_list(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(db_session),
                 context: AuthContext = Depends(require_scope("archives:read"))) -> list[ArchiveResponse]:
    rows = list(db.scalars(select(ArchiveRecord).where(ArchiveRecord.tenant_id == context.tenant_id)
                           .order_by(ArchiveRecord.created_at.desc()).limit(limit)))
    return [_archive_response(db, row) for row in rows]


def _replica_response(row: ArchiveReplica) -> ArchiveReplicaResponse:
    return ArchiveReplicaResponse.model_validate(row)


@router.get("/v1/archive/replicas", response_model=list[ArchiveReplicaResponse])
def archive_replica_list(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(db_session),
                         context: AuthContext = Depends(require_scope("archives:read"))) -> list[ArchiveReplicaResponse]:
    return [_replica_response(row) for row in list_replicas(db, tenant_id=context.tenant_id)[:limit]]


@router.get("/v1/archive/replicas/{logical_archive_id}", response_model=list[ArchiveReplicaResponse])
def archive_replica_detail(logical_archive_id: UUID, db: Session = Depends(db_session),
                           context: AuthContext = Depends(require_scope("archives:read"))) -> list[ArchiveReplicaResponse]:
    rows = list_replicas(db, tenant_id=context.tenant_id, logical_archive_id=logical_archive_id)
    if not rows:
        raise HTTPException(status_code=404, detail="archive replicas not found")
    return [_replica_response(row) for row in rows]


@router.get("/v1/archive/health", response_model=list[ArchiveReplicaHealthResponse])
def archive_health(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(db_session),
                   context: AuthContext = Depends(require_scope("archives:read"))) -> list[ArchiveReplicaHealthResponse]:
    keys = {(row.logical_archive_type, row.logical_archive_id) for row in list_replicas(db, tenant_id=context.tenant_id)}
    return [ArchiveReplicaHealthResponse(**logical_archive_health(db, tenant_id=context.tenant_id, logical_archive_type=kind, logical_archive_id=archive_id)) for kind, archive_id in sorted(keys, key=lambda item: str(item[1]))[:limit]]


@router.post("/v1/archive/replicas/{replica_id}/verify", response_model=ArchiveReplicaResponse)
def archive_replica_verify(replica_id: UUID, db: Session = Depends(db_session),
                           context: AuthContext = Depends(require_scope("archives:read"))) -> ArchiveReplicaResponse:
    row = db.get(ArchiveReplica, replica_id)
    if row is None or row.tenant_id != context.tenant_id:
        raise HTTPException(status_code=404, detail="archive replica not found")
    verify_replica(db, replica_id)
    return _replica_response(db.get(ArchiveReplica, replica_id))


@router.post("/v1/archive/replicas/{logical_archive_id}/repair", response_model=dict[str, Any])
def archive_replica_repair(logical_archive_id: UUID, request: ArchiveRepairRequest,
                           logical_archive_type: str = Query(TRACE_ARCHIVE), db: Session = Depends(db_session),
                           context: AuthContext = Depends(require_scope("archive:repair"))) -> dict[str, Any]:
    rows = list_replicas(db, tenant_id=context.tenant_id, logical_archive_type=logical_archive_type, logical_archive_id=logical_archive_id)
    if not rows:
        raise HTTPException(status_code=404, detail="archive replicas not found")
    return repair_missing_replica(db, tenant_id=context.tenant_id, logical_archive_type=logical_archive_type,
                                  logical_archive_id=logical_archive_id, target_store_id=request.target_store_id,
                                  dry_run=request.dry_run)


@router.get("/v1/archives/{archive_id}", response_model=ArchiveRetrievalResponse)
def archive_detail(archive_id: UUID, db: Session = Depends(db_session),
                   context: AuthContext = Depends(require_scope("archives:read"))) -> ArchiveRetrievalResponse:
    row = db.scalar(select(ArchiveRecord).where(ArchiveRecord.id == archive_id,
                                                ArchiveRecord.tenant_id == context.tenant_id))
    if row is None:
        raise HTTPException(status_code=404, detail="archive not found")
    try:
        payload = retrieve_archive(db, tenant_id=context.tenant_id, archive_id=archive_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="archive not found") from exc
    except Exception as exc:
        logger.warning("archive_retrieval_failed tenant_id=%s archive_id=%s reason=%s",
                       context.tenant_id, archive_id, type(exc).__name__)
        raise HTTPException(status_code=503, detail="archive unavailable or failed integrity verification") from exc
    logger.info("archive_retrieved tenant_id=%s archive_id=%s", context.tenant_id, archive_id)
    return ArchiveRetrievalResponse(archive=_archive_response(db, row), payload=payload)


@router.get("/v1/traces/{trace_id}/archive", response_model=ArchiveRetrievalResponse)
def trace_archive(trace_id: str, db: Session = Depends(db_session),
                  context: AuthContext = Depends(require_scope("archives:read"))) -> ArchiveRetrievalResponse:
    row = db.scalar(select(ArchiveRecord).where(ArchiveRecord.tenant_id == context.tenant_id,
                                                ArchiveRecord.trace_id == trace_id)
                    .order_by(ArchiveRecord.created_at.desc()).limit(1))
    if row is None:
        raise HTTPException(status_code=404, detail="archive not found")
    try:
        payload = retrieve_archive(db, tenant_id=context.tenant_id, archive_id=row.id)
    except Exception as exc:
        logger.warning("archive_retrieval_failed tenant_id=%s trace_id=%s reason=%s",
                       context.tenant_id, trace_id, type(exc).__name__)
        raise HTTPException(status_code=503, detail="archive unavailable or failed integrity verification") from exc
    return ArchiveRetrievalResponse(archive=_archive_response(db, row), payload=payload)


@router.post("/v1/retention/run", response_model=RetentionRunResponse)
def retention_run(request: RetentionRunRequest, db: Session = Depends(db_session),
                  context: AuthContext = Depends(require_scope("retention:manage"))) -> RetentionRunResponse:
    settings = get_settings()
    rows = list(db.scalars(select(Trace).where(Trace.tenant_id == context.tenant_id)
                           .order_by(Trace.ended_at).limit(settings.archive_batch_size)))
    eligible = queued = blocked = 0
    for row in rows:
        try:
            from agentguard_server.services.archive import check_archive_eligibility
            check_archive_eligibility(db, context.tenant_id, row.trace_id, settings=settings)
            eligible += 1
            if not request.dry_run:
                queue_retention_job(db, tenant_id=context.tenant_id, trace_id=row.trace_id)
                queued += 1
        except Exception:
            blocked += 1
    return RetentionRunResponse(dry_run=request.dry_run, queued=queued, eligible=eligible, blocked=blocked)


@router.get("/v1/retention/holds", response_model=list[RetentionHoldResponse])
def retention_hold_list(db: Session = Depends(db_session),
                        context: AuthContext = Depends(require_scope("retention:hold"))) -> list[RetentionHoldResponse]:
    rows = list(db.scalars(select(RetentionHold).where(RetentionHold.tenant_id == context.tenant_id)
                           .order_by(RetentionHold.created_at.desc()).limit(1000)))
    return [_hold_response(row) for row in rows]


@router.post("/v1/retention/holds", response_model=RetentionHoldResponse, status_code=status.HTTP_201_CREATED)
def retention_hold_create(request: RetentionHoldCreate, db: Session = Depends(db_session),
                          context: AuthContext = Depends(require_scope("retention:hold"))) -> RetentionHoldResponse:
    if request.subject_type == "TRACE" and db.scalar(select(Trace).where(
            Trace.tenant_id == context.tenant_id, Trace.trace_id == request.trace_id)) is None:
        raise HTTPException(status_code=404, detail="trace not found")
    try:
        row = create_hold(db, tenant_id=context.tenant_id, subject_type=request.subject_type,
                          trace_id=request.trace_id, reason=request.reason,
                          principal_type="API_KEY", principal_id=str(context.api_key_id))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _hold_response(row)


@router.post("/v1/retention/holds/{hold_id}/release", response_model=RetentionHoldResponse)
def retention_hold_release(hold_id: UUID, db: Session = Depends(db_session),
                           context: AuthContext = Depends(require_scope("retention:hold"))) -> RetentionHoldResponse:
    row = release_hold(db, tenant_id=context.tenant_id, hold_id=hold_id,
                       principal_type="API_KEY", principal_id=str(context.api_key_id))
    if row is None:
        raise HTTPException(status_code=404, detail="hold not found")
    return _hold_response(row)

