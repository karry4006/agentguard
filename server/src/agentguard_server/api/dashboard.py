"""Bounded, server-rendered operator console.

This router is deliberately a presentation layer over existing AgentGuard
services. It has no shell, arbitrary HTTP, deployment, or remediation seam.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
from urllib.parse import parse_qs
from uuid import UUID

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import ChoiceLoader, FileSystemLoader
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session
from starlette.templating import Jinja2Templates

from agentguard_server.api.routes import db_session, _incident_detail
from agentguard_server.config import get_settings
from agentguard_server.models import (AnalysisFinding, AnalysisRun, EvaluationComparison, HumanUser, Incident,
    IncidentEvent, IntegrityArchiveSegment, NotificationDelivery, OrganizationMembership, ReleaseGateResult, Span, Trace)
from agentguard_server.provenance import build_metadata, migration_head
from agentguard_server.services.analysis import AnalysisRefused, AnalysisResourceLimit, analyze_trace, persist_analysis
from agentguard_server.services.auth import AuthContext
from agentguard_server.services.dashboard import (CSRF_FIELD, SESSION_COOKIE, DashboardIdentity,
    allow_login, create_dashboard_session, create_human_dashboard_session, create_pending_human_dashboard_session,
    csrf_token_for_session, load_dashboard_session,
    revoke_dashboard_session, validate_csrf)
from agentguard_server.services.evaluation import EvaluationValidationError
from agentguard_server.services.incidents import IncidentTransitionError, incident_trend, process_analysis_findings, transition_incident
from agentguard_server.services.identity import (IdentityValidationError, change_membership_role,
    create_machine_api_key, disable_membership, list_machine_api_keys, list_members, provision_member,
    record_human_event, revoke_machine_api_key, select_organization, selectable_organizations)
from agentguard_server.services.integrity import verify_trace_integrity
from agentguard_server.services.oidc import OidcProtocolError, begin_login, complete_login
from agentguard_server.services.query import get_trace, list_traces, make_span_tree
from agentguard_server.services.replay import ReplayRefused, build_replay_plan, persist_blocked_replay, persist_replay

router = APIRouter()
OIDC_STATE_COOKIE = "agentguard_oidc_state"
logger = logging.getLogger(__name__)
_TEMPLATE_DIR = Path(__file__).resolve().parents[0].parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_next(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value or "://" in value:
        return "/ui"
    return value[:512]


def _form_data(body: bytes, content_type: str) -> dict[str, str]:
    if len(body) > 16 * 1024:
        return {}
    try:
        if content_type.split(";", 1)[0].lower() == "application/json":
            value = json.loads(body.decode("utf-8"))
            return {str(key): str(item) for key, item in value.items()} if isinstance(value, dict) else {}
        values = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=False)
        return {key: items[0] for key, items in values.items() if items}
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return {}


def _render(request: Request, name: str, identity: DashboardIdentity | None = None, **context):
    settings = get_settings()
    context.update({
        "request": request,
        "identity": identity,
        "scopes": identity.context.scopes if identity else frozenset(),
        "csrf_token": context.pop("csrf_token", None),
        "environment": settings.environment,
        "oidc_enabled": settings.oidc_enabled,
        "api_key_login_enabled": settings.dashboard_api_key_login_enabled,
    })
    return templates.TemplateResponse(request=request, name=name, context=context)


def _login_redirect() -> RedirectResponse:
    return RedirectResponse("/ui/login", status_code=303)


def _client_rate_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _secure_cookie(settings) -> bool:
    return settings.environment.strip().lower() in {"production", "staging"}


def _clear_oidc_state(response):
    response.delete_cookie(OIDC_STATE_COOKIE, path="/ui/oidc/callback")
    return response


def _identity(request: Request, db: Session) -> DashboardIdentity | None:
    return load_dashboard_session(db, request.cookies.get(SESSION_COOKIE))


def _require(request: Request, db: Session, scope: str | None = None,
             allow_unselected: bool = False) -> tuple[DashboardIdentity | None, HTMLResponse | None]:
    identity = _identity(request, db)
    if identity is None:
        return None, _login_redirect()
    if (identity.context.principal_type == "HUMAN_SESSION" and identity.context.organization_id is None
            and not allow_unselected):
        return identity, RedirectResponse("/ui/organization/select", status_code=303)
    if scope and scope not in identity.context.scopes:
        return identity, HTMLResponse("forbidden", status_code=403)
    return identity, None


def _csrf_or_forbidden(request: Request, identity: DashboardIdentity, body: bytes) -> HTMLResponse | None:
    form = _form_data(body, request.headers.get("content-type", ""))
    if not validate_csrf(identity.session, form.get(CSRF_FIELD)):
        return HTMLResponse("forbidden", status_code=403)
    return None


@router.get("/ui/login", response_class=HTMLResponse)
def ui_login(request: Request):
    return _render(request, "login.html", error=request.query_params.get("error"))


@router.get("/ui/oidc/login")
async def ui_oidc_login(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    if not allow_login(_client_rate_key(request), "oidc-init", db=db):
        return RedirectResponse("/ui/login?error=identity_provider_unavailable", status_code=303)
    settings = get_settings()
    transport = getattr(request.app.state, "oidc_transport", None)
    try:
        authorization = await begin_login(db, settings, request.query_params.get("next"), transport)
    except OidcProtocolError:
        logger.warning("OIDC authorization initiation rejected")
        return RedirectResponse("/ui/login?error=identity_provider_unavailable", status_code=303)
    response = RedirectResponse(authorization.url, status_code=303)
    response.set_cookie(OIDC_STATE_COOKIE, authorization.state,
                        max_age=settings.oidc_login_attempt_lifetime_seconds,
                        httponly=True, secure=_secure_cookie(settings),
                        samesite="lax", path="/ui/oidc/callback")
    return response


@router.get("/ui/oidc/callback")
async def ui_oidc_callback(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    if not allow_login(_client_rate_key(request), "oidc-callback", db=db):
        return _clear_oidc_state(HTMLResponse("access denied", status_code=403))
    settings = get_settings()
    transport = getattr(request.app.state, "oidc_transport", None)
    try:
        verified, return_to = await complete_login(
            db, settings, request.query_params.get("state"), request.cookies.get(OIDC_STATE_COOKIE),
            request.query_params.get("code"), transport,
        )
    except OidcProtocolError:
        logger.warning("OIDC callback rejected")
        return _clear_oidc_state(HTMLResponse("access denied", status_code=403))
    user = db.scalar(select(HumanUser).where(
        HumanUser.external_issuer == verified.issuer,
        HumanUser.external_subject == verified.subject,
        HumanUser.disabled_at.is_(None),
    ))
    if user is None:
        logger.warning("OIDC identity is not provisioned")
        return _clear_oidc_state(HTMLResponse("access denied", status_code=403))
    user.display_name = verified.display_name
    user.email = verified.email
    user.updated_at = _now()
    memberships = list(db.scalars(select(OrganizationMembership).where(
        OrganizationMembership.user_id == user.id,
        OrganizationMembership.disabled_at.is_(None),
    ).limit(2)))
    db.commit()
    if not memberships:
        return _clear_oidc_state(HTMLResponse("access denied", status_code=403))
    login = (create_human_dashboard_session(db, user, memberships[0], settings) if len(memberships) == 1
             else create_pending_human_dashboard_session(db, user, settings))
    if login is None:
        return _clear_oidc_state(HTMLResponse("access denied", status_code=403))
    record_human_event(db, login.context, "human_login_success")
    response = RedirectResponse(return_to if len(memberships) == 1 else "/ui/organization/select", status_code=303)
    response.set_cookie(SESSION_COOKIE, login.session_token,
                        max_age=settings.dashboard_session_lifetime_seconds,
                        httponly=True, secure=_secure_cookie(settings),
                        samesite="strict", path="/")
    return _clear_oidc_state(response)


@router.post("/ui/login")
async def ui_login_submit(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    if not allow_login(_client_rate_key(request), "api-key", db=db):
        return RedirectResponse("/ui/login?error=invalid_credentials", status_code=303)
    form = _form_data(await request.body(), request.headers.get("content-type", ""))
    settings = get_settings()
    if settings.oidc_enabled and not settings.dashboard_api_key_login_enabled:
        return RedirectResponse("/ui/login?error=invalid_credentials", status_code=303)
    presented_key = form.get("api_key", "").strip()
    login = create_dashboard_session(db, presented_key, settings.key_pepper or "") if presented_key else None
    if login is None:
        return RedirectResponse("/ui/login?error=invalid_credentials", status_code=303)
    response = RedirectResponse(_safe_next(form.get("next")), status_code=303)
    response.set_cookie(SESSION_COOKIE, login.session_token,
                        max_age=settings.dashboard_session_lifetime_seconds,
                        httponly=True, secure=_secure_cookie(settings),
                        samesite="strict", path="/")
    return response


@router.post("/ui/logout")
async def ui_logout(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, allow_unselected=True)
    if response:
        return response
    csrf_error = _csrf_or_forbidden(request, identity, await request.body())
    if csrf_error:
        return csrf_error
    if identity.context.principal_type == "HUMAN_SESSION":
        record_human_event(db, identity.context, "human_logout")
    revoke_dashboard_session(db, identity.session)
    result = RedirectResponse("/ui/login", status_code=303)
    result.delete_cookie(SESSION_COOKIE, path="/")
    return result


def _overview_data(db: Session, tenant_id: UUID) -> dict:
    cutoff = _now() - timedelta(hours=24)
    incidents = list(db.scalars(select(Incident).where(Incident.tenant_id == tenant_id)
                               .order_by(Incident.last_seen_at.desc()).limit(25)))
    recent_traces = list(db.scalars(select(Trace).where(Trace.tenant_id == tenant_id, Trace.started_at >= cutoff)
                                  .order_by(Trace.started_at.desc()).limit(25)))
    failed_traces = [row for row in recent_traces if str(row.status).lower() in {"failed", "failure", "error", "timeout"}]
    failed_notifications = list(db.scalars(select(NotificationDelivery).where(
        NotificationDelivery.tenant_id == tenant_id, NotificationDelivery.status.in_(["FAILED", "RETRYING"]))
        .order_by(NotificationDelivery.created_at.desc()).limit(10)))
    gates = list(db.execute(select(ReleaseGateResult, EvaluationComparison).join(
        EvaluationComparison, EvaluationComparison.id == ReleaseGateResult.comparison_id
    ).where(EvaluationComparison.tenant_id == tenant_id).order_by(ReleaseGateResult.created_at.desc()).limit(10)))
    integrity_segments = list(db.scalars(select(IntegrityArchiveSegment).where(
        IntegrityArchiveSegment.tenant_id == tenant_id
    ).order_by(IntegrityArchiveSegment.created_at.desc()).limit(25)))
    return {
        "incidents": incidents, "recent_traces": recent_traces, "failed_traces": failed_traces,
        "failed_notifications": failed_notifications, "gates": gates,
        "counts": {
            "open": sum(row.status == "OPEN" for row in incidents),
            "acknowledged": sum(row.status == "ACKNOWLEDGED" for row in incidents),
            "critical_high": sum(row.severity in {"CRITICAL", "HIGH"} for row in incidents),
            "integrity_segments": len(integrity_segments),
            "integrity_compacted": sum(row.state == "COMPACTED" for row in integrity_segments),
            "integrity_blocked": sum(row.state in {"BLOCKED", "FAILED"} for row in integrity_segments),
        },
        "integrity_segments": integrity_segments,
    }


@router.get("/ui", response_class=HTMLResponse)
def ui_overview(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db)
    if response:
        return response
    return _render_authenticated(request, "overview.html", identity, **_overview_data(db, identity.context.tenant_id))


def _render_authenticated(request: Request, name: str, identity: DashboardIdentity, **context):
    context.setdefault("csrf_token", csrf_token_for_session(identity.session))
    return _render(request, name, identity, **context)


@router.get("/ui/incidents", response_class=HTMLResponse)
def ui_incidents(request: Request, status_filter: str | None = Query(default=None, alias="status"), severity: str | None = None,
                 category: str | None = None, page: int = Query(1, ge=1), db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "incidents:read")
    if response:
        return response
    query = select(Incident).where(Incident.tenant_id == identity.context.tenant_id)
    if status_filter in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
        query = query.where(Incident.status == status_filter)
    if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        query = query.where(Incident.severity == severity)
    if category and len(category) <= 64:
        query = query.where(Incident.primary_category == category)
    page_size = 50
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = list(db.scalars(query.order_by(Incident.last_seen_at.desc()).offset((page - 1) * page_size).limit(page_size)))
    return _render_authenticated(request, "incidents.html", identity, incidents=rows, total=total, page=page,
                                  status_filter=status_filter, severity=severity, category=category)


@router.get("/ui/incidents/{incident_id}", response_class=HTMLResponse)
def ui_incident_detail(incident_id: UUID, request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "incidents:read")
    if response:
        return response
    incident = db.scalar(select(Incident).where(Incident.id == incident_id, Incident.tenant_id == identity.context.tenant_id))
    if incident is None:
        return HTMLResponse("not found", status_code=404)
    return _render_authenticated(request, "incident_detail.html", identity, detail=_incident_detail(db, incident), incident=incident)


@router.post("/ui/incidents/{incident_id}/{action}")
async def ui_incident_action(incident_id: UUID, action: str, request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "incidents:manage")
    if response:
        return response
    csrf_error = _csrf_or_forbidden(request, identity, await request.body())
    if csrf_error:
        return csrf_error
    targets = {"acknowledge": "ACKNOWLEDGED", "resolve": "RESOLVED", "reopen": "OPEN"}
    target = targets.get(action)
    if target is None:
        return HTMLResponse("not found", status_code=404)
    try:
        transition_incident(db, identity.context.tenant_id, incident_id, target,
                            actor_type="dashboard", actor_id=str(identity.session.id))
    except (LookupError, IncidentTransitionError):
        return HTMLResponse("not found", status_code=404)
    return RedirectResponse(f"/ui/incidents/{incident_id}", status_code=303)


@router.get("/ui/traces", response_class=HTMLResponse)
def ui_traces(request: Request, page: int = Query(1, ge=1), status_filter: str | None = Query(default=None, alias="status"),
              db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "traces:read")
    if response:
        return response
    limit = 50
    rows, total = list_traces(db, identity.context.tenant_id, limit, (page - 1) * limit)
    if status_filter in {"running", "success", "failed", "error", "timeout"}:
        rows = [row for row in rows if str(row.status).lower() == status_filter]
    return _render_authenticated(request, "traces.html", identity, traces=rows, total=total, page=page, status_filter=status_filter)


@router.get("/ui/traces/{trace_id}", response_class=HTMLResponse)
def ui_trace_detail(trace_id: str, request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "traces:read")
    if response:
        return response
    trace, spans = get_trace(db, trace_id, identity.context.tenant_id)
    if trace is None:
        return HTMLResponse("not found", status_code=404)
    integrity = verify_trace_integrity(db, identity.context.tenant_id, trace_id).as_dict(trace_id)
    findings = list(db.scalars(select(AnalysisFinding).join(AnalysisRun, AnalysisRun.id == AnalysisFinding.analysis_run_id)
                              .where(AnalysisRun.tenant_id == identity.context.tenant_id, AnalysisRun.trace_id == trace_id).limit(100)))
    root_ids = {row.root_cause_span_id for row in findings if row.root_cause_span_id}
    symptom_ids = {row.symptom_span_id for row in findings if row.symptom_span_id}
    return _render_authenticated(request, "trace_detail.html", identity, trace=trace, spans=spans,
                                  span_tree=make_span_tree(spans), integrity=integrity, findings=findings,
                                  root_ids=root_ids, symptom_ids=symptom_ids,
                                  content_policy="CONTENT NOT CAPTURED" if not get_settings().capture_content else "SENSITIVE CONTENT HIDDEN BY POLICY")


@router.post("/ui/traces/{trace_id}/analysis")
async def ui_trace_analysis(trace_id: str, request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "analysis:run")
    if response:
        return response
    if "traces:read" not in identity.context.scopes:
        return HTMLResponse("forbidden", status_code=403)
    csrf_error = _csrf_or_forbidden(request, identity, await request.body())
    if csrf_error:
        return csrf_error
    try:
        report, _ = analyze_trace(db, identity.context.tenant_id, trace_id, mode="deterministic")
        run = persist_analysis(db, tenant_id=identity.context.tenant_id, report=report, mode="deterministic")
        process_analysis_findings(db, identity.context.tenant_id, run)
    except (AnalysisRefused, AnalysisResourceLimit):
        return HTMLResponse("analysis unavailable", status_code=409)
    return RedirectResponse(f"/ui/traces/{trace_id}", status_code=303)


@router.post("/ui/traces/{trace_id}/replay")
async def ui_trace_replay(trace_id: str, request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "replay:run")
    if response:
        return response
    if "traces:read" not in identity.context.scopes:
        return HTMLResponse("forbidden", status_code=403)
    csrf_error = _csrf_or_forbidden(request, identity, await request.body())
    if csrf_error:
        return csrf_error
    try:
        plan = build_replay_plan(db, identity.context.tenant_id, trace_id)
        persist_replay(db, tenant_id=identity.context.tenant_id, plan=plan, idempotency_key=f"dashboard-{identity.session.id}-{trace_id}")
    except ReplayRefused as exc:
        persist_blocked_replay(db, tenant_id=identity.context.tenant_id, trace_id=trace_id,
                               reason=exc.reason, integrity_status=exc.integrity_status)
    return RedirectResponse(f"/ui/traces/{trace_id}", status_code=303)


@router.get("/ui/evaluations", response_class=HTMLResponse)
def ui_evaluations(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "evaluations:read")
    if response:
        return response
    rows = list(db.scalars(select(EvaluationComparison).where(EvaluationComparison.tenant_id == identity.context.tenant_id)
                           .order_by(EvaluationComparison.created_at.desc()).limit(100)))
    gates = list(db.execute(select(ReleaseGateResult, EvaluationComparison).join(
        EvaluationComparison, EvaluationComparison.id == ReleaseGateResult.comparison_id
    ).where(EvaluationComparison.tenant_id == identity.context.tenant_id).order_by(ReleaseGateResult.created_at.desc()).limit(100)))
    return _render_authenticated(request, "evaluations.html", identity, comparisons=rows, gates=gates)


@router.get("/ui/notifications", response_class=HTMLResponse)
def ui_notifications(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "notifications:read")
    if response:
        return response
    rows = list(db.scalars(select(NotificationDelivery).where(NotificationDelivery.tenant_id == identity.context.tenant_id)
                           .order_by(NotificationDelivery.created_at.desc()).limit(100)))
    return _render_authenticated(request, "notifications.html", identity, deliveries=rows)


@router.get("/ui/system", response_class=HTMLResponse)
def ui_system(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db)
    if response:
        return response
    try:
        current_user = db.execute(text("SELECT current_user")).scalar_one()
        db_status = "connected"
    except Exception:
        current_user, db_status = "unavailable", "unavailable"
    metadata = build_metadata()
    metadata["migration_head"] = migration_head()
    return _render_authenticated(request, "system.html", identity, metadata=metadata,
                                  current_user=current_user, db_status=db_status)


@router.get("/ui/organization", response_class=HTMLResponse)
def ui_organization(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db)
    if response:
        return response
    if identity.context.principal_type != "HUMAN_SESSION":
        return HTMLResponse("forbidden", status_code=403)
    return _render_authenticated(request, "organization.html", identity)


@router.get("/ui/organization/select", response_class=HTMLResponse)
def ui_organization_select(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity = _identity(request, db)
    if identity is None:
        return _login_redirect()
    if identity.context.principal_type != "HUMAN_SESSION":
        return HTMLResponse("forbidden", status_code=403)
    try:
        organizations = selectable_organizations(db, identity.context)
    except PermissionError:
        return HTMLResponse("forbidden", status_code=403)
    return _render_authenticated(request, "organization_select.html", identity, organizations=organizations)


@router.post("/ui/organization/select")
async def ui_organization_select_submit(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity = _identity(request, db)
    if identity is None:
        return _login_redirect()
    body = await request.body()
    csrf_error = _csrf_or_forbidden(request, identity, body)
    if csrf_error:
        return csrf_error
    form = _form_data(body, request.headers.get("content-type", ""))
    try:
        organization_id = UUID(form.get("organization_id", ""))
        selected = select_organization(db, identity.context, identity.session, organization_id)
    except (ValueError, PermissionError):
        return HTMLResponse("forbidden", status_code=403)
    if not selected:
        return HTMLResponse("not found", status_code=404)
    return RedirectResponse("/ui", status_code=303)


@router.get("/ui/organization/members", response_class=HTMLResponse)
def ui_organization_members(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "members:read")
    if response:
        return response
    try:
        members = list_members(db, identity.context)
    except PermissionError:
        return HTMLResponse("forbidden", status_code=403)
    return _render_authenticated(request, "organization_members.html", identity, members=members)


@router.post("/ui/organization/members")
async def ui_organization_member_create(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "members:manage")
    if response:
        return response
    body = await request.body()
    csrf_error = _csrf_or_forbidden(request, identity, body)
    if csrf_error:
        return csrf_error
    form = _form_data(body, request.headers.get("content-type", ""))
    settings = get_settings()
    try:
        provision_member(db, identity.context, settings.oidc_issuer or "", form.get("subject", ""),
                         form.get("display_name"), form.get("email"), form.get("role", ""))
    except PermissionError:
        return HTMLResponse("forbidden", status_code=403)
    except IdentityValidationError:
        return HTMLResponse("invalid membership request", status_code=409)
    return RedirectResponse("/ui/organization/members", status_code=303)


@router.post("/ui/organization/members/{membership_id}/role")
async def ui_organization_member_role(membership_id: UUID, request: Request,
                                      db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "members:manage")
    if response:
        return response
    body = await request.body()
    csrf_error = _csrf_or_forbidden(request, identity, body)
    if csrf_error:
        return csrf_error
    form = _form_data(body, request.headers.get("content-type", ""))
    try:
        membership = change_membership_role(db, identity.context, membership_id, form.get("role", ""))
    except PermissionError:
        return HTMLResponse("forbidden", status_code=403)
    except IdentityValidationError:
        return HTMLResponse("membership change rejected", status_code=409)
    if membership is None:
        return HTMLResponse("not found", status_code=404)
    return RedirectResponse("/ui/organization/members", status_code=303)


@router.post("/ui/organization/members/{membership_id}/disable")
async def ui_organization_member_disable(membership_id: UUID, request: Request,
                                         db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "members:manage")
    if response:
        return response
    csrf_error = _csrf_or_forbidden(request, identity, await request.body())
    if csrf_error:
        return csrf_error
    try:
        membership = disable_membership(db, identity.context, membership_id)
    except PermissionError:
        return HTMLResponse("forbidden", status_code=403)
    except IdentityValidationError:
        return HTMLResponse("membership change rejected", status_code=409)
    if membership is None:
        return HTMLResponse("not found", status_code=404)
    return RedirectResponse("/ui/organization/members", status_code=303)


@router.get("/ui/organization/api-keys", response_class=HTMLResponse)
def ui_organization_api_keys(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "keys:manage")
    if response:
        return response
    try:
        keys = list_machine_api_keys(db, identity.context)
    except PermissionError:
        return HTMLResponse("forbidden", status_code=403)
    return _render_authenticated(request, "organization_api_keys.html", identity, api_keys=keys)


@router.post("/ui/organization/api-keys", response_class=HTMLResponse)
async def ui_organization_api_key_create(request: Request, db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "keys:manage")
    if response:
        return response
    body = await request.body()
    csrf_error = _csrf_or_forbidden(request, identity, body)
    if csrf_error:
        return csrf_error
    form = _form_data(body, request.headers.get("content-type", ""))
    scopes = [item for item in form.get("scopes", "").split(",") if item]
    try:
        _, plaintext = create_machine_api_key(db, identity.context, form.get("name", "machine-key"),
                                              scopes, get_settings().key_pepper or "")
    except PermissionError:
        return HTMLResponse("forbidden", status_code=403)
    except (IdentityValidationError, ValueError):
        return HTMLResponse("invalid API key request", status_code=409)
    result = _render_authenticated(request, "organization_api_key_created.html", identity,
                                   plaintext_api_key=plaintext)
    result.status_code = 201
    return result


@router.post("/ui/organization/api-keys/{public_id}/revoke")
async def ui_organization_api_key_revoke(public_id: str, request: Request,
                                         db: Session = __import__("fastapi").Depends(db_session)):
    identity, response = _require(request, db, "keys:manage")
    if response:
        return response
    csrf_error = _csrf_or_forbidden(request, identity, await request.body())
    if csrf_error:
        return csrf_error
    try:
        revoked = revoke_machine_api_key(db, identity.context, public_id)
    except PermissionError:
        return HTMLResponse("forbidden", status_code=403)
    if not revoked:
        return HTMLResponse("not found", status_code=404)
    return RedirectResponse("/ui/organization/api-keys", status_code=303)
