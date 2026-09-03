from __future__ import annotations

from typing import Any
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentguard_server.models import Span, Trace
from agentguard_server.services.auth import get_or_create_local_tenant


def _tenant_id(db: Session, tenant_id: uuid.UUID | str | None) -> uuid.UUID:
    if tenant_id is None:
        return get_or_create_local_tenant(db).id
    return tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(str(tenant_id))


def list_traces(db: Session, tenant_id: uuid.UUID | str | None = None, limit: int = 100, offset: int = 0) -> tuple[list[Trace], int]:
    tenant = _tenant_id(db, tenant_id)
    total = db.scalar(select(func.count()).select_from(Trace).where(Trace.tenant_id == tenant)) or 0
    traces = list(db.scalars(select(Trace).where(Trace.tenant_id == tenant).order_by(Trace.started_at.desc()).limit(limit).offset(offset)))
    return traces, total


def get_trace(db: Session, trace_id: str, tenant_id: uuid.UUID | str | None = None) -> tuple[Trace | None, list[Span]]:
    tenant = _tenant_id(db, tenant_id)
    trace = db.scalar(select(Trace).where(Trace.tenant_id == tenant, Trace.trace_id == trace_id))
    if trace is None:
        return None, []
    spans = list(db.scalars(select(Span).where(Span.tenant_id == tenant, Span.trace_id == trace_id).order_by(Span.started_at, Span.span_id)))
    return trace, spans


def make_span_tree(spans: list[Span]) -> list[dict[str, Any]]:
    nodes = {span.span_id: {"span": span, "children": []} for span in spans}
    roots: list[dict[str, Any]] = []
    for span in spans:
        node = nodes[span.span_id]
        parent = nodes.get(span.parent_span_id)
        if parent:
            parent["children"].append(node)
        else:
            roots.append(node)
    return roots
