"""Small disposable fixtures shared by the Phase 3 examples."""
from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "server", "src"), os.path.join(ROOT, "sdk", "python", "src")]
os.environ.setdefault("AGENTGUARD_DATABASE_URL", "sqlite://")
os.environ.setdefault("AGENTGUARD_KEY_PEPPER", "phase3-demo-key-pepper")
os.environ.setdefault("AGENTGUARD_INTEGRITY_KEY", "phase3-demo-integrity-key-32-bytes!!")
os.environ.setdefault("AGENTGUARD_AUTH_ENABLED", "false")

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from agentguard_server.db.base import Base
from agentguard_server.models import EventLog  # noqa: F401 - imports all model metadata
from agentguard_server.schemas.events import Event
from agentguard_server.services.auth import get_or_create_local_tenant
from agentguard_server.services.ingestion import ingest_events


@contextmanager
def disposable_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as db:
        tenant = get_or_create_local_tenant(db)
        try:
            yield db, tenant
        finally:
            db.rollback()
    engine.dispose()


def fixture_events(trace_id: str, *, failed: bool = False, output: str = "Kaohsiung: sunny, 30C",
                   base: datetime | None = None) -> list[Event]:
    base = base or datetime(2026, 1, 1, tzinfo=timezone.utc)
    agent_id, tool_id = f"{trace_id}-agent", f"{trace_id}-tool"
    tool_end = base + timedelta(milliseconds=42)
    trace_end = base + timedelta(milliseconds=84)
    tool_status = "error" if failed else "success"
    error_type = "TimeoutError" if failed else None
    error_message = "weather provider timed out" if failed else None
    return [
        Event(event_type="trace.started", event_id=f"{trace_id}-trace-start", occurred_at=base,
              data={"trace_id": trace_id, "workflow_name": "phase3-demo", "provider": "local-demo", "status": "running"}),
        Event(event_type="span.started", event_id=f"{agent_id}-start", occurred_at=base,
              data={"trace_id": trace_id, "span_id": agent_id, "span_type": "agent", "name": "answer-question", "status": "running"}),
        Event(event_type="span.started", event_id=f"{tool_id}-start", occurred_at=base,
              data={"trace_id": trace_id, "span_id": tool_id, "parent_span_id": agent_id,
                    "span_type": "tool", "name": "get_weather", "tool_name": "get_weather",
                    "input": {"city": "Kaohsiung"}, "status": "running"}),
        Event(event_type="span.ended", event_id=f"{tool_id}-end", occurred_at=tool_end,
              data={"trace_id": trace_id, "span_id": tool_id, "parent_span_id": agent_id,
                    "span_type": "tool", "name": "get_weather", "tool_name": "get_weather",
                    "output": output if not failed else None, "status": tool_status,
                    "error_type": error_type, "error_message": error_message, "duration_ms": 42.0}),
        Event(event_type="span.ended", event_id=f"{agent_id}-end", occurred_at=trace_end,
              data={"trace_id": trace_id, "span_id": agent_id, "span_type": "agent", "name": "answer-question",
                    "status": tool_status, "error_type": error_type, "error_message": error_message, "duration_ms": 84.0}),
        Event(event_type="trace.ended", event_id=f"{trace_id}-trace-end", occurred_at=trace_end,
              data={"trace_id": trace_id, "workflow_name": "phase3-demo", "provider": "local-demo",
                    "status": tool_status}),
    ]


def ingest_fixture(db: Session, tenant_id, trace_id: str, **kwargs) -> None:
    ingest_events(db, fixture_events(trace_id, **kwargs), tenant_id, capture_content=True)

