from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.orm import sessionmaker

from agentguard_server import cli
from agentguard_server.schemas.events import Event
from agentguard_server.services.auth import create_tenant
from agentguard_server.services.evaluation import create_run, create_suite
from agentguard_server.services.ingestion import ingest_events


def _trace(trace_id: str) -> list[Event]:
    stamp = datetime.now(timezone.utc)
    return [
        Event(event_type="trace.started", event_id=f"{trace_id}-start", occurred_at=stamp,
              data={"trace_id": trace_id, "status": "running"}),
        Event(event_type="trace.ended", event_id=f"{trace_id}-end", occurred_at=stamp,
              data={"trace_id": trace_id, "status": "success"}),
    ]


def test_eval_compare_cli_returns_pass_exit_code(db_session, monkeypatch, capsys):
    tenant = create_tenant(db_session, f"cli-{uuid4().hex[:12]}", "CLI evaluation tenant")
    ingest_events(db_session, _trace("cli-base"), tenant.id)
    ingest_events(db_session, _trace("cli-candidate"), tenant.id)
    suite = create_suite(db_session, tenant.id, "cli-suite", "1", {})
    baseline = create_run(db_session, tenant.id, suite=suite, variant="baseline", agent_version="base",
                          prompt_version=None, model=None, environment={}, cases=[{"case_id": "one", "trace_id": "cli-base"}])
    candidate = create_run(db_session, tenant.id, suite=suite, variant="candidate", agent_version="candidate",
                           prompt_version=None, model=None, environment={}, cases=[{"case_id": "one", "trace_id": "cli-candidate"}])
    factory = sessionmaker(bind=db_session.bind, expire_on_commit=False)
    monkeypatch.setattr(cli, "get_session_factory", lambda: factory)

    exit_code = cli.main(["eval", "compare", "--tenant", tenant.slug, "--suite", str(suite.id),
                          "--baseline-run", str(baseline.id), "--candidate-run", str(candidate.id)])

    assert exit_code == 0
    assert "decision=PASS" in capsys.readouterr().out

