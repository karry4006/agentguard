from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import agentguard_server.ledger_compactor as ledger_compactor
import agentguard_server.services.ledger as ledger_service
from agentguard_server.models import LedgerCompactionJob, LedgerSegment, LedgerSegmentLifecycle
from agentguard_server.services.auth import create_tenant
from agentguard_server.services.archive_store import ArchiveStoreUnavailable


class _FakeSession:
    def __init__(self, job):
        self.job = job
        self.commit_count = 0
        self.rollback_count = 0
        self.close_count = 0

    def get(self, model, job_id):
        return self.job if job_id == self.job.id else None

    def rollback(self):
        self.rollback_count += 1

    def commit(self):
        self.commit_count += 1

    def close(self):
        self.close_count += 1


def test_retryable_archive_failure_returns_to_retry_wait_and_releases_lease(monkeypatch):
    now = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)
    job = SimpleNamespace(
        id=uuid4(), status="IN_FLIGHT", attempt_count=1,
        next_attempt_at=None, claimed_by="worker-a", claim_token="claim-token",
        claimed_at=now, lease_expires_at=now,
        last_error_category=None, updated_at=now,
    )
    session = _FakeSession(job)
    settings = SimpleNamespace(instance_id="worker-a", ledger_compaction_retry_base_seconds=2,
                               ledger_compaction_retry_max_seconds=60,
                               ledger_compaction_retry_max_attempts=10)

    monkeypatch.setattr(ledger_compactor, "get_settings", lambda: settings)
    monkeypatch.setattr(ledger_compactor, "get_session_factory", lambda: lambda: session)
    monkeypatch.setattr(ledger_compactor, "claim_ledger_compaction_job", lambda db, settings: job)
    monkeypatch.setattr(ledger_compactor, "database_now", lambda db: now, raising=False)

    def unavailable(_settings):
        raise ArchiveStoreUnavailable("object store unavailable")

    monkeypatch.setattr(ledger_compactor, "S3ArchiveStore", unavailable)

    assert ledger_compactor.run_once() is False
    assert job.status == "RETRY_WAIT"
    assert job.attempt_count == 1
    assert job.next_attempt_at == datetime(2026, 8, 31, 12, 0, 4, tzinfo=timezone.utc)
    assert job.last_error_category == "ArchiveStoreUnavailable"
    assert job.claimed_by is None
    assert job.claim_token is None
    assert job.claimed_at is None
    assert job.lease_expires_at is None
    assert session.rollback_count == 1
    assert session.close_count == 1


def test_retry_wait_is_not_claimable_before_db_time_and_is_claimable_after(monkeypatch, db_session):
    from agentguard_server.config import Settings

    now = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)
    tenant = create_tenant(db_session, f"retry-{uuid4().hex[:12]}", "retry tenant")
    segment = LedgerSegment(
        tenant_id=tenant.id, trace_id=f"retry-trace-{uuid4().hex}", segment_sequence=1,
        segment_version="ledger-segment-v1", start_event_sequence=1, end_event_sequence=1,
        start_previous_hash=None, end_event_hash="a" * 64, event_count=1,
        events_manifest_digest="b" * 64, segment_manifest_digest="c" * 64,
        created_at=now,
    )
    db_session.add(segment)
    db_session.flush()
    db_session.add(LedgerSegmentLifecycle(segment_id=segment.id, status="CANDIDATE", updated_at=now))
    job = LedgerCompactionJob(
        tenant_id=tenant.id, segment_id=segment.id, job_type="COMPACT", status="RETRY_WAIT",
        attempt_count=1, next_attempt_at=now.replace(second=10), created_at=now, updated_at=now,
    )
    db_session.add(job)
    db_session.commit()

    monkeypatch.setattr(ledger_service, "database_now", lambda db: now)
    settings = Settings(_env_file=None, instance_id="retry-worker", ledger_compaction_enabled=True)
    assert ledger_service.claim_ledger_compaction_job(db_session, settings=settings) is None
    assert db_session.get(LedgerCompactionJob, job.id).status == "RETRY_WAIT"

    job = db_session.get(LedgerCompactionJob, job.id)
    job.next_attempt_at = now
    db_session.commit()
    claimed = ledger_service.claim_ledger_compaction_job(db_session, settings=settings)
    assert claimed is not None
    db_session.expire_all()
    claimed = db_session.get(LedgerCompactionJob, job.id)
    assert claimed.status == "IN_FLIGHT"
    assert claimed.attempt_count == 2
    assert claimed.claimed_by == "retry-worker"


def test_retry_backoff_is_bounded_and_terminal_attempt_stays_failed():
    settings = SimpleNamespace(
        ledger_compaction_retry_base_seconds=5,
        ledger_compaction_retry_max_seconds=12,
        ledger_compaction_retry_max_attempts=2,
    )
    assert ledger_compactor._retry_delay_seconds(settings, 1) == 10
    assert ledger_compactor._retry_delay_seconds(settings, 10) == 12
    job = SimpleNamespace(attempt_count=2)
    assert job.attempt_count >= settings.ledger_compaction_retry_max_attempts


def test_compactor_main_keeps_polling_after_empty_or_failed_poll(monkeypatch):
    settings = SimpleNamespace(instance_id="polling-worker", ledger_compaction_poll_interval_seconds=7)
    calls = []
    sleeps = []

    def poll_once():
        calls.append(len(calls) + 1)
        if len(calls) == 3:
            raise RuntimeError("stop test loop")
        return False

    monkeypatch.setattr(ledger_compactor, "get_settings", lambda: settings)
    monkeypatch.setattr(ledger_compactor, "run_once", poll_once)
    monkeypatch.setattr(ledger_compactor.time, "sleep", lambda seconds: sleeps.append(seconds))

    import pytest
    with pytest.raises(RuntimeError, match="stop test loop"):
        ledger_compactor.main()
    assert calls == [1, 2, 3]
    assert sleeps == [7, 7]
