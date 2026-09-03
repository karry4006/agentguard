"""Dedicated V17 compactor worker entrypoint.

The FastAPI process only queues work.  This module performs external
verification before the narrow, authorization-bound destructive operation.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

from agentguard_server.config import get_settings
from agentguard_server.db.session import get_session_factory
from agentguard_server.services.archive import ArchiveKeyring
from agentguard_server.services.archive_store import ArchiveStoreUnavailable, S3ArchiveStore
from agentguard_server.services.anchoring import HttpSignedWitnessProvider
from agentguard_server.services.ledger import (
    LedgerError, LedgerVerificationError, archive_ledger_segment, authorize_ledger_compaction, claim_ledger_compaction_job,
    compact_ledger_segment,
)
from agentguard_server.services.rate_limit import database_now
from agentguard_server.models import LedgerSegment, LedgerSegmentLifecycle

logger = logging.getLogger("agentguard.ledger.compactor")


def _retry_delay_seconds(settings, attempt_count: int) -> int:
    return min(settings.ledger_compaction_retry_max_seconds,
               settings.ledger_compaction_retry_base_seconds * 2 ** min(max(attempt_count, 0), 10))


def _retryable_failure(exc: Exception) -> bool:
    if isinstance(exc, ArchiveStoreUnavailable):
        return True
    if isinstance(exc, LedgerVerificationError):
        return exc.status in {"OBJECT_STORE_UNAVAILABLE", "V15_WITNESS_UNAVAILABLE"}
    return False


def run_once() -> bool:
    settings = get_settings()
    db = get_session_factory()()
    try:
        job = claim_ledger_compaction_job(db, settings=settings)
        if job is None:
            return False
        try:
            store = S3ArchiveStore(settings)
            keyring = ArchiveKeyring.from_settings(settings)
            provider = HttpSignedWitnessProvider(settings)
            segment = db.get(LedgerSegment, job.segment_id)
            if segment is None:
                raise LedgerError("SEGMENT_NOT_FOUND")
            lifecycle = db.get(LedgerSegmentLifecycle, segment.id)
            if lifecycle is not None and lifecycle.status == "COMPACTED":
                job.status = "SUCCEEDED"
            else:
                if lifecycle is None:
                    raise LedgerError("SEGMENT_STATE_INVALID")
                if lifecycle.status in {"CANDIDATE", "CLOSED", "FAILED"}:
                    # Archival is part of the same durable job.  It verifies
                    # PUT/GET, envelope, keys, V3, V15 and remote continuity
                    # before the job can reach the destructive phase.
                    archive_ledger_segment(db, segment.id, store, provider=provider, settings=settings, keyring=keyring)
                if lifecycle is None or lifecycle.status != "COMPACTION_AUTHORIZED":
                    authorize_ledger_compaction(db, segment.id, provider=provider, settings=settings, keyring=keyring, store=store)
                compact_ledger_segment(db, segment.id, settings=settings)
                job.status = "SUCCEEDED"
            job.last_error_category = None
        except Exception as exc:
            db.rollback()
            job = db.get(type(job), job.id)
            if job is not None:
                job.last_error_category = getattr(exc, "status", None) or getattr(exc, "reason", None) or type(exc).__name__
                retry = _retryable_failure(exc) and job.attempt_count < settings.ledger_compaction_retry_max_attempts
                current = database_now(db)
                job.status = "RETRY_WAIT" if retry else "FAILED"
                job.next_attempt_at = current + timedelta(seconds=_retry_delay_seconds(settings, job.attempt_count)) if retry else None
                job.claimed_by = job.claim_token = job.claimed_at = job.lease_expires_at = None
                job.updated_at = current
                db.commit()
            logger.warning("ledger_compaction_failed job_id=%s reason=%s", job.id if job else "unknown", type(exc).__name__)
            return False
        job.updated_at = database_now(db)
        db.commit()
        return True
    finally:
        db.close()


def main() -> None:
    settings = get_settings()
    logger.info("ledger_compactor_started instance_id=%s", settings.instance_id)
    while True:
        run_once()
        time.sleep(settings.ledger_compaction_poll_interval_seconds)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
