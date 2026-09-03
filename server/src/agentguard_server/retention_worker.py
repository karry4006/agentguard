"""Dedicated V16 retention worker entrypoint.

The worker has the only application path that may purge ``spans``. It never
deletes archive objects and performs network work outside database locks.
"""

from __future__ import annotations

import logging
import time
from datetime import timedelta

from agentguard_server.config import get_settings, validate_configuration
from agentguard_server.db.session import get_session_factory
from agentguard_server.services.archive import ArchiveVerificationError
from agentguard_server.services.retention import ARCHIVE_JOB, PURGE_JOB, archive_trace, claim_retention_job, configured_archive_store, purge_trace

logger = logging.getLogger("agentguard.retention")


def process_one_job(*, instance_id: str | None = None) -> bool:
    settings = get_settings()
    with get_session_factory()() as db:
        job = claim_retention_job(db, instance_id=instance_id or settings.instance_id)
        if job is None:
            return False
        store = configured_archive_store(settings)
        try:
            if job.job_type == ARCHIVE_JOB:
                record = archive_trace(db, tenant_id=job.tenant_id, trace_id=job.trace_id, store=store, settings=settings)
                job.archive_record_id = record.id
                job.status = "SUCCEEDED"
            elif job.job_type == PURGE_JOB:
                purge_trace(db, tenant_id=job.tenant_id, trace_id=job.trace_id, archive_id=job.archive_record_id, store=store, settings=settings)
                job.status = "SUCCEEDED"
            else:
                job.status = "FAILED"
                job.last_error_category = "UNSUPPORTED_JOB_TYPE"
        except ArchiveVerificationError as exc:
            job.status = "RETRY_WAIT"
            job.last_error_category = exc.status
            job.next_attempt_at = time_to_datetime() + timedelta(seconds=min(3600, 2 ** min(job.attempt_count, 10)))
            logger.warning("retention_job_failed job_id=%s category=%s", job.id, exc.status)
        except Exception as exc:
            job.status = "RETRY_WAIT"
            job.last_error_category = type(exc).__name__[:64]
            job.next_attempt_at = time_to_datetime() + timedelta(seconds=min(3600, 2 ** min(job.attempt_count, 10)))
            logger.warning("retention_job_failed job_id=%s category=%s", job.id, type(exc).__name__)
        job.claimed_by = job.claim_token = job.claimed_at = job.lease_expires_at = None
        job.updated_at = time_to_datetime()
        db.commit()
        return True


def time_to_datetime():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def main() -> None:
    settings = validate_configuration(get_settings())
    logger.info("retention_worker_started instance_id=%s", settings.instance_id)
    while True:
        if not process_one_job(instance_id=settings.instance_id):
            time.sleep(min(settings.archive_interval_seconds, 30))


if __name__ == "__main__":
    main()
