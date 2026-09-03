"""Dedicated V19 compactor worker.

Only this process uses the compaction authorization path.  Runtime API
processes can plan and queue work but never perform the destructive step.
"""

from __future__ import annotations

import logging
import time

from agentguard_server.config import get_settings, validate_configuration
from agentguard_server.db.session import get_session_factory
from agentguard_server.services.integrity_segments import claim_integrity_compaction_job, process_integrity_compaction_job

logger = logging.getLogger("agentguard.integrity.compactor")


def process_one_job() -> bool:
    settings = get_settings()
    with get_session_factory()() as db:
        job = claim_integrity_compaction_job(db, settings=settings, instance_id=settings.instance_id)
        if job is None:
            return False
        process_integrity_compaction_job(db, job=job, settings=settings)
        return True


def main() -> None:
    settings = validate_configuration(get_settings())
    logger.info("integrity_compactor_started instance_id=%s", settings.instance_id)
    while True:
        if not process_one_job():
            time.sleep(min(settings.integrity_compaction_poll_interval_seconds, 30))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
