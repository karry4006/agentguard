"""Dedicated V18 replication worker entrypoint."""

from __future__ import annotations

import logging
import time

from agentguard_server.config import get_settings, validate_configuration
from agentguard_server.db.session import get_session_factory
from agentguard_server.services.archive import ArchiveKeyring
from agentguard_server.services.archive_store import archive_store_registry
from agentguard_server.services.replicas import claim_replication_job, process_replication_job

logger = logging.getLogger("agentguard.replica.worker")


def process_one_job(*, instance_id: str | None = None) -> bool:
    settings = get_settings()
    with get_session_factory()() as db:
        job = claim_replication_job(db, settings=settings, instance_id=instance_id or settings.instance_id)
        if job is None:
            return False
        process_replication_job(db, job=job, stores=archive_store_registry(settings), keyring=ArchiveKeyring.from_settings(settings), settings=settings)
        return True


def main() -> None:
    settings = validate_configuration(get_settings())
    logger.info("replica_worker_started instance_id=%s", settings.instance_id)
    while True:
        if not process_one_job(instance_id=settings.instance_id):
            time.sleep(min(settings.archive_replica_poll_interval_seconds, 30))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
