"""Dedicated V18 full verification scrub worker."""

from __future__ import annotations

import logging
import time

from agentguard_server.config import get_settings, validate_configuration
from agentguard_server.db.session import get_session_factory
from agentguard_server.models import ArchiveReplica
from agentguard_server.services.archive import ArchiveKeyring
from agentguard_server.services.archive_store import archive_store_registry
from agentguard_server.services.replicas import list_replicas, scrub_replica
from sqlalchemy import select

logger = logging.getLogger("agentguard.replica.scrub")


def process_batch(limit: int = 100) -> int:
    settings = get_settings()
    with get_session_factory()() as db:
        rows = list(db.scalars(select(ArchiveReplica).order_by(ArchiveReplica.updated_at).limit(max(1, min(limit, 1000)))))
        bindings = archive_store_registry(settings)
        keyring = ArchiveKeyring.from_settings(settings)
        for row in rows:
            scrub_replica(db, row.id, stores=bindings, keyring=keyring, settings=settings)
        return len(rows)


def main() -> None:
    settings = validate_configuration(get_settings())
    logger.info("scrub_worker_started instance_id=%s", settings.instance_id)
    while True:
        if not process_batch():
            time.sleep(min(settings.archive_replica_scrub_interval_seconds, 300))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
