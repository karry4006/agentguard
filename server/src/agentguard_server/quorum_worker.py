"""V20 disposable/live coordinator entrypoint.

The durable job, lease, retry, receipt, and quorum semantics remain in the
V20 service module.  This process only supplies the runtime polling and HTTP
transport needed by the isolated acceptance topology.
"""

from __future__ import annotations

import http.client
import json
import logging
import time
from urllib.parse import urlparse

from sqlalchemy import select

from agentguard_server.config import get_settings, validate_configuration
from agentguard_server.db.session import get_session_factory
from agentguard_server.models import IntegrityCheckpoint, Witness, WitnessPublishJob, WitnessQuorumPolicy
from agentguard_server.services.quorum import WitnessUnavailable, claim_publish_job, process_publish_job, run_quorum_cycle


logger = logging.getLogger("agentguard.quorum.worker")


class HttpWitnessClient:
    def __init__(self, endpoint: str, *, timeout: float = 5.0) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise WitnessUnavailable("invalid test witness endpoint")
        self.host = parsed.hostname
        self.port = parsed.port or 80
        self.path = parsed.path.rstrip("/") or ""
        self.timeout = timeout

    def publish(self, request: dict) -> dict:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            body = json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            connection.request("POST", self.path + "/anchor", body=body,
                               headers={"Content-Type": "application/json", "Accept": "application/json"})
            response = connection.getresponse()
            raw = response.read(256 * 1024 + 1)
            if response.status >= 500 or response.status in {408, 425, 429}:
                raise WitnessUnavailable("witness temporarily unavailable")
            if response.status == 409:
                raise WitnessUnavailable("witness reported a conflict")
            if not 200 <= response.status < 300 or len(raw) > 256 * 1024:
                raise ValueError("witness response rejected")
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("witness response is not an object")
            return value
        except (OSError, TimeoutError) as exc:
            raise WitnessUnavailable("witness unavailable") from exc
        finally:
            connection.close()


def process_one_job() -> bool:
    settings = get_settings()
    with get_session_factory()() as db:
        job = claim_publish_job(db, worker_id=settings.instance_id, lease_seconds=settings.anchor_lease_seconds)
        if job is None:
            run_quorum_cycle(db, limit=100)
            return False
        checkpoint = db.get(IntegrityCheckpoint, job.checkpoint_id)
        policy = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == job.policy_epoch))
        witness = db.scalar(select(Witness).where(Witness.witness_id == job.witness_id, Witness.enabled.is_(True)))
        if checkpoint is None or policy is None or witness is None:
            logger.error("quorum_job_invalid job_id=%s", job.id)
            return False
        client = HttpWitnessClient(witness.endpoint_config_ref, timeout=settings.anchor_request_timeout_seconds)
        try:
            process_publish_job(db, job, client=client, checkpoint=checkpoint, policy=policy,
                                max_attempts=settings.anchor_retry_max_attempts,
                                base_seconds=settings.anchor_retry_base_seconds,
                                max_backoff_seconds=settings.anchor_retry_max_seconds)
        except Exception as exc:
            logger.warning("quorum_publish_failed job_id=%s witness_id=%s reason=%s", job.id, job.witness_id, type(exc).__name__)
        return True


def main() -> None:
    settings = validate_configuration(get_settings())
    logger.info("quorum_worker_started instance_id=%s", settings.instance_id)
    while True:
        if not process_one_job():
            time.sleep(min(settings.anchor_interval_seconds, 5))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
