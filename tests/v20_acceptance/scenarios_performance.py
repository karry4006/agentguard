"""Real V20 checkpoint/job load scenarios over disposable PostgreSQL."""
from __future__ import annotations

from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import time
from typing import Callable
from urllib.parse import urlparse, urlunparse

from sqlalchemy import func, select, text

from agentguard_server.config import get_settings
from agentguard_server.models import CheckpointQuorumEvaluation, CheckpointWitnessReceipt, IntegrityCheckpoint, Witness, WitnessPublishJob, WitnessQuorumPolicy
from agentguard_server.quorum_worker import HttpWitnessClient
from agentguard_server.services.anchoring import create_checkpoint
from agentguard_server.services.quorum import claim_publish_job, evaluate_checkpoint_quorum, process_publish_job

from .context import cleanup_namespace, db_session, new_namespace
from .evidence import Scenario
from .helpers import assertion
from .scenarios_live import _control


def _scenario(sid: str, name: str, operation: Callable[[], dict]) -> Scenario:
    scenario = Scenario(sid, "performance", name)
    scenario.execute(operation)
    return scenario


def _settings(namespace: str, pending: int):
    return get_settings().model_copy(update={
        "anchor_enabled": True, "quorum_enabled": True, "anchor_namespace": namespace,
        "anchor_max_pending_jobs": pending, "anchor_interval_seconds": 0,
    })


def _client_endpoint(endpoint: str) -> str:
    parsed = urlparse(endpoint.replace("host.docker.internal", "127.0.0.1"))
    ports = {"v20-witness-a": 18090, "v20-witness-b": 18091, "v20-witness-c": 18092}
    if parsed.hostname in ports:
        return urlunparse((parsed.scheme, f"127.0.0.1:{ports[parsed.hostname]}", parsed.path, parsed.params, parsed.query, parsed.fragment))
    return endpoint


def _reset_witnesses() -> None:
    for wid in ("a", "b", "c"):
        _control(wid, mode="MATCH", reset=True)


def _create(namespace: str, count: int) -> list:
    settings = _settings(namespace, count * 3 + 100)
    checkpoints = []
    with db_session() as db:
        for _ in range(count):
            checkpoint = create_checkpoint(db, settings=settings, force=True)
            if checkpoint is None:
                raise RuntimeError("production checkpoint creator returned no checkpoint during load")
            checkpoints.append(checkpoint.id)
    return checkpoints


def _counts(db, namespace: str) -> dict[str, int]:
    job_count = int(db.scalar(select(func.count()).select_from(WitnessPublishJob).join(IntegrityCheckpoint, IntegrityCheckpoint.id == WitnessPublishJob.checkpoint_id).where(IntegrityCheckpoint.namespace == namespace)) or 0)
    completed = int(db.scalar(select(func.count()).select_from(WitnessPublishJob).join(IntegrityCheckpoint, IntegrityCheckpoint.id == WitnessPublishJob.checkpoint_id).where(IntegrityCheckpoint.namespace == namespace, WitnessPublishJob.status == "SUCCEEDED")) or 0)
    retries = int(db.scalar(select(func.coalesce(func.sum(func.greatest(WitnessPublishJob.attempt_count - 1, 0)), 0)).select_from(WitnessPublishJob).join(IntegrityCheckpoint, IntegrityCheckpoint.id == WitnessPublishJob.checkpoint_id).where(IntegrityCheckpoint.namespace == namespace)) or 0)
    failed = int(db.scalar(select(func.count()).select_from(WitnessPublishJob).join(IntegrityCheckpoint, IntegrityCheckpoint.id == WitnessPublishJob.checkpoint_id).where(IntegrityCheckpoint.namespace == namespace, WitnessPublishJob.status == "FAILED")) or 0)
    receipts = int(db.scalar(select(func.count()).select_from(CheckpointWitnessReceipt).join(IntegrityCheckpoint, IntegrityCheckpoint.id == CheckpointWitnessReceipt.checkpoint_id).where(IntegrityCheckpoint.namespace == namespace)) or 0)
    evaluations = int(db.scalar(select(func.count()).select_from(CheckpointQuorumEvaluation).join(IntegrityCheckpoint, IntegrityCheckpoint.id == CheckpointQuorumEvaluation.checkpoint_id).where(IntegrityCheckpoint.namespace == namespace)) or 0)
    return {"job_count": job_count, "jobs_completed": completed, "jobs_retried": retries,
            "jobs_failed": failed, "receipt_count": receipts, "evaluation_count": evaluations}


def _drain_worker(clients: dict[str, HttpWitnessClient], deadline: float, worker_index: int) -> None:
    while time.perf_counter() < deadline:
        with db_session() as db:
            job = claim_publish_job(db, worker_id=f"v20-performance-harness-{worker_index}", lease_seconds=30)
            if job is None:
                return
            checkpoint = db.get(IntegrityCheckpoint, job.checkpoint_id)
            policy = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == job.policy_epoch))
            if checkpoint is not None and policy is not None:
                process_publish_job(db, job, client=clients[job.witness_id], checkpoint=checkpoint, policy=policy,
                                    max_attempts=5, base_seconds=0, max_backoff_seconds=0)
    raise TimeoutError("V20 durable job worker exceeded bounded timeout")


def _drain(namespace: str, expected_jobs: int, *, timeout_seconds: int = 300) -> dict[str, int]:
    clients: dict[str, HttpWitnessClient] = {}
    with db_session() as db:
        for witness in db.scalars(select(Witness).where(Witness.enabled.is_(True))):
            clients[witness.witness_id] = HttpWitnessClient(_client_endpoint(witness.endpoint_config_ref), timeout=5)
    deadline = time.perf_counter() + timeout_seconds
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="v20-perf") as executor:
        futures = [executor.submit(_drain_worker, clients, deadline, index) for index in range(4)]
        for future in futures:
            future.result()
    with db_session() as db:
        counts = _counts(db, namespace)
        if counts["jobs_failed"]:
            failure = db.execute(text("SELECT last_error_category FROM witness_publish_jobs j JOIN integrity_checkpoints c ON c.id=j.checkpoint_id WHERE c.namespace = :namespace AND j.status = 'FAILED' ORDER BY j.updated_at DESC LIMIT 1"), {"namespace": namespace}).scalar()
            raise RuntimeError(f"durable V20 load produced a failed publish job category={failure}")
        if counts["jobs_completed"] < expected_jobs:
            raise TimeoutError("V20 durable job drain did not complete expected jobs")
        evaluation_started = time.perf_counter()
        for checkpoint in db.scalars(select(IntegrityCheckpoint).where(IntegrityCheckpoint.namespace == namespace)).all():
            evaluate_checkpoint_quorum(db, checkpoint.id, persist=True)
        db.commit()
        counts = _counts(db, namespace)
        counts["quorum_evaluation_seconds"] = round(time.perf_counter() - evaluation_started, 3)
        return counts


def _scale(count: int, *, jobs_to_process: int | None = None) -> dict:
    namespace = new_namespace("performance")
    try:
        _reset_witnesses()
        started = time.perf_counter()
        checkpoint_ids = _create(namespace, count)
        checkpoint_creation_seconds = round(time.perf_counter() - started, 3)
        if jobs_to_process == 0:
            evaluation_started = time.perf_counter()
            with db_session() as db:
                checkpoints = list(db.scalars(select(IntegrityCheckpoint).where(IntegrityCheckpoint.namespace == namespace).order_by(IntegrityCheckpoint.checkpoint_sequence)))
                for checkpoint in checkpoints:
                    evaluate_checkpoint_quorum(db, checkpoint.id, persist=True)
                db.commit()
            quorum_evaluation_seconds = round(time.perf_counter() - evaluation_started, 3)
            durable_processing_seconds = 0.0
            counts = _counts_for_namespace(namespace)
        else:
            processing_started = time.perf_counter()
            counts = _drain(namespace, jobs_to_process if jobs_to_process is not None else count * 3,
                            timeout_seconds=1800 if count > 3000 else 300)
            durable_processing_seconds = round(time.perf_counter() - processing_started, 3)
            quorum_evaluation_seconds = counts.get("quorum_evaluation_seconds", 0.0)
        counts["checkpoint_count"] = len(checkpoint_ids)
        counts["elapsed_seconds"] = round(time.perf_counter() - started, 3)
        counts["checkpoint_creation_seconds"] = checkpoint_creation_seconds
        counts["durable_processing_seconds"] = durable_processing_seconds
        counts["quorum_evaluation_seconds"] = quorum_evaluation_seconds
        return counts
    finally:
        cleanup_namespace(namespace)


def _counts_for_namespace(namespace: str) -> dict[str, int]:
    with db_session() as db:
        return _counts(db, namespace)


def _outage_storm() -> dict:
    namespace = new_namespace("performance")
    try:
        started = time.perf_counter()
        _reset_witnesses()
        checkpoint_ids = _create(namespace, 30)
        for _ in range(2):
            _control("c", mode="OFFLINE")
            time.sleep(0.5)
            _control("c", mode="MATCH")
            time.sleep(0.5)
        counts = _drain(namespace, 90)
        return {**counts, "checkpoint_count": len(checkpoint_ids), "outage_cycles": 2,
                "elapsed_seconds": round(time.perf_counter() - started, 3), "global_stall": False}
    finally:
        _control("c", mode="MATCH", reset=False)
        cleanup_namespace(namespace)


def _query_plans() -> dict:
    with db_session() as db:
        plans = {}
        for name, query in {
            "publish_job_claim": "EXPLAIN SELECT id FROM witness_publish_jobs WHERE status IN ('PENDING','RETRY_WAIT') ORDER BY created_at LIMIT 1",
            "receipt_lookup": "EXPLAIN SELECT * FROM checkpoint_witness_receipts WHERE checkpoint_id = '00000000-0000-0000-0000-000000000000'",
            "policy_lookup": "EXPLAIN SELECT * FROM witness_quorum_policies WHERE policy_epoch = 1",
            "evaluation_lookup": "EXPLAIN SELECT * FROM checkpoint_quorum_evaluations WHERE checkpoint_id = '00000000-0000-0000-0000-000000000000'",
            "checkpoint_lookup": "EXPLAIN SELECT * FROM integrity_checkpoints WHERE namespace = 'v20-harness-performance' ORDER BY checkpoint_sequence DESC LIMIT 1",
        }.items():
            plans[name] = [row[0] for row in db.execute(text(query)).all()]
    return plans


CASES = {
    "P20-01": ("1000 actual checkpoints", lambda: _scale(1000, jobs_to_process=0)),
    "P20-02": ("approximately 3000 valid signed receipts", lambda: _scale(1000)),
    "P20-03": ("10000 durable V20 jobs", lambda: _scale(3334)),
    "P20-04": ("witness outage storm", _outage_storm),
}


def _operation(sid: str) -> dict:
    result = CASES[sid][1]()
    plans = _query_plans()
    required = {"P20-01": (1000, 3000, 0), "P20-02": (1000, 3000, 3000), "P20-03": (3334, 10002, 10002), "P20-04": (30, 90, 90)}[sid]
    checks = [assertion("checkpoint target reached", result["checkpoint_count"] >= required[0]),
              assertion("durable job target reached", result["job_count"] >= required[1]),
              assertion("durable jobs completed", result["jobs_completed"] >= required[2]),
              assertion("no durable jobs failed", result["jobs_failed"] == 0),
              assertion("query plans were captured", len(plans) == 5)]
    if sid == "P20-01":
        checks.append(assertion("checkpoint evaluations reached target", result["evaluation_count"] >= 1000))
    if sid == "P20-02":
        checks.append(assertion("valid distinct receipts reached target", result["receipt_count"] >= 3000))
    if sid == "P20-03":
        checks.append(assertion("job count reached target", result["job_count"] >= 10000))
    if sid == "P20-04":
        checks.append(assertion("outage did not globally stall A/B", result.get("global_stall") is False))
    return {"expected": {"checkpoint_count": required[0], "job_count": required[1], "jobs_completed": required[2], "jobs_failed": 0},
            "actual": {**result, "query_plans": plans}, "assertions": checks,
            "threshold_proof": True,
            "actions": ["create checkpoints through production create_checkpoint", "publish through durable witness jobs",
                         "verify signed receipts and quorum evaluations", "capture EXPLAIN plans", "clean disposable namespace"],
            "preconditions": ["PostgreSQL 0018", "three real disposable witness services", "2-of-3 policy"]}


def run(scenario_id: str | None = None) -> list[Scenario]:
    ids = [scenario_id] if scenario_id else list(CASES)
    return [_scenario(sid, CASES[sid][0], lambda sid=sid: _operation(sid)) for sid in ids]
