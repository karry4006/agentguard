"""Secret-safe runtime context for disposable V20 acceptance scenarios."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import subprocess
import time
from typing import Iterator
from uuid import uuid4

import httpx
from sqlalchemy import create_engine, delete, select, text
from sqlalchemy.orm import Session, sessionmaker

from agentguard_server.models import IntegrityCheckpoint, WitnessQuorumPolicy
from agentguard_server.services.anchoring import CHECKPOINT_VERSION, checkpoint_digest, manifest_digest
from agentguard_server.services.quorum import enqueue_publish_jobs, record_receipt

ROOT = Path(__file__).resolve().parents[2]
WITNESSES = {"a": "http://127.0.0.1:18090", "b": "http://127.0.0.1:18091", "c": "http://127.0.0.1:18092"}


def load_env_file(path: Path) -> None:
    """Load the disposable env file without ever logging its values."""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ[key.strip()] = value
    test_database = os.getenv("AGENTGUARD_TEST_DATABASE_URL")
    if test_database:
        os.environ["DATABASE_URL"] = test_database
        os.environ["AGENTGUARD_DATABASE_URL"] = test_database
    os.environ["V20_ACCEPTANCE_ENV_FILE"] = str(path)
    try:
        from agentguard_server.config import get_settings
        get_settings.cache_clear()
    except ImportError:
        pass


def _url(setup: bool = False) -> str:
    value = os.getenv("AGENTGUARD_TEST_SETUP_DATABASE_URL" if setup else "AGENTGUARD_TEST_DATABASE_URL")
    if not value:
        raise RuntimeError("V20 acceptance requires --env-file with a disposable PostgreSQL URL")
    return value


@contextmanager
def db_session(*, setup: bool = False) -> Iterator[Session]:
    engine = create_engine(_url(setup), pool_pre_ping=True)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@contextmanager
def session_for_url(url: str) -> Iterator[Session]:
    engine = create_engine(url, pool_pre_ping=True)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def new_namespace(suite: str) -> str:
    return f"v20-harness-{suite}-{uuid4().hex[:12]}"


def create_fixture_checkpoint(db: Session, *, namespace: str, sequence: int | None = None) -> IntegrityCheckpoint:
    policy = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == 1))
    if policy is None:
        raise RuntimeError("disposable database has no V20 epoch-1 policy")
    now = datetime.now(timezone.utc)
    sequence = sequence or int(uuid4().int % 1_000_000_000) + 1
    manifest = manifest_digest([])
    digest = checkpoint_digest(namespace=namespace, checkpoint_sequence=sequence,
                               manifest_digest_value=manifest, previous_checkpoint_digest=None,
                               created_at=now, entry_count=0)
    checkpoint = IntegrityCheckpoint(namespace=namespace, checkpoint_sequence=sequence,
        checkpoint_version=CHECKPOINT_VERSION, manifest_digest=manifest,
        previous_checkpoint_digest=None, checkpoint_digest=digest, entry_count=0,
        policy_epoch=policy.policy_epoch, policy_digest=policy.policy_digest, created_at=now)
    db.add(checkpoint)
    db.flush()
    enqueue_publish_jobs(db, checkpoint=checkpoint, policy=policy, now=now)
    db.commit()
    db.refresh(checkpoint)
    return checkpoint


def witness_receipt(witness: str, checkpoint: IntegrityCheckpoint, *, mode: str = "MATCH") -> dict:
    response = httpx.post(WITNESSES[witness] + "/anchor", json={
        "receipt_version": "multi-witness-receipt-v1", "witness_id": f"v20-witness-{witness}",
        "policy_epoch": checkpoint.policy_epoch, "checkpoint_sequence": checkpoint.checkpoint_sequence,
        "checkpoint_digest": checkpoint.checkpoint_digest,
    }, timeout=5)
    response.raise_for_status()
    return response.json()


def record_witnesses(db: Session, checkpoint: IntegrityCheckpoint, witnesses: tuple[str, ...] = ("a", "b", "c")) -> None:
    policy = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == checkpoint.policy_epoch))
    if policy is None:
        raise RuntimeError("fixture policy disappeared")
    for witness in witnesses:
        record_receipt(db, checkpoint=checkpoint, policy=policy, receipt=witness_receipt(witness, checkpoint))
    db.commit()


def cleanup_namespace(namespace: str) -> None:
    with db_session(setup=True) as db:
        db.execute(text("DELETE FROM integrity_checkpoints WHERE namespace = :namespace"), {"namespace": namespace})
        db.commit()


def safe_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def docker_logs() -> str:
    env_file = os.getenv("V20_ACCEPTANCE_ENV_FILE")
    if not env_file:
        raise RuntimeError("container log evidence requires --env-file")
    command = ["docker", "compose", "-f", str(ROOT / "compose.yaml"), "-f", str(ROOT / "tests" / "compose.v20-live.yaml"),
               "--env-file", env_file, "logs", "--no-color", "--tail", "500",
               "agentguard-server-v20", "agentguard-quorum-worker-a", "agentguard-quorum-worker-b",
               "v20-witness-a", "v20-witness-b", "v20-witness-c"]
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=30, check=False)
    if result.returncode == 0:
        return result.stdout
    fallback = []
    for container in ("agentguard-server-v20-1", "agentguard-quorum-worker-a-1", "agentguard-quorum-worker-b-1",
                      "agentguard-v20-witness-a-1", "agentguard-v20-witness-b-1", "agentguard-v20-witness-c-1"):
        direct = subprocess.run(["docker", "logs", "--tail", "500", container], cwd=ROOT,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                timeout=15, check=False)
        if direct.returncode == 0:
            fallback.append(direct.stdout)
    if not fallback:
        raise RuntimeError("disposable container logs unavailable")
    return "\n".join(fallback)
