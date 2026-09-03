"""Real V16--V19 archive history construction for V20 acceptance tests.

This module is setup infrastructure only.  It deliberately does not create
catalog rows or lifecycle states by hand.  Every archive, replica, quorum
binding, and compaction transition is produced by the production services.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from typing import Iterable
from uuid import UUID, uuid4

import httpx
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from agentguard_server.config import Settings, get_settings
from agentguard_server.models import (
    ArchiveRecord,
    ArchiveReplicationJob,
    ArchiveReplica,
    IntegrityAnchorJob,
    IntegrityArchiveSegment,
    IntegrityCheckpoint,
    LedgerSegment,
    LedgerSegmentLifecycle,
    Tenant,
    Trace,
)
from agentguard_server.schemas.events import Event
from agentguard_server.services.archive import ArchiveKeyring
from agentguard_server.services.archive_store import ArchiveStoreBinding, archive_store_registry
from agentguard_server.services.anchoring import (
    HttpSignedWitnessProvider,
    anchor_job,
    create_checkpoint,
    verify_checkpoint,
)
from agentguard_server.services.auth import create_tenant
from agentguard_server.services.ingestion import ingest_events
from agentguard_server.services.integrity_segments import (
    archive_integrity_segment,
    authorize_integrity_compaction,
    compact_integrity_segment,
    create_integrity_segment_candidate,
)
from agentguard_server.services.ledger import (
    archive_ledger_segment,
    authorize_ledger_compaction,
    compact_ledger_segment,
    create_ledger_segment_candidate,
    verify_mixed_ledger,
)
from agentguard_server.services.quorum import (
    enqueue_publish_jobs,
    ensure_configured_policy,
    evaluate_checkpoint_quorum,
)
from agentguard_server.services.replicas import (
    claim_replication_job,
    list_replicas,
    process_replication_job,
    replica_policy_passes,
    verified_replica_count,
)

from .context import WITNESSES, record_witnesses


@dataclass
class ArchiveFixture:
    """Safe handles for a disposable, production-built archive history."""

    tenant_id: UUID
    trace_id: str
    namespace: str
    checkpoint_id: UUID
    archive_id: UUID | None
    ledger_segment_id: UUID | None
    integrity_segment_id: UUID | None
    settings: Settings = field(repr=False)
    provider: HttpSignedWitnessProvider = field(repr=False)
    stores: dict[str, ArchiveStoreBinding] = field(repr=False)
    keyring: ArchiveKeyring = field(repr=False)

    @property
    def primary_store(self):
        return self.stores[self.settings.archive_primary_store_id].store


def cleanup_archive_fixture(db: Session, fixture: ArchiveFixture) -> None:
    """Remove only this disposable tenant after its evidence is captured."""
    db.rollback()
    db.execute(text("DELETE FROM tenants WHERE id = :tenant_id"), {"tenant_id": str(fixture.tenant_id)})
    db.commit()


def _secret_file(name: str, *, json_value: bool = False) -> str:
    """Read a disposable host secret without exposing it to output."""
    path = os.getenv(name) or os.getenv(name.replace("_HOST_FILE", "_FILE"))
    if not path:
        raise RuntimeError(f"missing disposable secret-file reference: {name}")
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value or "\n" in value or "\r" in value:
        raise RuntimeError(f"invalid disposable secret-file content: {name}")
    if json_value:
        parsed = json.loads(value)
        if not isinstance(parsed, dict) or not parsed:
            raise RuntimeError("archive encryption key registry is invalid")
    return value


def _v15_settings(base: Settings, namespace: str) -> Settings:
    public = httpx.get("http://127.0.0.1:18080/public-key", timeout=5)
    public.raise_for_status()
    key = public.json()
    if not isinstance(key, dict) or not key.get("signer_key_id") or not key.get("public_key"):
        raise RuntimeError("V15 witness public key response is invalid")
    return _settings(base, namespace, anchor_verify_keys=json.dumps({key["signer_key_id"]: key["public_key"]}), quorum_enabled=False)


def _settings(base: Settings, namespace: str, *, anchor_verify_keys: str,
              quorum_enabled: bool, bucket: str | None = None) -> Settings:
    bucket = bucket or f"agentguard-v20-{uuid4().hex[:20]}"
    store_b_access = os.getenv("MINIO_B_ROOT_USER")
    store_b_secret = os.getenv("MINIO_B_ROOT_PASSWORD")
    if not store_b_access or not store_b_secret:
        raise RuntimeError("disposable Store B credentials are unavailable")
    os.environ["V20_FIXTURE_STORE_B_ACCESS"] = store_b_access
    os.environ["V20_FIXTURE_STORE_B_SECRET"] = store_b_secret
    registry = json.dumps([{
        "store_id": "store_b",
        "endpoint": "http://127.0.0.1:19011",
        "bucket": bucket,
        "access_key_env": "V20_FIXTURE_STORE_B_ACCESS",
        "secret_key_env": "V20_FIXTURE_STORE_B_SECRET",
        "priority": 1,
    }], separators=(",", ":"))
    return base.model_copy(update={
        "database_url": os.getenv("AGENTGUARD_TEST_DATABASE_URL") or base.database_url,
        "environment": "test",
        "key_pepper": _secret_file("AGENTGUARD_KEY_PEPPER_HOST_FILE"),
        "integrity_key": _secret_file("AGENTGUARD_INTEGRITY_KEY_HOST_FILE"),
        "anchor_enabled": True,
        "anchor_endpoint": "http://127.0.0.1:18080/anchor",
        "anchor_namespace": namespace,
        "anchor_verify_keys": anchor_verify_keys,
        "anchor_verify_keys_file": None,
        "allow_private_anchor_tests": True,
        "quorum_enabled": quorum_enabled,
        "quorum_threshold": 2,
        "quorum_policy_epoch": 1,
        "quorum_witness_registry": base.quorum_witness_registry,
        "archive_enabled": True,
        "retention_purge_enabled": True,
        "archive_after_days": 0,
        "purge_after_days": 0,
        "retention_finalization_grace_days": 0,
        "archive_store_endpoint": "http://127.0.0.1:19010",
        "archive_store_bucket": bucket,
        "archive_store_access_key": os.getenv("MINIO_A_ROOT_USER"),
        "archive_store_secret_key": os.getenv("MINIO_A_ROOT_PASSWORD"),
        "archive_store_access_key_file": None,
        "archive_store_secret_key_file": None,
        "archive_store_registry": registry,
        "archive_encryption_keys": _secret_file("AGENTGUARD_ARCHIVE_ENCRYPTION_KEYS_HOST_FILE", json_value=True),
        "archive_encryption_keys_file": None,
        "archive_encryption_key_id": base.archive_encryption_key_id or "archive-key-v1",
        "allow_private_archive_tests": True,
        "archive_replication_enabled": True,
        "archive_minimum_verified_replicas": 2,
        "archive_replica_repair_enabled": True,
        "archive_primary_store_id": "primary",
        "ledger_archive_enabled": True,
        "ledger_compaction_enabled": True,
        "ledger_segment_min_age_days": 0,
        "ledger_hot_tail_events": 1,
        "ledger_compaction_replica_policy_enabled": True,
        "integrity_segment_compaction_enabled": True,
        "integrity_segment_min_age_days": 0,
        "integrity_hot_tail_records": 1,
    })


def _create_buckets(settings: Settings) -> None:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError

    stores = (
        ("http://127.0.0.1:19010", os.getenv("MINIO_A_ROOT_USER"), os.getenv("MINIO_A_ROOT_PASSWORD")),
        ("http://127.0.0.1:19011", os.getenv("MINIO_B_ROOT_USER"), os.getenv("MINIO_B_ROOT_PASSWORD")),
    )
    for endpoint, access, secret in stores:
        if not access or not secret:
            raise RuntimeError("disposable MinIO credentials are unavailable")
        client = boto3.client("s3", endpoint_url=endpoint, region_name="us-east-1",
                              aws_access_key_id=access, aws_secret_access_key=secret,
                              config=Config(signature_version="s3v4"))
        try:
            client.head_bucket(Bucket=settings.archive_store_bucket)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code not in {"404", "NoSuchBucket", "NotFound"}:
                raise
            client.create_bucket(Bucket=settings.archive_store_bucket)


def _reset_v20_witnesses() -> None:
    token = os.getenv("V20_TEST_CONTROL_TOKEN", "v20-harness-control")
    for witness in WITNESSES.values():
        response = httpx.post(witness + "/control", headers={"X-V20-Control-Token": token},
                              json={"mode": "MATCH", "reset": True}, timeout=5)
        response.raise_for_status()


def _events(trace_id: str, occurred_at: datetime) -> list[Event]:
    values = [Event(event_type="trace.started", event_id=f"{trace_id}-trace-started",
                    occurred_at=occurred_at, data={"trace_id": trace_id, "workflow_name": "v20-archive-fixture", "status": "running"})]
    for index in range(1, 7):
        span_id = f"{trace_id}-span-{index}"
        values.append(Event(event_type="span.started", event_id=f"{span_id}-started", occurred_at=occurred_at,
                            data={"trace_id": trace_id, "span_id": span_id, "span_type": "tool", "name": f"fixture-{index}", "status": "running"}))
        values.append(Event(event_type="span.ended", event_id=f"{span_id}-ended", occurred_at=occurred_at,
                            data={"trace_id": trace_id, "span_id": span_id, "span_type": "tool", "name": f"fixture-{index}", "status": "completed", "duration_ms": 1.0}))
    values.append(Event(event_type="trace.ended", event_id=f"{trace_id}-trace-ended", occurred_at=occurred_at,
                        data={"trace_id": trace_id, "status": "completed"}))
    return values


def _replicate_tenant(db: Session, *, tenant_id: UUID, settings: Settings,
                      stores: dict[str, ArchiveStoreBinding], keyring: ArchiveKeyring,
                      now: datetime) -> None:
    """Drain only this fixture's durable V18 jobs through the worker service."""
    for _ in range(16):
        jobs = list(db.scalars(select(ArchiveReplicationJob).where(
            ArchiveReplicationJob.tenant_id == tenant_id,
            ArchiveReplicationJob.status.in_(("PENDING", "RETRY_WAIT", "IN_FLIGHT")),
        ).order_by(ArchiveReplicationJob.created_at)))
        if not jobs:
            return
        for job in jobs:
            # Claiming is a production worker operation.  If a job is already
            # leased by the live worker, use the normal claim path after its
            # lease is available rather than mutating the job state.
            claimed = claim_replication_job(db, settings=settings, instance_id="v20-archive-fixture", now=now)
            if claimed is None:
                raise RuntimeError("fixture replication job could not be claimed")
            if claimed.id != job.id:
                # It can only be an unrelated pre-existing job; process the
                # claimed job through production and continue draining ours.
                process_replication_job(db, job=claimed, stores=stores, keyring=keyring, settings=settings, now=now)
                continue
            if not process_replication_job(db, job=claimed, stores=stores, keyring=keyring, settings=settings, now=now):
                raise RuntimeError("fixture replication job failed closed")
    raise RuntimeError("fixture replication jobs did not drain")


def _assert_replicas(db: Session, *, tenant_id: UUID, archive_type: str, archive_id: UUID,
                     settings: Settings, now: datetime) -> None:
    rows = list_replicas(db, tenant_id=tenant_id, logical_archive_type=archive_type, logical_archive_id=archive_id)
    if {row.store_id for row in rows if row.state == "VALID"} != {"primary", "store_b"}:
        raise RuntimeError(f"fixture did not produce two verified replicas: {archive_type}")
    if verified_replica_count(db, tenant_id=tenant_id, logical_archive_type=archive_type,
                              logical_archive_id=archive_id, settings=settings, now=now) != 2:
        raise RuntimeError(f"fixture replica freshness check failed: {archive_type}")
    if not replica_policy_passes(db, tenant_id=tenant_id, logical_archive_type=archive_type,
                                 logical_archive_id=archive_id, settings=settings, now=now):
        raise RuntimeError(f"fixture replica policy failed: {archive_type}")


def build_archive_fixture(
    db: Session,
    *,
    build_v16: bool = True,
    build_v17: bool = True,
    compact_v17: bool = True,
    build_v19: bool = True,
    compact_v19: bool = True,
    v20_witnesses: tuple[str, ...] = ("a", "b", "c"),
) -> ArchiveFixture:
    """Build a fresh real archive history and return only safe object handles.

    ``compact_v17`` and ``compact_v19`` are scenario setup controls.  When a
    scenario needs to execute a destructive operation itself, it requests the
    corresponding archive to remain ``ARCHIVED_VERIFIED``/``READY_TO_COMPACT``
    and performs authorization and compaction outside this helper.
    """
    if not v20_witnesses or not set(v20_witnesses) <= set(WITNESSES):
        raise ValueError("fixture witness selection is invalid")
    _reset_v20_witnesses()
    # In the disposable compose environment the host-facing env file uses
    # *_HOST_FILE names.  In-process production helpers such as ingestion's
    # V3 append path resolve the standard settings object, so load the same
    # external secrets into this process-only environment before that object
    # is first used.  Values are never returned, logged, or persisted.
    os.environ["AGENTGUARD_KEY_PEPPER"] = _secret_file("AGENTGUARD_KEY_PEPPER_HOST_FILE")
    os.environ["AGENTGUARD_INTEGRITY_KEY"] = _secret_file("AGENTGUARD_INTEGRITY_KEY_HOST_FILE")
    os.environ["AGENTGUARD_ARCHIVE_ENCRYPTION_KEYS"] = _secret_file(
        "AGENTGUARD_ARCHIVE_ENCRYPTION_KEYS_HOST_FILE", json_value=True,
    )
    get_settings.cache_clear()
    base = get_settings()
    namespace = f"v20-archive-fixture-{uuid4().hex[:16]}"
    v15 = _v15_settings(base, namespace)
    settings = _settings(base, namespace, anchor_verify_keys=v15.anchor_verify_keys or "{}",
                         quorum_enabled=True, bucket=v15.archive_store_bucket)
    _create_buckets(settings)
    stores = archive_store_registry(settings)
    if set(stores) != {"primary", "store_b"}:
        raise RuntimeError("fixture archive store registry is incomplete")
    keyring = ArchiveKeyring.from_settings(settings)
    provider = HttpSignedWitnessProvider(v15)
    now = datetime.now(timezone.utc)
    historical = now - timedelta(days=30)
    tenant = create_tenant(db, f"v20-fixture-{uuid4().hex[:20]}", "V20 real archive fixture")
    trace_id = f"v20-fixture-trace-{uuid4().hex}"
    ingest_events(db, _events(trace_id, historical), tenant.id)

    checkpoint = create_checkpoint(db, settings=v15, force=True, now=now)
    if checkpoint is None:
        raise RuntimeError("V15 fixture checkpoint was not created")
    anchor = db.scalar(select(IntegrityAnchorJob).where(IntegrityAnchorJob.checkpoint_id == checkpoint.id))
    if anchor is None or anchor_job(db, anchor.id, provider, settings=v15, now=now) is None:
        raise RuntimeError("V15 fixture anchor job did not complete")
    if verify_checkpoint(db, checkpoint.id, settings=v15).get("status") != "VALID":
        raise RuntimeError("V15 fixture checkpoint did not verify")

    policy = ensure_configured_policy(db, settings=settings, now=now)
    if policy is None:
        raise RuntimeError("V20 fixture policy was not configured")
    checkpoint.policy_epoch = policy.policy_epoch
    checkpoint.policy_digest = policy.policy_digest
    enqueue_publish_jobs(db, checkpoint=checkpoint, policy=policy, now=now)
    db.commit()
    record_witnesses(db, checkpoint, v20_witnesses)
    quorum = evaluate_checkpoint_quorum(db, checkpoint.id, now=now, persist=True)
    if quorum.state not in {"QUORUM_MATCH", "QUORUM_MATCH_DEGRADED"}:
        raise RuntimeError(f"V20 fixture quorum did not match: {quorum.state}")

    operation_now = now + timedelta(seconds=2)
    archive = None
    if build_v16 or build_v17 or build_v19:
        from agentguard_server.services.retention import archive_trace
        archive = archive_trace(db, tenant_id=tenant.id, trace_id=trace_id,
                                store=stores["primary"].store, settings=settings, now=operation_now)
        _replicate_tenant(db, tenant_id=tenant.id, settings=settings, stores=stores, keyring=keyring, now=operation_now)
        _assert_replicas(db, tenant_id=tenant.id, archive_type="TRACE_ARCHIVE",
                         archive_id=archive.id, settings=settings, now=operation_now)

    ledger = None
    if build_v17:
        ledger = create_ledger_segment_candidate(db, tenant_id=tenant.id, trace_id=trace_id,
                                                 settings=settings, now=operation_now)
        archive_ledger_segment(db, ledger.id, stores["primary"].store, provider=provider,
                               settings=settings, keyring=keyring, now=operation_now)
        _replicate_tenant(db, tenant_id=tenant.id, settings=settings, stores=stores, keyring=keyring, now=operation_now)
        _assert_replicas(db, tenant_id=tenant.id, archive_type="LEDGER_SEGMENT",
                         archive_id=ledger.id, settings=settings, now=operation_now)
        if compact_v17:
            authorize_ledger_compaction(db, ledger.id, provider=provider, settings=settings,
                                        keyring=keyring, store=stores["primary"].store, now=operation_now)
            deleted = compact_ledger_segment(db, ledger.id, settings=settings, now=operation_now)
            db.refresh(ledger)
            if deleted <= 0 or db.get(LedgerSegmentLifecycle, ledger.id).status != "COMPACTED":
                raise RuntimeError("V17 fixture compaction did not complete")

    integrity = None
    if build_v19:
        if ledger is None or not compact_v17:
            raise ValueError("V19 fixture requires a compacted V17 segment")
        integrity = create_integrity_segment_candidate(db, tenant_id=tenant.id, trace_id=trace_id,
                                                       settings=settings, now=operation_now)
        archive_integrity_segment(db, integrity.id, stores["primary"].store, provider=provider,
                                  settings=settings, keyring=keyring, now=operation_now)
        _replicate_tenant(db, tenant_id=tenant.id, settings=settings, stores=stores, keyring=keyring, now=operation_now)
        _assert_replicas(db, tenant_id=tenant.id, archive_type="INTEGRITY_SEGMENT",
                         archive_id=integrity.id, settings=settings, now=operation_now)
        if compact_v19:
            authorize_integrity_compaction(db, integrity.id, provider=provider, settings=settings,
                                           now=operation_now)
            deleted = compact_integrity_segment(db, integrity.id, settings=settings,
                                                now=operation_now, provider=provider)
            db.refresh(integrity)
            if deleted <= 0 or integrity.state != "COMPACTED":
                raise RuntimeError("V19 fixture compaction did not complete")

    if ledger is not None and compact_v17:
        validation = verify_mixed_ledger(db, tenant_id=tenant.id, trace_id=trace_id,
                                         store=stores, keyring=keyring, settings=settings)
        if validation.status != "VALID":
            raise RuntimeError(f"V17 mixed-ledger verification failed: {validation.status}")
    return ArchiveFixture(
        tenant_id=tenant.id, trace_id=trace_id, namespace=namespace,
        checkpoint_id=checkpoint.id, archive_id=archive.id if archive else None,
        ledger_segment_id=ledger.id if ledger else None,
        integrity_segment_id=integrity.id if integrity else None,
        settings=settings, provider=provider, stores=stores, keyring=keyring,
    )
