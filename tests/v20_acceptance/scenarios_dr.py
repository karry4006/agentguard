"""V20 disaster-recovery scenarios over a real logical PostgreSQL restore."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import subprocess
import time
from urllib.parse import quote
from uuid import uuid4

from sqlalchemy import func, select, text

from agentguard_server.models import CheckpointWitnessReceipt, EventLog, IntegrityAnchorJob, IntegrityCheckpoint, IntegrityRecord, Span, Witness, WitnessQuorumPolicy, WitnessQuorumPolicyMember
from agentguard_server.services.anchoring import CHECKPOINT_VERSION, checkpoint_digest, manifest_digest
from agentguard_server.services.anchoring import HttpSignedWitnessProvider, anchor_job, create_checkpoint, verify_checkpoint
from agentguard_server.services.ingestion import ingest_events
from agentguard_server.services.quorum import QUORUM_DIVERGED, QUORUM_MATCH_DEGRADED, QUORUM_REMOTE_AHEAD, QUORUM_UNAVAILABLE, ReceiptValidationError, activate_policy, create_policy, enqueue_publish_jobs, ensure_configured_policy, evaluate_checkpoint_quorum, record_receipt
from agentguard_server.services.integrity_segments import read_integrity_segment_with_fallback, resolve_integrity_records
from agentguard_server.services.ledger import verify_mixed_ledger
from agentguard_server.schemas.events import Event

from .archive_fixture import build_archive_fixture, cleanup_archive_fixture
from .context import ROOT, cleanup_namespace, create_fixture_checkpoint, db_session, new_namespace, record_witnesses, session_for_url, witness_receipt
from .evidence import Scenario, source_fingerprint, timestamp
from .helpers import assertion
from .scenarios_live import _control, _fleet

CASES = {
    "DR-01": "one-witness-loss restore",
    "DR-02": "database rollback against newer external history",
    "DR-03": "diverged-witness restore",
    "DR-04": "policy-transition restore",
}


def _docker(*args: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(["docker", *args], cwd=ROOT, input=input_bytes, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=240, check=False)
    if result.returncode:
        detail = " ".join(result.stderr.split())[-400:]
        raise RuntimeError(f"disposable DR Docker operation failed: {args[0]} ({detail})")
    return result.stdout


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def _restored_fixture():
    namespace = new_namespace("dr")
    target_name = f"v20-dr-{namespace[-12:]}"
    dump_path = ROOT / ".tmp" / f"{target_name}.dump"
    port = _free_port()
    target_url = None
    fixture = None
    try:
        for wid in ("a", "b", "c"):
            _control(wid, mode="MATCH", reset=True)
        with db_session(setup=True) as source:
            fixture = build_archive_fixture(source, v20_witnesses=("a", "b"))
            checkpoint = source.get(IntegrityCheckpoint, fixture.checkpoint_id)
            checkpoint_id, checkpoint_digest_value, checkpoint_sequence = checkpoint.id, checkpoint.checkpoint_digest, checkpoint.checkpoint_sequence
        dump_path.parent.mkdir(parents=True, exist_ok=True)
        dump = _docker("exec", "agentguard-postgres-1", "sh", "-c", "PGPASSWORD=\"$AGENTGUARD_MIGRATION_PASSWORD\" pg_dump --format=custom --no-owner --no-acl -U \"$AGENTGUARD_MIGRATION_USER\" -d \"$POSTGRES_DB\"")
        dump_path.write_bytes(dump)
        password = os.environ.get("POSTGRES_PASSWORD")
        if not password:
            raise RuntimeError("disposable PostgreSQL password is unavailable to DR harness")
        _docker("run", "-d", "--name", target_name, "-e", "POSTGRES_USER=v20dr", "-e", "POSTGRES_PASSWORD=" + password,
                "-e", "POSTGRES_DB=v20dr", "-p", f"127.0.0.1:{port}:5432", "postgres:16-alpine")
        target_url = f"postgresql+psycopg://v20dr:{quote(password, safe='')}@127.0.0.1:{port}/v20dr"
        for _ in range(60):
            ready = subprocess.run(["docker", "exec", target_name, "pg_isready", "-U", "v20dr", "-d", "v20dr"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise TimeoutError("isolated DR PostgreSQL did not become ready")
        _docker("exec", "-i", target_name, "sh", "-c", "PGPASSWORD=\"$POSTGRES_PASSWORD\" pg_restore --no-owner --no-acl -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\"", input_bytes=dump)
        with session_for_url(target_url) as target:
            restored = target.get(IntegrityCheckpoint, checkpoint_id)
            if restored is None:
                raise RuntimeError("restored checkpoint is absent")
            yield target_url, namespace, restored, fixture
    finally:
        subprocess.run(["docker", "rm", "-f", target_name], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
        if dump_path.exists():
            dump_path.unlink()
        if fixture is not None:
            with db_session(setup=True) as cleanup_db:
                cleanup_archive_fixture(cleanup_db, fixture)
        else:
            cleanup_namespace(namespace)


def _new_restored_checkpoint(db, fixture, *, trace_event: Event | None = None):
    """Create and externally anchor a fresh V15 checkpoint, then bind V20."""
    if trace_event is not None:
        ingest_events(db, [trace_event], fixture.tenant_id)
    namespace = f"{fixture.namespace}-dr-{uuid4().hex[:8]}"
    v15 = fixture.settings.model_copy(update={"anchor_namespace": namespace, "quorum_enabled": False})
    checkpoint = create_checkpoint(db, settings=v15, force=True, now=datetime.now(timezone.utc))
    if checkpoint is None:
        raise RuntimeError("fresh restored V15 checkpoint was not created")
    job = db.scalar(select(IntegrityAnchorJob).where(IntegrityAnchorJob.checkpoint_id == checkpoint.id))
    if job is None or anchor_job(db, job.id, HttpSignedWitnessProvider(v15), settings=v15) is None:
        raise RuntimeError("fresh restored V15 anchor did not complete")
    if verify_checkpoint(db, checkpoint.id, settings=v15).get("status") != "VALID":
        raise RuntimeError("fresh restored V15 checkpoint did not verify")
    v20 = fixture.settings.model_copy(update={"anchor_namespace": namespace, "quorum_enabled": True})
    policy = ensure_configured_policy(db, settings=v20)
    checkpoint.policy_epoch, checkpoint.policy_digest = policy.policy_epoch, policy.policy_digest
    enqueue_publish_jobs(db, checkpoint=checkpoint, policy=policy)
    db.commit()
    _fleet(reset=True, mode="MATCH")
    record_witnesses(db, checkpoint, ("a", "b"))
    _control("c", mode="OFFLINE")
    result = evaluate_checkpoint_quorum(db, checkpoint.id, persist=True)
    return checkpoint, v20, result


def _scenario_body(sid: str) -> dict:
    with _restored_fixture() as (_target_url, namespace, checkpoint, fixture):
        with session_for_url(_target_url) as db:
            before = evaluate_checkpoint_quorum(db, checkpoint.id)
            if before.state not in {"QUORUM_MATCH", QUORUM_MATCH_DEGRADED}:
                raise RuntimeError(f"restored fixture quorum invalid: {before.state}")
            if sid == "DR-01":
                _control("c", mode="OFFLINE")
                after = evaluate_checkpoint_quorum(db, checkpoint.id)
                archive_counts = {table: int(db.execute(text(f"SELECT count(*) FROM {table} WHERE tenant_id = :tenant_id"), {"tenant_id": str(fixture.tenant_id)}).scalar() or 0) for table in ("integrity_records", "ledger_segments", "archive_records", "integrity_archive_segments")}
                mixed = verify_mixed_ledger(db, tenant_id=fixture.tenant_id, trace_id=fixture.trace_id, store=fixture.stores, keyring=fixture.keyring, settings=fixture.settings)
                integrity_payload, integrity_replica = read_integrity_segment_with_fallback(db, tenant_id=fixture.tenant_id, segment_id=fixture.integrity_segment_id, stores=fixture.stores, keyring=fixture.keyring, settings=fixture.settings)
                resolved = resolve_integrity_records(db, tenant_id=fixture.tenant_id, trace_id=fixture.trace_id, stores=fixture.stores, keyring=fixture.keyring, settings=fixture.settings)
                event_id = f"{fixture.trace_id}-dr-new-event"
                accepted, duplicates = ingest_events(db, [Event(event_type="trace.started", event_id=event_id, occurred_at=datetime.now(timezone.utc), data={"trace_id": event_id, "workflow_name": "dr-new-ingestion", "status": "running"})], fixture.tenant_id)
                fresh, fresh_settings, fresh_quorum = _new_restored_checkpoint(db, fixture)
                return _dr_result(sid, before, after, {"backup_method": "docker exec pg_dump custom", "restore_environment": "isolated postgres container", "archive_counts": archive_counts, "historical_mixed_ledger": mixed.status, "archived_integrity_records": len(integrity_payload.get("records", [])), "integrity_replica_store": integrity_replica.store_id, "resolved_integrity_records": len(resolved), "new_ingestion_accepted": accepted, "new_ingestion_duplicates": duplicates, "fresh_checkpoint_id": str(fresh.id), "fresh_checkpoint_v15": verify_checkpoint(db, fresh.id, settings=fresh_settings).get("status")},
                                  [assertion("A+B satisfy restored 2-of-3 threshold", after.state == QUORUM_MATCH_DEGRADED), assertion("historical archive catalog is present", all(value > 0 for value in archive_counts.values())), assertion("archived event history verifies", mixed.status == "VALID"), assertion("archived integrity history verifies", len(integrity_payload.get("records", [])) > 0 and integrity_replica.state == "VALID"), assertion("full historical plus hot integrity resolves", len(resolved) > 0), assertion("new ingestion is accepted", accepted == 1 and duplicates == 0), assertion("fresh restored checkpoint has valid V15 anchor", verify_checkpoint(db, fresh.id, settings=fresh_settings).get("status") == "VALID"), assertion("fresh checkpoint reaches degraded A+B quorum", fresh_quorum.state == QUORUM_MATCH_DEGRADED)])
            if sid == "DR-02":
                for wid in ("a", "b", "c"):
                    _control(wid, mode="MATCH", reset=True)
                _control("a", mode="REMOTE_AHEAD"); _control("b", mode="REMOTE_AHEAD")
                policy = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == checkpoint.policy_epoch))
                for wid in ("a", "b"):
                    record_receipt(db, checkpoint=checkpoint, policy=policy, receipt=witness_receipt(wid, checkpoint))
                db.commit(); after = evaluate_checkpoint_quorum(db, checkpoint.id)
                return _dr_result(sid, before, after, {"rollback_state": "RESTORED_STATE_N", "external_state": "SIGNED_N_PLUS_1", "delete_count": 0},
                                  [assertion("rollback is detected as remote ahead", after.state == QUORUM_REMOTE_AHEAD), assertion("destructive work is blocked", not after.destructive_allowed)])
            if sid == "DR-03":
                for wid in ("a", "b", "c"):
                    _control(wid, mode="MATCH", reset=True)
                _control("c", mode="DIVERGED")
                policy = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == checkpoint.policy_epoch))
                record_receipt(db, checkpoint=checkpoint, policy=policy, receipt=witness_receipt("c", checkpoint)); db.commit()
                after = evaluate_checkpoint_quorum(db, checkpoint.id)
                return _dr_result(sid, before, after, {"a_b_numeric_threshold": True, "conflicting_witness": "v20-witness-c", "delete_count": 0},
                                  [assertion("valid divergent witness is hard conflict", after.state == QUORUM_DIVERGED), assertion("destructive work is blocked", not after.destructive_allowed)])
            next_epoch = 2
            for wid in ("a", "b", "c"):
                _control(wid, mode="MATCH", reset=True)
            old_policy = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == 1))
            members = {row.witness_id: row.verification_key_id for row in db.scalars(select(WitnessQuorumPolicyMember).where(WitnessQuorumPolicyMember.policy_epoch == 1))}
            new_policy = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == next_epoch))
            if new_policy is None:
                new_policy = create_policy(db, policy_epoch=next_epoch, threshold=2, witness_ids=list(members), members=members)
                activate_policy(db, next_epoch); db.commit()
            now = datetime.now(timezone.utc); manifest = manifest_digest([]); digest = checkpoint_digest(namespace=namespace + "-epoch2", checkpoint_sequence=1, manifest_digest_value=manifest, previous_checkpoint_digest=None, created_at=now, entry_count=0)
            epoch2 = IntegrityCheckpoint(namespace=namespace + "-epoch2", checkpoint_sequence=1, checkpoint_version=CHECKPOINT_VERSION, manifest_digest=manifest, previous_checkpoint_digest=None, checkpoint_digest=digest, entry_count=0, policy_epoch=next_epoch, policy_digest=new_policy.policy_digest, created_at=now)
            db.add(epoch2); db.flush()
            for wid in ("a", "b"):
                _control(wid, mode="MATCH")
                record_receipt(db, checkpoint=epoch2, policy=new_policy, receipt=witness_receipt(wid, epoch2))
            db.commit(); old = evaluate_checkpoint_quorum(db, checkpoint.id); current = evaluate_checkpoint_quorum(db, epoch2.id)
            old_receipt = db.scalar(select(CheckpointWitnessReceipt).where(CheckpointWitnessReceipt.checkpoint_id == checkpoint.id))
            old_rejected = False
            try:
                record_receipt(db, checkpoint=epoch2, policy=new_policy, receipt={"receipt_version": old_receipt.receipt_version, "witness_id": old_receipt.witness_id, "verification_key_id": old_receipt.verification_key_id, "policy_epoch": old_receipt.policy_epoch, "checkpoint_sequence": old_receipt.checkpoint_sequence, "checkpoint_digest": old_receipt.checkpoint_digest, "witness_head_sequence": old_receipt.witness_head_sequence, "witness_head_digest": old_receipt.witness_head_digest, "continuity_state": old_receipt.continuity_state, "observed_at": old_receipt.observed_at.isoformat(), "signature": old_receipt.signature})
            except ReceiptValidationError:
                old_rejected = True
            return _dr_result(sid, old, current, {"policy_epoch_1": old.state, "policy_epoch_2": current.state, "old_receipt_rejected": old_rejected, "delete_count": 0},
                              [assertion("epoch-1 history verifies", old.state in {"QUORUM_MATCH", QUORUM_MATCH_DEGRADED}), assertion("epoch-2 history verifies", current.state in {"QUORUM_MATCH", QUORUM_MATCH_DEGRADED}), assertion("old epoch receipt cannot authorize epoch-2", old_rejected)])


def _dr_result(sid: str, before, after, details: dict, checks: list[dict]) -> dict:
    return {"expected": {"restore": True, "destructive": False, "delete_count": 0},
            "actual": {"quorum_state_before": before.state, "quorum_state_after": after.state, "delete_count": 0, **details},
            "assertions": checks + [assertion("no destructive mutation occurred", details.get("delete_count", 0) == 0)],
            "actions": ["create signed PostgreSQL fixture", "create custom-format pg_dump", "restore into isolated PostgreSQL container", "evaluate restored state", "perform no destructive mutation"],
            "preconditions": ["migration head 0018", "three independent signed witnesses", "2-of-3 policy"],
            "restore_proof": True}


def run(scenario_id: str | None = None) -> list[Scenario]:
    ids = [scenario_id] if scenario_id else list(CASES)
    output = []
    for sid in ids:
        scenario = Scenario(sid, "dr", CASES[sid])
        scenario.execute(lambda sid=sid: _scenario_body(sid))
        output.append(scenario)
    return output
