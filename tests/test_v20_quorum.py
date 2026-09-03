from datetime import datetime, timedelta, timezone
import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import sessionmaker

from agentguard_server.models import CheckpointWitnessReceipt, IntegrityArchiveSegment, IntegrityCheckpoint, WitnessQuorumPolicy
from agentguard_server.services.quorum import (
    POLICY_VERSION, QUORUM_DIVERGED, QUORUM_INVALID_SIGNATURE, QUORUM_LOCAL_AHEAD,
    QUORUM_MATCH, QUORUM_MATCH_DEGRADED, QUORUM_REMOTE_AHEAD, QUORUM_STALE,
    PolicyDowngradeError, PolicyValidationError, ReceiptValidationError,
    canonical_witness_id, create_policy, create_witness, evaluate_quorum,
    policy_digest, receipt_signing_bytes, sign_receipt, activate_policy,
    enqueue_publish_jobs, claim_publish_job, process_publish_job,
)


def _receipt(witness_id, key_id, key, *, digest="a" * 64, state="MATCH", now=None, sequence=1, epoch=1):
    value = {
        "receipt_version": "multi-witness-receipt-v1", "witness_id": witness_id,
        "verification_key_id": key_id, "policy_epoch": epoch,
        "checkpoint_sequence": sequence, "checkpoint_digest": digest,
        "witness_head_sequence": sequence, "witness_head_digest": digest,
        "continuity_state": state,
        "observed_at": (now or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z"),
    }
    return sign_receipt(value, key)


@pytest.fixture()
def witness_set():
    result = {}
    for witness_id in ("a", "b", "c"):
        key = Ed25519PrivateKey.generate()
        result[witness_id] = (f"{witness_id}-key", key)
    return result


def _policy(ids=("a", "b", "c"), threshold=2):
    return {"policy_version": POLICY_VERSION, "policy_epoch": 1, "threshold": threshold,
            "witness_ids": list(ids), "receipt_freshness_seconds": 900,
            "quorum_freshness_seconds": 300, "strict_conflict_blocking": True}


def test_witness_id_is_canonical_and_duplicate_members_are_removed():
    assert canonical_witness_id("  Witness-A ") == "witness-a"
    with pytest.raises(ValueError):
        canonical_witness_id("Witness A")
    with pytest.raises(PolicyValidationError):
        create_policy(None, policy_epoch=1, threshold=2, witness_ids=["a", "a"], members={"a": "k"})


def test_threshold_validation_and_policy_digest_are_deterministic():
    with pytest.raises(PolicyValidationError):
        create_policy(None, policy_epoch=1, threshold=0, witness_ids=["a"], members={"a": "k"})
    with pytest.raises(PolicyValidationError):
        create_policy(None, policy_epoch=1, threshold=2, witness_ids=["a"], members={"a": "k"})
    args = dict(policy_version=POLICY_VERSION, policy_epoch=1, threshold=2, witness_ids=["b", "a"],
                strict_conflict_blocking=True, allow_degraded_match=True, receipt_freshness_seconds=900,
                quorum_freshness_seconds=300, conflict_behavior="BLOCK_ANY_VALID_CONTRADICTION")
    assert policy_digest(**args) == policy_digest(**{**args, "witness_ids": ["a", "b"]})


def test_v20_archive_catalog_exposes_all_quorum_authorization_bindings():
    expected = {
        "v20_policy_epoch", "v20_quorum_evaluation_digest", "v20_quorum_state",
        "v20_receipt_set_digest", "v20_evaluated_at", "v20_fresh_until",
    }
    assert expected <= set(IntegrityArchiveSegment.__table__.columns.keys())


def test_exact_match_and_degraded_match(witness_set):
    now = datetime.now(timezone.utc)
    receipts = [_receipt(w, *witness_set[w], now=now) for w in ("a", "b", "c")]
    keys = {kid: key.public_key().public_bytes_raw() for kid, key in witness_set.values()}
    result = evaluate_quorum(policy=_policy(), checkpoint_sequence=1, checkpoint_digest="a" * 64,
                             receipts=receipts, now=now, public_keys=keys)
    assert result.state == QUORUM_MATCH and result.match_count == 3
    result = evaluate_quorum(policy=_policy(), checkpoint_sequence=1, checkpoint_digest="a" * 64,
                             receipts=receipts[:2], now=now, public_keys=keys)
    assert result.state == QUORUM_MATCH_DEGRADED and result.unavailable_count == 1


def test_distinct_witnesses_mixed_digest_and_conflict_blocking(witness_set):
    now = datetime.now(timezone.utc)
    keys = {kid: key.public_key().public_bytes_raw() for kid, key in witness_set.values()}
    a = _receipt("a", *witness_set["a"], now=now)
    duplicate = dict(a)
    b = _receipt("b", *witness_set["b"], digest="b" * 64, now=now)
    c = _receipt("c", *witness_set["c"], now=now)
    result = evaluate_quorum(policy=_policy(), checkpoint_sequence=1, checkpoint_digest="a" * 64,
                             receipts=[a, duplicate, b, c], now=now, public_keys=keys)
    assert result.state == QUORUM_DIVERGED
    assert result.match_count == 2
    remote = _receipt("c", *witness_set["c"], state="REMOTE_AHEAD", now=now)
    result = evaluate_quorum(policy=_policy(), checkpoint_sequence=1, checkpoint_digest="a" * 64,
                             receipts=[a, _receipt("b", *witness_set["b"], now=now), remote], now=now, public_keys=keys)
    assert result.state == QUORUM_REMOTE_AHEAD and not result.destructive_allowed


def test_invalid_unknown_stale_and_local_ahead_are_blocking(witness_set):
    now = datetime.now(timezone.utc)
    keys = {kid: key.public_key().public_bytes_raw() for kid, key in witness_set.values()}
    valid = _receipt("a", *witness_set["a"], now=now)
    invalid = dict(valid, witness_id="b", signature=base64.b64encode(b"x" * 64).decode())
    result = evaluate_quorum(policy=_policy(), checkpoint_sequence=1, checkpoint_digest="a" * 64,
                             receipts=[valid, invalid], now=now, public_keys=keys)
    assert result.state == QUORUM_INVALID_SIGNATURE
    stale = _receipt("b", *witness_set["b"], now=now - timedelta(hours=1))
    result = evaluate_quorum(policy=_policy(), checkpoint_sequence=1, checkpoint_digest="a" * 64,
                             receipts=[valid, stale], now=now, public_keys=keys)
    assert result.state == QUORUM_STALE
    ahead = _receipt("b", *witness_set["b"], state="LOCAL_AHEAD", now=now, sequence=2)
    result = evaluate_quorum(policy=_policy(), checkpoint_sequence=2, checkpoint_digest="a" * 64,
                             receipts=[ahead], now=now, public_keys=keys)
    assert result.state == QUORUM_LOCAL_AHEAD


def test_receipt_signature_canonicalization_and_policy_epoch_binding(witness_set):
    now = datetime.now(timezone.utc)
    kid, key = witness_set["a"]
    receipt = _receipt("a", kid, key, now=now)
    assert receipt_signing_bytes(receipt) == receipt_signing_bytes(dict(reversed(list(receipt.items()))))
    changed = sign_receipt({**receipt, "policy_epoch": 2}, key)
    result = evaluate_quorum(policy=_policy(), checkpoint_sequence=1, checkpoint_digest="a" * 64,
                             receipts=[changed], now=now,
                             public_keys={kid: key.public_key().public_bytes_raw()})
    assert result.state == "QUORUM_INVALID_SIGNATURE"


def test_database_registry_policy_and_activation_are_immutable(db_session):
    now = datetime.now(timezone.utc)
    key = Ed25519PrivateKey.generate()
    create_witness(db_session, witness_id="A", display_name="A", verification_key_id="a-key",
                   verification_public_key=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
                   endpoint_config_ref="witness-a", now=now)
    policy = create_policy(db_session, policy_epoch=1, threshold=1, witness_ids=["a"], members={"a": "a-key"}, now=now)
    activate_policy(db_session, 1, now=now)
    db_session.commit()
    assert policy.policy_digest == policy_digest(policy_version=POLICY_VERSION, policy_epoch=1, threshold=1,
        witness_ids=["a"], strict_conflict_blocking=True, allow_degraded_match=True,
        receipt_freshness_seconds=900, quorum_freshness_seconds=300,
        conflict_behavior="BLOCK_ANY_VALID_CONTRADICTION")


def test_durable_per_witness_jobs_are_idempotent_and_reclaimable(db_session, witness_set):
    now = datetime.now(timezone.utc)
    for wid, (kid, key) in witness_set.items():
        create_witness(db_session, witness_id=wid, display_name=wid, verification_key_id=kid,
                       verification_public_key=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
                       endpoint_config_ref=f"ref-{wid}", now=now)
    policy = create_policy(db_session, policy_epoch=1, threshold=2, witness_ids=["a", "b", "c"],
                           members={wid: pair[0] for wid, pair in witness_set.items()}, now=now)
    activate_policy(db_session, 1, now=now)
    checkpoint = IntegrityCheckpoint(namespace="v20", checkpoint_sequence=1, checkpoint_version="checkpoint-v1",
        manifest_digest="b" * 64, previous_checkpoint_digest=None, checkpoint_digest="a" * 64,
        entry_count=0, created_at=now, policy_epoch=1, policy_digest=policy.policy_digest)
    db_session.add(checkpoint); db_session.flush()
    jobs = enqueue_publish_jobs(db_session, checkpoint=checkpoint, policy=policy, now=now)
    assert len(jobs) == 3
    assert len(enqueue_publish_jobs(db_session, checkpoint=checkpoint, policy=policy, now=now)) == 0
    db_session.commit()
    claimed = claim_publish_job(db_session, now=now, worker_id="worker-a", lease_seconds=5)
    assert claimed is not None
    claimed.lease_expires_at = now - timedelta(seconds=1)
    db_session.commit()
    reclaimed = claim_publish_job(db_session, now=now, worker_id="worker-b", lease_seconds=5)
    assert reclaimed is not None and reclaimed.id == claimed.id

    class Client:
        def publish(self, request):
            pair = witness_set[request["witness_id"]]
            return _receipt(request["witness_id"], *pair, now=now, sequence=1)

    process_publish_job(db_session, reclaimed, client=Client(), checkpoint=checkpoint, policy=policy, now=now)
    assert db_session.query(CheckpointWitnessReceipt).count() == 1


def test_repeated_claimers_do_not_duplicate_claimed_jobs(db_session, witness_set):
    now = datetime.now(timezone.utc)
    for wid, (kid, key) in witness_set.items():
        create_witness(db_session, witness_id=wid, display_name=wid, verification_key_id=kid,
                       verification_public_key=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
                       endpoint_config_ref=f"ref-{wid}", now=now)
    policy = create_policy(db_session, policy_epoch=1, threshold=2, witness_ids=["a", "b", "c"],
                           members={wid: pair[0] for wid, pair in witness_set.items()}, now=now)
    activate_policy(db_session, 1, now=now)
    checkpoint = IntegrityCheckpoint(namespace="parallel-claim", checkpoint_sequence=1, checkpoint_version="checkpoint-v1",
        manifest_digest="b" * 64, previous_checkpoint_digest=None, checkpoint_digest="a" * 64,
        entry_count=0, created_at=now, policy_epoch=1, policy_digest=policy.policy_digest)
    db_session.add(checkpoint); db_session.flush(); enqueue_publish_jobs(db_session, checkpoint=checkpoint, policy=policy, now=now)
    db_session.commit()

    def claim(worker):
        engine = db_session.get_bind()
        local = sessionmaker(bind=engine, expire_on_commit=False)()
        try:
            job = claim_publish_job(local, now=now, worker_id=worker, lease_seconds=30)
            local.commit()
            return str(job.id) if job else None
        finally:
            local.close()

    claimed = [claim(worker) for worker in ("parallel-a", "parallel-b", "parallel-c")]
    assert len([item for item in claimed if item]) == 3
    assert len(set(item for item in claimed if item)) == 3
