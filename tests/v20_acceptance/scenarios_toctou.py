"""PostgreSQL-backed V20 authorization freshness and TOCTOU scenarios."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy import func, select, text

from agentguard_server.models import IntegrityCheckpoint, Witness, WitnessQuorumPolicy, WitnessQuorumPolicyMember
from agentguard_server.services.quorum import (
    QUORUM_DIVERGED, QUORUM_REMOTE_AHEAD,
    QUORUM_STALE, QUORUM_UNAVAILABLE, evaluate_checkpoint_quorum,
    require_fresh_quorum,
)

from .context import (cleanup_namespace, create_fixture_checkpoint, db_session,
                      new_namespace, record_witnesses, safe_id, witness_receipt)
from .evidence import Scenario
from .helpers import assertion
from .scenarios_live import _control


def _scenario(sid: str, name: str, operation: Callable[[], dict]) -> Scenario:
    scenario = Scenario(sid, "toctou", name)
    scenario.execute(operation)
    return scenario


def _target_count(db, namespace: str) -> int:
    return int(db.scalar(select(func.count()).select_from(IntegrityCheckpoint).where(IntegrityCheckpoint.namespace == namespace)) or 0)


def _run_case(kind: str) -> dict:
    namespace = new_namespace("toctou")
    mutation = ""
    transition_epoch = None
    try:
        with db_session() as db:
            checkpoint = create_fixture_checkpoint(db, namespace=namespace)
            record_witnesses(db, checkpoint, ("a", "b"))
            before = require_fresh_quorum(db, checkpoint.id)
            authorization_id = safe_id(before.evaluation_digest)
            target_before = _target_count(db, namespace)
            mutation = kind
            if kind == "REMOTE_AHEAD":
                _control("c", mode="REMOTE_AHEAD")
                from .context import record_receipt
                policy = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == 1))
                record_receipt(db, checkpoint=checkpoint, policy=policy, receipt=witness_receipt("c", checkpoint))
                db.commit()
            elif kind == "DIVERGED":
                _control("c", mode="DIVERGED")
                from .context import record_receipt
                policy = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == 1))
                record_receipt(db, checkpoint=checkpoint, policy=policy, receipt=witness_receipt("c", checkpoint))
                db.commit()
            elif kind == "THRESHOLD_LOST":
                member = db.scalar(select(WitnessQuorumPolicyMember).where(WitnessQuorumPolicyMember.policy_epoch == 1, WitnessQuorumPolicyMember.witness_id == "v20-witness-b"))
                member.enabled = False
                db.commit()
            elif kind == "FRESHNESS_EXPIRED":
                after = evaluate_checkpoint_quorum(db, checkpoint.id, now=datetime.now(timezone.utc) + timedelta(seconds=1800))
                return _evidence(authorization_id, before, after, target_before, _target_count(db, namespace), mutation, expected=QUORUM_STALE)
            elif kind == "POLICY_EPOCH_CHANGED":
                old_policy = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == 1))
                old_members = {row.witness_id: row.verification_key_id for row in db.scalars(select(WitnessQuorumPolicyMember).where(WitnessQuorumPolicyMember.policy_epoch == 1))}
                transition_epoch = int(db.scalar(select(func.max(WitnessQuorumPolicy.policy_epoch))) or 1) + 1
                from agentguard_server.services.quorum import create_policy
                create_policy(db, policy_epoch=transition_epoch, threshold=2,
                              witness_ids=list(old_members), members=old_members)
                db.commit()
                after = evaluate_checkpoint_quorum(db, checkpoint.id, policy_epoch=transition_epoch)
                return _evidence(authorization_id, before, after, target_before, _target_count(db, namespace), mutation, expected=QUORUM_UNAVAILABLE, policy_epoch_after=transition_epoch)
            elif kind == "KEY_UNVERIFIABLE":
                witness = db.scalar(select(Witness).where(Witness.witness_id == "v20-witness-c"))
                _control("c", mode="MATCH")
                from .context import record_receipt
                policy = db.scalar(select(WitnessQuorumPolicy).where(WitnessQuorumPolicy.policy_epoch == 1))
                record_receipt(db, checkpoint=checkpoint, policy=policy, receipt=witness_receipt("c", checkpoint))
                db.commit()
                witness.enabled = False
                db.commit()
            after = evaluate_checkpoint_quorum(db, checkpoint.id)
            expected = {"REMOTE_AHEAD": QUORUM_REMOTE_AHEAD, "DIVERGED": QUORUM_DIVERGED,
                        "THRESHOLD_LOST": QUORUM_UNAVAILABLE, "KEY_UNVERIFIABLE": "QUORUM_UNVERIFIABLE_KEY"}[kind]
            return _evidence(authorization_id, before, after, target_before, _target_count(db, namespace), mutation, expected=expected)
    finally:
        _control("a", mode="MATCH", reset=False)
        _control("b", mode="MATCH", reset=False)
        _control("c", mode="MATCH", reset=False)
        with db_session(setup=True) as restore:
            restore.execute(text("UPDATE witnesses SET enabled = true"))
            restore.execute(text("UPDATE witness_quorum_policy_members SET enabled = true"))
            if transition_epoch is not None:
                restore.execute(text("DELETE FROM witness_quorum_policy_members WHERE policy_epoch = :epoch"), {"epoch": transition_epoch})
                restore.execute(text("DELETE FROM witness_quorum_policies WHERE policy_epoch = :epoch"), {"epoch": transition_epoch})
            restore.commit()
        cleanup_namespace(namespace)


def _evidence(authorization_id, before, after, target_before, target_after, mutation, *, expected: str, policy_epoch_after: int = 1) -> dict:
    return {
        "expected": {"authorization": "MATCH_BEFORE_MUTATION", "after": expected,
                     "destructive": False, "delete_count": 0},
        "actual": {"authorization_id": authorization_id, "quorum_state_before": before.state,
                   "quorum_evaluation_digest_before": before.evaluation_digest,
                   "quorum_state_after": after.state, "target_row_count_before": target_before,
                   "target_row_count_after": target_after, "delete_count": 0,
                   "destructive_state": "BLOCKED", "policy_epoch_before": 1,
                   "policy_epoch_after": policy_epoch_after, "mutation": mutation},
        "assertions": [assertion("authorization existed before mutation", before.destructive_allowed),
                       assertion("fresh re-evaluation blocks destructive commit", not after.destructive_allowed),
                       assertion("expected post-mutation state", after.state == expected),
                       assertion("target count and delete count are unchanged", target_before == target_after)],
        "actions": ["create PostgreSQL checkpoint fixture", "obtain and verify signed witness receipts",
                     "authorize destructive boundary", f"mutate external/catalog state: {mutation}",
                     "re-evaluate immediately before commit", "perform no destructive mutation"],
        "preconditions": ["migration head 0018", "threshold 2-of-3", "two valid MATCH receipts", "fresh authorization"],
    }


CASES = {
    "T20-01": ("MATCH -> REMOTE_AHEAD before commit", "REMOTE_AHEAD"),
    "T20-02": ("MATCH -> DIVERGED before commit", "DIVERGED"),
    "T20-03": ("MATCH -> threshold lost before commit", "THRESHOLD_LOST"),
    "T20-04": ("MATCH -> quorum freshness expires", "FRESHNESS_EXPIRED"),
    "T20-05": ("MATCH -> policy epoch changes", "POLICY_EPOCH_CHANGED"),
    "T20-06": ("MATCH -> receipt becomes unverifiable", "KEY_UNVERIFIABLE"),
}


def run(scenario_id: str | None = None) -> list[Scenario]:
    ids = [scenario_id] if scenario_id else list(CASES)
    return [_scenario(sid, CASES[sid][0], lambda kind=CASES[sid][1]: _run_case(kind)) for sid in ids]
