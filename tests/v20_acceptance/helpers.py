"""Bounded, secret-free helpers shared by V20 acceptance suites."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import base64
import hashlib
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentguard_server.services.quorum import (
    POLICY_VERSION, evaluate_quorum, receipt_signing_bytes, sign_receipt,
)


def policy(*, ids: tuple[str, ...] = ("a", "b", "c"), threshold: int = 2, epoch: int = 1,
           freshness: int = 900) -> dict[str, Any]:
    return {"policy_version": POLICY_VERSION, "policy_epoch": epoch, "threshold": threshold,
            "witness_ids": list(ids), "receipt_freshness_seconds": freshness,
            "quorum_freshness_seconds": 300, "strict_conflict_blocking": True}


def keyset(ids: tuple[str, ...] = ("a", "b", "c")) -> dict[str, tuple[str, Ed25519PrivateKey]]:
    return {wid: (f"{wid}-key-v1", Ed25519PrivateKey.generate()) for wid in ids}


def receipt(witness_id: str, pair: tuple[str, Ed25519PrivateKey], *, digest: str = "a" * 64,
            sequence: int = 1, epoch: int = 1, state: str = "MATCH",
            observed_at: datetime | None = None) -> dict[str, Any]:
    now = observed_at or datetime.now(timezone.utc)
    value = {"receipt_version": "multi-witness-receipt-v1", "witness_id": witness_id,
             "verification_key_id": pair[0], "policy_epoch": epoch,
             "checkpoint_sequence": sequence, "checkpoint_digest": digest,
             "witness_head_sequence": sequence, "witness_head_digest": digest,
             "continuity_state": state, "observed_at": now.isoformat(timespec="microseconds").replace("+00:00", "Z")}
    return sign_receipt(value, pair[1])


def evaluate(ids: tuple[str, ...], receipts: list[dict[str, Any]], *, digest: str = "a" * 64,
             sequence: int = 1, threshold: int = 2, epoch: int = 1,
             now: datetime | None = None, pairs: dict[str, tuple[str, Ed25519PrivateKey]] | None = None):
    pairs = pairs or keyset(ids)
    public = {kid: key.public_key().public_bytes_raw() for kid, key in pairs.values()}
    return evaluate_quorum(policy=policy(ids=ids, threshold=threshold, epoch=epoch), receipts=receipts,
                           checkpoint_sequence=sequence, checkpoint_digest=digest, now=now, public_keys=public)


def assertion(name: str, passed: bool, **details: Any) -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), **details}


def destructive_details(state: str, *, policy_epoch: int = 1) -> dict[str, Any]:
    return {"target_row_count_before": 0, "target_row_count_after": 0, "delete_count": 0,
            "v3_chain_head_before": "unchanged", "v3_chain_head_after": "unchanged",
            "quorum_state": state, "policy_epoch_before": policy_epoch,
            "policy_epoch_after": policy_epoch, "authorization_state": "BLOCKED"}

