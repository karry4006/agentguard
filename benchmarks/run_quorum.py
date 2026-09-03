from __future__ import annotations

import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agentguard_server.services.quorum import POLICY_VERSION, evaluate_quorum, sign_receipt
from support import summary, timing


def main() -> None:
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    witnesses = {name: (f"{name}-key", Ed25519PrivateKey.generate()) for name in ("a", "b", "c")}
    keys = {kid: key.public_key().public_bytes_raw() for kid, key in witnesses.values()}
    policy = {"policy_version": POLICY_VERSION, "policy_epoch": 1, "threshold": 2, "witness_ids": ["a", "b", "c"],
              "receipt_freshness_seconds": 900, "quorum_freshness_seconds": 300, "strict_conflict_blocking": True}
    receipts = []
    for name in ("a", "b", "c"):
        kid, key = witnesses[name]
        receipts.append(sign_receipt({"receipt_version": "multi-witness-receipt-v1", "witness_id": name,
            "verification_key_id": kid, "policy_epoch": 1, "checkpoint_sequence": 1,
            "checkpoint_digest": "a" * 64, "witness_head_sequence": 1, "witness_head_digest": "a" * 64,
            "continuity_state": "MATCH", "observed_at": "2026-01-01T00:00:00Z"}, key))
    samples = timing(lambda: evaluate_quorum(policy, receipts, checkpoint_sequence=1, checkpoint_digest="a" * 64,
                                               now=now, public_keys=keys), 200)
    result = evaluate_quorum(policy, receipts, checkpoint_sequence=1, checkpoint_digest="a" * 64, now=now, public_keys=keys)
    print(json.dumps({"benchmark": "v20_quorum_evaluation", "iterations": 200, "state": result.state,
                      "latency": summary(samples), "notes": "Local Ed25519 verification and quorum evaluation; no witnesses contacted."}, sort_keys=True))


if __name__ == "__main__":
    main()
