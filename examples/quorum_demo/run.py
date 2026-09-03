from __future__ import annotations

from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agentguard_server.services.quorum import POLICY_VERSION, evaluate_quorum, sign_receipt


def receipt(witness_id, key_id, key, *, state="MATCH", digest="a" * 64, now):
    return sign_receipt({"receipt_version": "multi-witness-receipt-v1", "witness_id": witness_id,
        "verification_key_id": key_id, "policy_epoch": 1, "checkpoint_sequence": 1,
        "checkpoint_digest": digest, "witness_head_sequence": 1, "witness_head_digest": digest,
        "continuity_state": state, "observed_at": now.isoformat().replace("+00:00", "Z")}, key)


def main() -> None:
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    witnesses = {name: (f"{name}-key", Ed25519PrivateKey.generate()) for name in ("a", "b", "c")}
    keys = {key_id: key.public_key().public_bytes_raw() for key_id, key in witnesses.values()}
    policy = {"policy_version": POLICY_VERSION, "policy_epoch": 1, "threshold": 2,
              "witness_ids": ["a", "b", "c"], "receipt_freshness_seconds": 900,
              "quorum_freshness_seconds": 300, "strict_conflict_blocking": True}
    matching = [receipt(name, *witnesses[name], now=now) for name in ("a", "b")]
    degraded = evaluate_quorum(policy, matching, checkpoint_sequence=1, checkpoint_digest="a" * 64,
                                now=now, public_keys=keys)
    remote = matching + [receipt("c", *witnesses["c"], state="REMOTE_AHEAD", now=now)]
    blocked = evaluate_quorum(policy, remote, checkpoint_sequence=1, checkpoint_digest="a" * 64,
                              now=now, public_keys=keys)
    print(f"A_B={degraded.state}")
    print(f"C=UNAVAILABLE; unavailable_count={degraded.unavailable_count}")
    print(f"remote_ahead={blocked.state}")
    print(f"destructive_allowed={blocked.destructive_allowed}")
    print("cleanup=automatic_in_memory_receipts")


if __name__ == "__main__":
    main()

