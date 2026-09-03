# AgentGuard V20: multi-witness quorum integrity anchoring

V20 aggregates independently configured V15-compatible external witnesses
under the immutable `witness-quorum-policy-v1` policy. It is evidence
aggregation under explicit trust assumptions, not PBFT, Raft, blockchain, or
Byzantine consensus.

## Safety rules

- A witness is identified by a canonical `witness_id`; display names and
  response metadata have no authority.
- Each policy member pins a verification key ID. Unknown response keys are
  rejected and key rotation uses a new policy/key epoch.
- Receipts use strict `multi-witness-receipt-v1` canonical JSON and Ed25519
  signatures. Only exact checkpoint sequence, digest, and policy epoch
  matches count.
- A witness counts once. Retries and duplicate responses cannot inflate a
  quorum.
- `REMOTE_AHEAD` and `DIVERGED` signed evidence is retained as a hard conflict
  even when a threshold of other witnesses matches. Invalid signatures and
  stale evidence block destructive authorization.
- Destructive paths require a fresh persisted quorum evaluation. Existing
  V3/V15/V16/V17/V18/V19 checks remain in force.

An existing single V15 witness can be represented as policy epoch 1 with a
1-of-1 membership. Historical checkpoints retain their original semantics;
new policy epochs do not reinterpret old receipts.

## Operational independence

Production witnesses should use separate providers, accounts, regions, and
signing keys. Three containers on one host are useful for functional testing
but are not three independent production failure domains.

## Residual risks

Two colluding compromised witnesses can defeat a 2-of-3 policy. Conversely,
the strict any-valid-contradiction rule allows one misbehaving witness to
deny destructive work. Shared hosting, signing-key compromise, key rotation,
policy downgrade, network partitions, archive availability, V3 historical
key loss, and existing supply-chain license/attestation residuals remain
operational risks. V20 improves external continuity assurance; it does not
replace V18 archive replicas or provide archive availability.
