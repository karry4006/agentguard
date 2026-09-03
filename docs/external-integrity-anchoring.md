# AgentGuard V15: External Integrity Anchoring

V15 provides externally anchored tamper-evident history for the V3 ledger. It
supplements V3; it does not replace V3 signatures or directly sign every trace
payload.

## Trust boundary and privacy

The witness receives one compact deployment checkpoint request containing only
`schema_version`, the trusted configured `namespace`, sequence, checkpoint
digest, previous checkpoint digest, and UTC creation time. It never receives
tenant IDs, trace IDs, telemetry, prompts, model output, tool arguments/results,
incident content, user IDs, API keys, database URLs, the V3 integrity key, or
pepper. Telemetry and witness responses are data, not authority: neither can
select an endpoint, namespace, public key, policy, or verification result.

The witness owns an Ed25519 private signing key outside AgentGuard. AgentGuard
has only an operator-managed registry of `signer_key_id` to Ed25519 public key.
The response cannot add or rotate trusted keys. Keep historical public keys for
as long as their receipts must remain verifiable; removing one yields
`UNVERIFIABLE_WITNESS_KEY_MISSING`, not an invalid-signature result.

## Checkpoint format

A checkpoint is a transactionally consistent snapshot of eligible V3
`integrity_chain_heads` rows. Each local entry contains a tenant ID, trace ID,
chain sequence, and chain head hash; these remain local. A checkpoint stores the
entry manifest digest, sequence, previous checkpoint digest, entry count,
`checkpoint-v1`, and UTC creation time. V15 refuses to checkpoint a V3 trace
whose chain is invalid or unverifiable and never rewrites or re-signs V3 data.

Canonicalization is UTF-8 JSON with lexicographically sorted object keys,
compact separators, NFC-independent UUID/string conversion, lowercase hex
digests, integer counts, and UTC timestamps formatted as
`YYYY-MM-DDTHH:MM:SS.ffffffZ`. Manifest entries are sorted by tenant ID then
trace ID. The manifest digest is SHA-256 of the canonical object
`{"checkpoint_version":"checkpoint-v1","entries":[...]}`. The checkpoint
digest is SHA-256 of canonical JSON binding version, namespace, sequence,
manifest digest, previous digest, creation time, and entry count.

The first checkpoint has a null previous digest. Each later checkpoint must
reference the prior local checkpoint digest. Local verification recomputes the
manifest and checkpoint digest, checks the chain, then checks the receipt's
namespace, sequence, digest, receipt digest, trusted key, and Ed25519 signature.

## Witness protocol and delivery

The protocol is `https-signed-witness-v1`. A witness accepts one request for
`namespace + checkpoint_sequence + checkpoint_digest` and returns a bounded,
strict receipt containing an external anchor ID, namespace, sequence, digest,
witness time, signer key ID, and signature. The signature excludes the
signature field and authenticates the canonical receipt message, including the
checkpoint's previous digest and creation time. Repeating the same logical
request returns the same logical anchor. A same-sequence different digest is a
conflict and is never overwritten.

Submission is at-least-once: a worker can crash after the witness accepts but
before the receipt is stored. Retrying is safe because witness idempotency
prevents conflicting logical anchors. Timeouts, connection failures, 429, and
5xx use bounded retry/backoff. Permanent 4xx failures do not tight-loop.
PostgreSQL stores jobs and leases. Replicas claim with an atomic database
update; expired `IN_FLIGHT` leases are reclaimable. No Redis or leader election
is required, and no PostgreSQL row lock is held during HTTPS.

Production endpoints require HTTPS, certificate verification, no redirects,
no proxy-dependent rerouting, and V11 resolved-IP checks that reject loopback,
private, link-local, metadata, and internal destinations. HTTP/private witness
access is available only with the explicit test-environment override
`AGENTGUARD_ALLOW_PRIVATE_ANCHOR_TESTS=true`.

## Continuity and freshness

Remote read-back compares the local latest checkpoint with the witness latest:

- `MATCH`: same sequence and digest.
- `REMOTE_AHEAD`: the witness has newer history; this is the expected signal for
  an older restored database and requires operator review.
- `LOCAL_AHEAD`: local history is newer but not yet witnessed; this is not by
  itself tampering.
- `DIVERGED`: same sequence has different digests; investigate both sides.
- `WITNESS_UNAVAILABLE`: remote comparison could not be made.
- `NEVER_ANCHORED`: no remote anchor exists.

Local verification uses `VALID`, `NOT_ANCHORED`, `INVALID_CHECKPOINT`,
`CHECKPOINT_CHAIN_DIVERGED`, `ANCHOR_DIGEST_MISMATCH`,
`INVALID_RECEIPT_SIGNATURE`, and `UNVERIFIABLE_WITNESS_KEY_MISSING` as
specific states. Freshness is `FRESH`, `STALE`, or `NEVER_ANCHORED` based on
the last successful local receipt and configured maximum age.

A checkpoint externally covers a historical trace only when its V3 chain
verifies and the trace ledger sequence is no greater than the sequence stored
for that trace in the verified checkpoint. It is not a direct signature over
trace payloads. Recent events between the last successful anchor and the
current checkpoint remain outside independent coverage. Shorter intervals
reduce this window but increase database and witness work. During witness
outage, V3 ingestion remains available; assurance becomes stale and durable
work retries later.

## Scheduling and APIs

`integrity_anchor_state` serializes sequence and due time with PostgreSQL row
locking. The periodic worker is only a wake-up mechanism; PostgreSQL remains
the authority, so concurrent replicas create one logical checkpoint per due
interval. A bounded pending-job policy prevents outage-driven checkpoint
storms.

The minimal API is:

- `GET /v1/integrity/checkpoints`
- `GET /v1/integrity/checkpoints/{id}`
- `POST /v1/integrity/checkpoints` (authorized, optionally forced)
- `POST /v1/integrity/checkpoints/{id}/anchor` (authorized)
- `POST /v1/integrity/checkpoints/{id}/verify`
- `GET /v1/integrity/anchor-status`
- `GET /v1/integrity/remote-continuity`

The new API-key scopes are `integrity:read` and `integrity:anchor`; existing
keys are not upgraded automatically. Responses omit local tenant-chain
entries and raw receipt/signature material.

## Backup, restore, and limitations

Backups preserve checkpoints, entries, receipts, state, and jobs. They never
contain the witness private key. After restore, expired anchor leases can be
reclaimed. A restored older DB is deliberately compared with the independent
witness and reports `REMOTE_AHEAD`; V15 does not auto-repair, insert missing
history, rewrite V3, replay, remediate, or deploy.

The independent witness must remain outside the AgentGuard backup boundary. If
both the database and witness are restored from the same old snapshot, rollback
detection is weakened or lost. V15 does not protect against witness private-key
compromise, simultaneous compromise of AgentGuard and the independent witness,
suppression of future anchor traffic before a checkpoint is accepted, global
multi-region consensus failures, stronger time notarization than the witness
clock provides, or a malicious witness that still holds a trusted key. It is
rollback/tamper detection under documented trust assumptions, not absolute
tamper prevention.
