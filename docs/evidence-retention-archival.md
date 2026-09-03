# V16 evidence retention, archival, and cold storage

V16 adds an optional, provider-neutral cold archive for finalized traces. The
current implementation archives one deterministic `trace-archive-v1` bundle
per trace. The bundle contains the trace projection and ordered span
projections, plus a manifest that binds the bundle to the V3 chain range and
the V15 covering checkpoint.

## Safety boundary

`event_log`, `integrity_records`, V3 chain heads, V15 checkpoints, checkpoint
entries, signed receipts, tenants, identities, sessions, keys, incidents, and
other control-plane data are never deleted by V16. `traces` remains as the hot
trace index. Only `spans` is classified as a purgeable hot projection, and
only after all deterministic checks pass.

Archive and purge are disabled by default. A retention hold always blocks
purge; it does not block making a cold copy. Retention laws and legal policy
remain the operator's responsibility; V16 makes no compliance claim.

## Integrity and encryption

Plaintext is canonical UTF-8 JSON, compressed with deterministic gzip, and
encrypted with AES-256-GCM using a fresh 96-bit nonce. The envelope is
`archive-envelope-v1`. AAD binds the envelope version, archive ID, tenant ID,
trace ID, and archive format. Plaintext, compressed, and ciphertext SHA-256
digests are recorded in PostgreSQL after read-back verification.

Archive encryption keys are supplied through the protected external key
registry `AGENTGUARD_ARCHIVE_ENCRYPTION_KEYS_FILE` (JSON key ID to base64 or
hex-encoded 32-byte key). PostgreSQL, the repository, images, manifests, and
API responses contain only the key ID. Rotation retains old decryption keys so
old archives remain readable; a missing historical key is reported as
`UNVERIFIABLE_ARCHIVE_KEY_MISSING`, not object tampering.

## Object storage

The production adapter is S3-compatible and uses maintained boto3 SigV4
support. Endpoint, bucket, and credentials are trusted deployment
configuration, never request or model output. TLS is required except for an
explicit test-only private HTTP override. The adapter exposes only PUT, GET,
and HEAD. AgentGuard V16 has no archive-object delete operation; external S3
lifecycle policies are outside AgentGuard's control.

Uploads use a stable generated key and are followed by GET, ciphertext hash,
AES-GCM, bounded decompression, plaintext hash, schema, identity, and source
digest verification. Existing different bytes produce
`ARCHIVE_OBJECT_CONFLICT`; missing objects, unavailable storage, and tampered
objects fail closed for purge.

## Eligibility and recovery

Archiving requires a finalized trace older than the configured age plus grace,
valid V3 evidence, valid V15 checkpoint coverage, and configured size bounds.
Purge additionally requires `retention_purge_enabled`, age policy, no active
hold, `ARCHIVED_VERIFIED`, a successful read-back, unchanged source-projection
digest, valid V3/V15 verification, and remote V15 continuity `MATCH` when
anchoring is enabled. `REMOTE_AHEAD`, `DIVERGED`, or witness unavailability
blocks purge. Late spans mark the archive stale and cannot be removed using the
old snapshot.

The dedicated worker is `python -m agentguard_server.retention_worker`. Jobs
use PostgreSQL-backed leases and can be reclaimed after a crash. Network I/O
is performed outside the claim transaction. Ingestion remains available when
object storage is unavailable; archive delivery retries are bounded, while
destructive operations fail closed.

Authenticated read paths are `GET /v1/archives`,
`GET /v1/archives/{archive_id}`, and `GET /v1/traces/{trace_id}/archive`.
They enforce tenant scope, verify the object before returning it, and never
rehydrate hot PostgreSQL rows. Holds are managed through
`/v1/retention/holds`; status is available at `/v1/retention/status` and a
bounded operator run can be requested at `/v1/retention/run`.

## Backup and residual risks

A complete restore requires PostgreSQL, V3 verification keys, V15 public
verification configuration, external archive key history, object-store
configuration/credentials, and the external objects. Do not put archive keys
inside a database backup for convenience. V3 `event_log` continues to grow by
design; object-store availability and key availability affect cold retrieval;
authorized AgentGuard processes can decrypt content; external lifecycle rules
may remove objects; and the archive catalog is not an independent public
transparency log.

