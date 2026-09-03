# AgentGuard V18 archive replica resilience

V18 adds a provider-neutral replica catalog for V16 trace archives and V17
ledger segments. The logical artifact remains the exact V16/V17 encrypted
ciphertext. Credentials, endpoints, buckets, and provider bindings stay in
trusted process configuration; PostgreSQL stores only opaque `store_id`
values and verification evidence.

## Safety rules

- `HEAD`, ETag, HTTP 200, object tags, and telemetry never make a replica valid.
- A replica becomes `VALID` only after bounded GET, ciphertext digest check,
  AES-256-GCM authentication, bounded decompression, strict envelope parsing,
  archive-specific verification, and V3 verification for ledger segments.
- `CORRUPT` and `CONFLICT` objects are retained for forensics and are never
  automatically overwritten.
- A missing object is distinct from provider unavailability, corruption,
  conflict, and missing decryption keys.
- Fallback reads iterate trusted, cryptographically verified replicas and
  return `NO_VALID_REPLICA` when all copies are unavailable.

## V18 primary validity audit

All production paths that can create or finalize an `ArchiveReplica` were
audited. `ensure_replica` now creates catalog entries only in a non-attested
state; it rejects direct `VALID` creation. The ledger archive path creates the
primary as `PENDING` only after object PUT/readback and V3, segment-manifest,
boundary, and V15 continuity checks have succeeded. The V16 retention path
does the same after `verify_stored_archive` succeeds. Replication and scrub
verification also use the same finalizer after a complete authenticated
readback.

`finalize_verified_replica` is the single application transition to `VALID`.
It atomically clears the error category and persists `verified_at` and
`updated_at` using PostgreSQL-authoritative time (`database_now`); callers
must provide the `VALID` result from full deterministic verification. Source
selection in enqueue, worker, repair, policy, and compaction paths requires
`VALID`, a non-null timestamp, and freshness. Existing `VALID` rows with a
null timestamp remain ineligible and are repaired only by a subsequent full
verification. A general database check constraint was not added because a
legacy malformed row could make a migration fail before the application has
an opportunity to verify or quarantine it; the existing PostgreSQL
compaction trigger and strict application gates remain fail-closed.

## Compatibility and operation

Migration `0015_archive_replica_resilience` preserves all V17 rows. V18 is
opt-in: replication, scrubbing, repair, and strict replica-count compaction
are disabled by default, and the default minimum is one verified replica.
Existing V16/V17 stores continue to use the original single-store path until
the operator enables the V18 registry.

The canonical release database is PostgreSQL. The historical SQLite migration
chain is not a canonical release path; its pre-V18 UUID binding limitation is
recorded as `NON_CANONICAL_SQLITE_MIGRATION_LIMITATION` and must not be treated
as a failure of migration `0015`.

The replication worker uses PostgreSQL leases and bounded retry backoff. A
crash after PUT is recovered by GET plus full verification; a different object
at the target key is recorded as `CONFLICT`. Automatic repair is limited to a
known `MISSING` target with a currently valid source.

## Recovery set and residual risks

A complete recovery set consists of PostgreSQL backup, one surviving valid
replica, V3 historical verification keys, V15 verification configuration and
history, archive key history, trusted store configuration, and the release
schema version. Losing every replica or the required encryption/V3 keys makes
compacted history unavailable or unverifiable. Separate providers, accounts,
regions, versioning, Object Lock/WORM, offline backups, and independent key
rotation are recommended hardening, not assumptions of the implementation.

Residual risks include simultaneous loss of every replica, archive or V3 key
loss, shared infrastructure/account false independence, provider lifecycle
deletion, unavailable WORM support, the fact that availability is not
tamper-proof storage, operator remediation for conflicts/corruption, added
storage cost, continued hot `integrity_records` growth, and the existing
`SUPPLY_CHAIN_LICENSE_REVIEW` / `MISSING_SUPPLY_CHAIN_ATTESTATIONS` residuals.
