# V17 verifiable ledger segment archival and compaction

V17 stores old V3 evidence in immutable, encrypted `ledger-segment-v1`
objects while keeping the V3 `integrity_records` and chain heads hot. The
current V3 implementation has a sequence per `(tenant_id, trace_id)`, so a
segment is explicitly scoped to one tenant and one trace; different tenants
and traces are never mixed.

Archival and destructive compaction are independent controls and both default
to disabled:

```text
AGENTGUARD_LEDGER_ARCHIVE_ENABLED=false
AGENTGUARD_LEDGER_COMPACTION_ENABLED=false
```

Segments are bounded by `AGENTGUARD_LEDGER_SEGMENT_MAX_EVENTS`, require the
configured minimum age, and retain `AGENTGUARD_LEDGER_HOT_TAIL_EVENTS` in
`event_log`. A candidate must pass the shared V3 canonical/HMAC verifier, a
valid V15 checkpoint with a covering trace entry, and external continuity
`MATCH` before it can be archived. The archive uses
`ledger-segment-envelope-v1`, deterministic gzip, AES-256-GCM, fresh nonces,
and an AAD purpose distinct from V16 trace archives.

Read-back verifies the ciphertext digest, authentication tag, decompression
bound, strict schema, segment manifest, event manifest, V3 event chain, and
range boundaries. Only then is the lifecycle `ARCHIVED_VERIFIED`.

Compaction requires a short-lived, digest-bound authorization and an active
`MATCH` result. The PostgreSQL implementation uses the narrow
`compact_verified_ledger_segment_v1(uuid)` security-definer function; the
compactor role is not granted broad `event_log` DELETE. The operation checks
the exact tenant/trace/range/count/index/boundaries and changes deletion and
`COMPACTED` state atomically. Repeating it is idempotent. V16 retention holds
block compaction.

`integrity_records`, current chain heads, V15 checkpoints/receipts, and V16
archive metadata are never deleted. No archive-object delete operation is
performed by AgentGuard. Object-store versioning, Object Lock/WORM,
replication, and independent backups are optional production hardening, not
protocol guarantees.

The dedicated worker is:

```text
python -m agentguard_server.ledger_compactor
```

The worker performs external archive and witness checks before the database
compaction transaction; it does not run compaction inside FastAPI. Historical
retrieval is read-only and never rehydrates rows into `event_log`.

Disaster recovery requires the PostgreSQL backup, all historical V3
verification-key versions, V15 verification configuration, V16/V17 archive
key history, archive access, and every compacted ledger object. Physical
PostgreSQL files may not shrink immediately after deletion; normal
autovacuum/reuse remains an operational concern.
