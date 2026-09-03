# Operations

## Lifecycle

Health endpoints are intended for local and deployment probes:

    curl.exe http://127.0.0.1:8000/health
    curl.exe http://127.0.0.1:8000/health/live

Monitor ingest rejection rates, queue and spool pressure, database capacity,
integrity verification failures, archive lag, witness disagreement, key
rotation age, and replay quarantine. Back up PostgreSQL and encryption
material together under separate access controls, and rehearse restore and
verification.

Use docker compose stop for a safe local pause. Do not remove shared volumes
or run destructive cleanup commands as part of routine diagnosis. See the
existing incident, retention, disaster-recovery, and production-deployment
documents for detailed runbooks.

Before a deployment, apply migrations with the migration job, verify
`/health/live` and `/health`, then exercise authenticated ingest and trace
readback. During shutdown, allow the SDK to flush and stop workers before
terminating the process. Keep PostgreSQL backups, integrity keys, and archive
encryption material recoverable under separate access controls; restore them
together and run integrity verification before serving restored data.

V20 witness receipts are evidence inputs, not a consensus protocol. A remote
ahead, diverged, stale, invalid, or unverifiable quorum state blocks
destructive work. Treat `QUORUM_MATCH_DEGRADED` as observable degraded health,
not as evidence that every configured witness is available.
