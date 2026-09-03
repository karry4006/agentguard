# AgentGuard disaster recovery

Backups are PostgreSQL logical custom-format dumps. They preserve application
data without replacing the existing Docker volume. Run:

```powershell
./scripts/backup.ps1 -OutputPath artifacts\agentguard-backup.dump
./scripts/restore-check.ps1 -BackupPath artifacts\agentguard-backup.dump
```

The restore check creates a uniquely named temporary schema inside the
AgentGuard PostgreSQL database, restores the dump into that isolated target,
verifies the Alembic head (`0013_evidence_retention_archival`), and drops only that
temporary schema. This target is used because the least-privileged migration
role is intentionally not `CREATEDB`; no runtime or migration role is promoted
just to test recovery. It does not delete the source volume or existing
non-test data. Keep backup files in a protected, encrypted operator-controlled
location and apply an independent retention policy.

After a PostgreSQL or server restart, verify container health, `/health/live`,
`/health/ready`, the current migration head, and a tenant-scoped trace query.
The SDK spool is local durable buffering, not a replacement for database
backups; retain and recover its directory according to the application
deployment policy.

## Secret recovery material

Database backup alone is not sufficient for complete AgentGuard recovery.
Production recovery material must include protected recovery copies of
`AGENTGUARD_KEY_PEPPER`, every active or verification-only integrity key, the
integrity key identifiers and rotation metadata, and the relevant external
secret-manager configuration. Secret values must never be committed, logged,
included in a release manifest/SBOM, or passed through telemetry.

Loss of `AGENTGUARD_KEY_PEPPER` means existing API credentials cannot be
assumed valid and may require controlled reissuance. Loss of an integrity
verification key makes evidence signed with that key
`UNVERIFIABLE_KEY_MISSING`. Old evidence must never be retroactively resigned
to claim original authenticity.

Recovery objectives, backup encryption, off-host replication, and multi-region
failover are deployment-specific residual risks for this V9 baseline.

## Dashboard sessions

The V12 `dashboard_sessions` table is included in logical backups. A restored
session is not automatically trusted after a disaster-recovery event: revoke
active sessions before resuming operator access. Revoked and expired sessions
remain unusable after restore, and runtime needs only SELECT/INSERT/UPDATE on
the table; cleanup does not require runtime DELETE.

V13 HumanUser, Organization, Membership, and identity audit rows are included
in the same logical backup. After restore, revoke all active human and API-key
dashboard sessions before reopening the console, verify at least one intended
active ADMIN per organization, and revalidate the configured issuer/client and
external OIDC client-secret reference. Do not infer membership from IdP email
or group claims during recovery. Loss of IdP access does not block machine API
ingestion, but it does block new human sessions.


## V14 coordination recovery

Rate-limit buckets, notification leases, circuit state, and OIDC attempts
are coordination state. Restored leases expire, restored buckets age out,
and restored OIDC attempts remain one-time and expiry-bound. Never revive
expired login transactions or weaken runtime database privileges.
## V15 anchor recovery

Backups include checkpoint, receipt, state, and anchor-job rows but never the
independent witness private key. Restore expired leases as reclaimable. Keep the
witness outside the AgentGuard backup boundary; an older restored database must
be checked against the unchanged witness and reported as `REMOTE_AHEAD`, with
no automatic repair. See [external-integrity-anchoring.md](external-integrity-anchoring.md).

