# AgentGuard production deployment

AgentGuard V9.2 is a single-region release-engineering baseline. Run the server
with the Compose file and a PostgreSQL service on a private network. Do not
expose PostgreSQL publicly, mount a Docker socket or named pipe, or run the
server as root.

## Configuration

Use an external secret manager or protected file injection. The server accepts
`AGENTGUARD_KEY_PEPPER_FILE`, `AGENTGUARD_INTEGRITY_KEY_FILE`, and
`DATABASE_URL_FILE`; OIDC confidential clients additionally use
`AGENTGUARD_OIDC_CLIENT_SECRET_FILE`. Each file must contain one non-empty,
single-line value.
Setting both a direct variable and its `_FILE` counterpart is rejected. File
paths and secret values are never logged. PostgreSQL bootstrap, runtime, and
migration credentials are separate; the runtime role must remain least
privileged and the migration role must not be passed to FastAPI. The promoted
server runtime is Python 3.13.5 in
`gcr.io/distroless/python3-debian13:nonroot` at digest
`sha256:f3d5ddc6c64a019fe520e7f005f2880be21e6afc461b10a3c15ef2e4edc71e33`.

Set `AGENTGUARD_ENVIRONMENT=production`, provide PostgreSQL, keep authentication
enabled, and use bounded request, pool, statement, and shutdown limits. The
container has a read-only root filesystem, drops all Linux capabilities, uses
`no-new-privileges`, has no shell or package manager, and runs as UID/GID
65532. The server and healthcheck use direct exec-form Python commands.

## Startup and health

Run migrations as the one-shot `agentguard-migrate` service before starting the
server. Workers do not run migrations. Use `/health/live` for process/liveness,
`/health/ready` for database, security configuration, and migration-head
readiness, and `/health` for the V0-compatible database health response.

V16 readiness requires migration head `0013_evidence_retention_archival`.

## V13 OIDC deployment

Configure one trusted HTTPS issuer, client ID, HTTPS callback, audience, RS256,
and required claims. Register the callback exactly as
`https://YOUR_AGENTGUARD/ui/oidc/callback`. Terminate TLS at the trusted ingress,
do not forward arbitrary issuer input, and block public access to PostgreSQL.
If a client secret is required, mount its external secret file only into the
server; the browser, migration service, image, manifest, and SBOM must not
receive it. Bootstrap the first ADMIN explicitly after migration and before
opening operator access. Keep API-key browser login disabled unless V12
compatibility is an intentional deployment choice.

## Release procedure

Use `scripts/ci.ps1` for the canonical local checks and
`scripts/release-check.ps1` for the release gate. Generate the CycloneDX SBOM
with `scripts/sbom.ps1` when Docker Scout is available, then generate the
secret-free manifest with `scripts/release-manifest.ps1`. A missing optional
scanner is reported as `UNAVAILABLE`, never as a false PASS.

## Container CVE triage

Run Docker Scout against the exact release image and retain the SARIF output.
Report raw Critical/High findings separately from actionable findings. The
release policy requires zero fixable Critical/High findings, zero CISA KEV
findings, and zero untriaged findings. Every remaining unfixed finding must
be explicitly `FIXED`, `NOT_AFFECTED`, or `AFFECTED_NO_FIX` with technical
evidence. `AFFECTED_NO_FIX` blocks release unless an operator-approved risk
exception is recorded by reference; raw upstream findings are not silently
suppressed and no automatic risk acceptance is granted.

The promoted V9.2 image reports 0 raw Critical/High, 0 fixable Critical/High,
and 0 CISA KEV findings in Docker Scout. The seven findings from the previous
Bookworm image remain historical triage evidence in `security/v9-scout-triage.json`;
they are not suppressed and are not present in the selected image.

## V9.2 compatibility and rollback

The server must pass the full Python 3.13 suite with 0 skipped tests. The SDK
must also pass its Python 3.12 compatibility suite; its declared support stays
`>=3.12`. Verify `sys.executable`, `sys.version`, and `sys.path` inside the
runtime when diagnosing no-shell containers; use `docker inspect`, logs, the
health endpoints, and direct Python probes rather than shell access. Keep the
previous approved Python 3.12 image configuration available for rollback if a
future rebuild fails compatibility, database, shutdown, or security gates.

## V10 incident operations

Apply Alembic migrations through the migration identity; the runtime identity
must remain `agentguard_runtime` and must not receive migration credentials.
Verify `/health/ready` reports `0013_evidence_retention_archival`, then verify runtime
database identity and incident table grants. Grant API keys incident scopes
explicitly. Incident detail/history responses are bounded projections and V10
has no notification, replay, remediation, or outbound integration path.


## V14 replica deployment

Run the migration container once, then run N replicas against the same
PostgreSQL database with identical security/OIDC configuration and distinct
AGENTGUARD_INSTANCE_ID values. Sticky sessions are unnecessary. Size the
sum of all replica pools below the database connection budget and use
/health/ready as the database/migration readiness gate. See
distributed-coordination.md.
## V15 external anchoring

Enable anchoring only with a trusted HTTPS endpoint, an operator-managed public
Ed25519 key registry, and a stable namespace. AgentGuard receives no witness
private key. Keep `AGENTGUARD_ALLOW_PRIVATE_ANCHOR_TESTS=false`; local HTTP
witnesses are test-only. External witness availability is not part of ordinary
readiness, but freshness and continuity must be monitored. See
[external-integrity-anchoring.md](external-integrity-anchoring.md).

## V16 evidence retention and cold storage

Enable archival only with an external HTTPS S3-compatible endpoint, an
externally injected archive encryption-key registry, and credentials supplied
through protected file injection. The retention role may delete only classified
hot projection rows; it must never delete V3 event-log/integrity rows or V15
checkpoint/continuity rows. Keep `AGENTGUARD_RETENTION_PURGE_ENABLED=false`
until archive verification, hold workflows, restore drills, and monitoring are
approved. See [evidence-retention-archival.md](evidence-retention-archival.md).

