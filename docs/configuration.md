# Configuration

Configuration is environment-driven. Names below use the `AGENTGUARD_`
prefix unless noted otherwise.

The checked-in .env.example is a placeholder template. For local work, run
scripts/bootstrap-dev.ps1. It generates cryptographically random credentials
and writes ignored files under .dev-secrets without overwriting existing
configuration.

The local Compose file consumes:

- database role names and passwords from the generated .env;
- key pepper and integrity key secret files;
- database URL files for the runtime, migration, retention, compactor, and
  replication roles;
- the archive encryption keyring file when archive features are enabled.

Safe local defaults include:

- content capture disabled;
- OIDC, anchoring, archive, retention purge, replication, and compaction
  disabled;
- dashboard API-key login enabled for loopback use;
- ingest URL set to http://127.0.0.1:8000/v1/ingest.

SDK applications normally set AGENTGUARD_INGEST_URL and
AGENTGUARD_API_KEY. Configure redaction and spool limits for the application
risk and throughput profile. Never commit .env, .dev-secrets, database URLs,
API keys, archive keys, or private keys.

Production should inject secrets through the deployment secret manager and
use externally managed TLS, database credentials, key rotation, and
environment-specific policy. Do not treat this local template as a
production baseline.

## Configuration groups

- Required server secrets: `KEY_PEPPER`, `INTEGRITY_KEY`, and `DATABASE_URL`
  (or their `*_FILE` forms). Secret-file values must be single-line and are
  never returned by diagnostics.
- SDK: `INGEST_URL`, `API_KEY`, `CAPTURE_CONTENT`, `SPOOL_ENABLED`,
  `SPOOL_PATH`, `QUEUE_SIZE`, `BATCH_SIZE`, flush interval, retry, and spool
  size limits. Keep capture disabled unless the data policy permits it.
- Authentication and dashboard: `AUTH_ENABLED`, API-key login controls,
  session limits, and optional OIDC issuer/client/redirect settings.
- Evidence and retention: archive store/keyring settings, retention and
  replica controls, and integrity segment limits. These are disabled in local
  Compose unless explicitly enabled.
- Witness/quorum: operator-configured witness registry and V20 policy. A
  client or model trace cannot configure trust or authorize destructive work.
- OTLP and analysis: bounded request, attribute, evidence-packet, model-call,
  concurrency, and timeout limits. These protect the service and are not
  performance guarantees.

Inspect `server/src/agentguard_server/config.py` for the authoritative list,
validation, defaults, and aliases. Use `scripts/bootstrap-dev.ps1` for a
disposable local configuration rather than copying production secrets.
