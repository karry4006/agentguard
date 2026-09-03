# Configuration

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
