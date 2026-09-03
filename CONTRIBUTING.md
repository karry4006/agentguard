# Contributing to AgentGuard

## Local setup

Use Python 3.12 or newer and Docker Compose v2. From the repository root:

    powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap-dev.ps1
    docker compose up --build -d
    python -m pip install -e .\sdk\python

The bootstrap creates ignored local credentials and refuses to overwrite an
existing .env or .dev-secrets directory. Never commit generated files,
database URLs, API keys, archive keys, private keys, or copied production
telemetry.

## Checks

Run the focused product checks before submitting a change:

    powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1 -SkipDocker

Run Docker configuration checks when Docker is available:

    powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1

Add or update tests for behavior changes. Keep live V20 acceptance tests and
their evidence fixtures separate from the normal local test path.

## Database and security changes

Migrations are forward-only Alembic migrations. Do not rewrite an applied
migration or use destructive migration behavior to make a test pass. Keep
authentication, tenant isolation, redaction, fail-closed authorization,
evidence integrity, replay safety, and secret-handling invariants intact.
Review SECURITY.md and docs/security.md for security-sensitive changes.

## Change review

Keep pull requests focused and explain compatibility, migration, operational,
and security impact. Do not add fake badges or claim a scan, release, or
deployment that was not actually run. Do not publish repositories, images, or
release artifacts as part of local development work.
