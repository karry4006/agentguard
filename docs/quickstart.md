# AgentGuard local Quick Start

This is the canonical local development path. It starts PostgreSQL, the
forward-only migration job, and the API server. The optional retention,
ledger, integrity, and replication workers are disabled unless their Compose
profiles are explicitly selected.

## Prerequisites

Use Git, Docker Desktop or Docker Engine with Compose v2, and Python 3.12 or
newer. Make ports 8000 and 5432 available on loopback.

## Fresh setup

From the repository root in PowerShell:

    powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap-dev.ps1
    docker compose up --build -d
    curl.exe http://127.0.0.1:8000/health

The bootstrap uses the operating system cryptographic random number generator.
It creates .env and .dev-secrets only when neither already exists, and never
prints secret values. If either path exists, use a new disposable directory or
remove only the exact local development directory after confirming it contains
no user data.

Create a tenant and a least-privilege local key:

    docker compose exec -T agentguard-server /usr/bin/python3.13 -m agentguard_server.cli tenant create --slug demo --name "Local Demo"
    docker compose exec -T agentguard-server /usr/bin/python3.13 -m agentguard_server.cli key create --tenant demo --name basic-demo --scopes ingest:write,traces:read,dashboard:access,incidents:read,integrity:read

The second command prints an API key once. Put that value in the current
shell only:

    $env:AGENTGUARD_INGEST_URL = "http://127.0.0.1:8000/v1/ingest"
    $env:AGENTGUARD_API_KEY = "<one-time-key>"
    python -m pip install -e .\sdk\python
    python .\examples\basic_agent\demo.py

The example emits one trace and a calculator-tool span without calling an LLM
or a paid API. Retrieve the result:

    curl.exe -H "Authorization: Bearer <one-time-key>" http://127.0.0.1:8000/v1/traces

Open the dashboard at http://127.0.0.1:8000/ui/login and submit the same key.
The dashboard is a local operational view; it is not an authentication system
for a production internet deployment.

Stop safely:

    docker compose stop

This preserves the local PostgreSQL volume. Use docker compose down only when
you intentionally want to remove the local containers and network; do not use
the volume-deleting form against a shared or valuable environment.

## What PASS means

A fresh Quick Start is PASS only when the documented commands are sufficient
to reach a healthy API, create the tenant and key, emit a trace, retrieve that
trace, and load the dashboard. Record elapsed time, errors, and any manual
steps in the Phase 1 evidence artifact. No undocumented manual step is
acceptable.

## Local limitations

The default configuration disables content capture, anchoring, archive
replication, retention purge, and optional workers. It uses loopback HTTP,
one PostgreSQL instance, and development credentials. Production requires
TLS, managed secret injection, backups, independent failure domains, and
explicit identity and retention policy.

For Linux or macOS, use the equivalent shell invocation for the bootstrap
script or generate the same secret files with an approved local secret
manager; do not copy Windows paths into a shared configuration.
