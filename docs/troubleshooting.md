# Troubleshooting

If the API is unavailable, check container status and logs:

    docker compose ps
    docker compose logs --tail=100 agentguard-migrate agentguard-server

If migration is not complete, wait for `agentguard-migrate` before diagnosing
the API. If bootstrap refuses to run, an existing `.env` or `.dev-secrets`
directory was found; preserve it and choose a new disposable output directory.

If ingest returns unauthorized, verify that the API key belongs to the
selected tenant and includes `ingest:write`. If retrieval is unauthorized,
verify `traces:read` and the documented authorization header. Never paste keys
or database URLs into issues or logs.

If the SDK appears silent, check the application's `force_flush()` and
shutdown path, bounded spool diagnostics, `AGENTGUARD_INGEST_URL`, and
loopback connectivity. Recorder failure is expected to be fail-open for the
host application.

On PowerShell, use `curl.exe` rather than the shell alias and use the paths in
the Quick Start exactly. On Linux/macOS, replace PowerShell environment
assignments with `export`. A port conflict on 8000 or 5432 is reported by
Compose; stop the conflicting local service or change the local mapping before
retrying. Do not delete volumes to fix a migration or data problem.

If a trace is missing, check SDK diagnostics, API-key scopes, tenant, and
whether `force_flush()` and `shutdown()` ran. If the dashboard loads but has
no data, confirm the browser uses the same loopback URL and the key has
dashboard access. For integrity or replay refusal, preserve the trace and
inspect the reported status; never edit sealed evidence to make a replay pass.
