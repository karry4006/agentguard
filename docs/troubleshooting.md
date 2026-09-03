# Troubleshooting

If the API is unavailable, check container status and logs:

    docker compose ps
    docker compose logs --tail=100 agentguard-migrate agentguard-server

If migration is not complete, wait for agentguard-migrate to finish before
diagnosing the API. If bootstrap refuses to run, an existing .env or
.dev-secrets directory was found; preserve it and choose a new disposable
output directory.

If ingest returns unauthorized, verify that the API key belongs to the
selected tenant and includes ingest:write. If retrieval is unauthorized,
verify traces:read and the X-API-Key header. Do not paste keys or database
URLs into issues or logs.

If the SDK appears silent, check the application’s flush and shutdown path,
the bounded spool diagnostics, AGENTGUARD_INGEST_URL, and loopback
connectivity. Recorder failure is expected to be fail-open for the host
application.
