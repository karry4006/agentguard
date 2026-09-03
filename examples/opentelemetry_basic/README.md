# AgentGuard OpenTelemetry basic demo

This synthetic demo uses only the official OpenTelemetry Python SDK. It emits
one workflow with an agent, model, and deterministic tool span, then sends the
events through AgentGuard's existing redaction, SQLite spool, HTTP exporter,
and PostgreSQL ingestion path.

Configure `AGENTGUARD_INGEST_URL` and a tenant-scoped
`AGENTGUARD_API_KEY` in the environment before running. The API key is never
printed by the demo. With `AGENTGUARD_CAPTURE_CONTENT=false` (the default),
the synthetic model content is not stored.

```powershell
py examples/opentelemetry_basic/app.py
```

The printed trace ID can be queried through the normal AgentGuard trace API.
This is a Python SDK bridge, not a universal OTLP collector and it does not
connect to or execute MCP servers.
