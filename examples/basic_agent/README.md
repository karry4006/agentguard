# Basic local agent

This example sends one successful trace with an agent span and a deterministic
calculator tool span through the AgentGuard Python SDK. It does not call an
LLM, use a paid API, execute shell commands, or make an external tool request.

From the repository root, after the Quick Start has created an API key:

```powershell
$env:AGENTGUARD_INGEST_URL = "http://127.0.0.1:8000/v1/ingest"
$env:AGENTGUARD_API_KEY = "paste-the-one-time-local-key-here"
python -m pip install -e .\sdk\python
python .\examples\basic_agent\run.py
```

The command prints a `trace_id`, two spans, the calculator tool call, and a
bounded duration. Use that ID with the authenticated trace API, or sign in to
`http://127.0.0.1:8000/ui` with the same key. Cleanup is `docker compose stop`.
