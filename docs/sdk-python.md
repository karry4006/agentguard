# Python SDK

Install the editable SDK for local development:

    python -m pip install -e .\sdk\python

Set AGENTGUARD_INGEST_URL and AGENTGUARD_API_KEY in the application
environment, then construct AgentGuardConfig.from_env(). The
AgentGuardTracingProcessor accepts trace and span lifecycle events, applies
bounded buffering and redaction, and sends batches to the ingest API.

The SDK is intended to fail open when the recorder is unavailable. Configure
spool capacity, flush intervals, and event size limits for the application’s
latency and durability needs. Do not put secrets, unrestricted prompts, or
tool credentials into captured content. Content capture is disabled in the
local template.

examples/basic_agent/demo.py is a complete no-paid-API example. The
OpenTelemetry and OpenAI examples show optional integrations; the OpenAI
example requires an independently supplied OPENAI_API_KEY and is not needed
for a basic installation.
