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

examples/basic_agent/run.py is a complete no-paid-API example. The
OpenTelemetry and OpenAI examples show optional integrations; the OpenAI
example requires an independently supplied OPENAI_API_KEY and is not needed
for a basic installation.

## Lifecycle and data contract

Create one `AgentGuardTracingProcessor` for the application lifetime. Send a
trace start, span start/end pairs, and trace end; call `force_flush()` at a
known handoff and `shutdown()` during orderly process exit. The processor
normalizes agent, model, tool, guardrail, handoff, and custom spans. It applies
bounded redaction before persistence and the service applies its own bounded
sanitization again.

The exporter is fail-open: recorder delivery failure is reported through
diagnostics and must not become an agent tool or shell action. Durable spool
mode retains bounded pending events; in-memory mode may drop events when its
queue is full. Capture only data allowed by the application's privacy policy;
do not record credentials or unrestricted prompts.
