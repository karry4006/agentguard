# OTLP/HTTP ingestion

V7 provides a language-neutral protocol seam for OTLP trace exporters:

```text
POST /otlp/v1/traces
Authorization: Bearer <AgentGuard API key>
Content-Type: application/x-protobuf
Content-Encoding: gzip       # optional; identity/absent is supported
```

The API key must carry the existing `ingest:write` scope. The tenant is taken
only from the authenticated key. `tenant_id` attributes, resource metadata,
`service.name`, `service.namespace`, and baggage cannot select a tenant.

The body is an official `ExportTraceServiceRequest`. The gateway supports
`ResourceSpans`, `ScopeSpans`, spans, bounded AnyValue attributes, span events,
and links. IDs must be valid OTLP binary IDs and are stored as lowercase
canonical hexadecimal values. The response for an accepted request is an
empty official `ExportTraceServiceResponse` with HTTP 200. Malformed or
unsupported requests receive a safe 4xx response.

Default limits are configurable with `AGENTGUARD_OTLP_*` environment variables:

- compressed body: 1 MiB
- decompressed body: 4 MiB
- ResourceSpans: 100; ScopeSpans: 1,000; spans: 1,000 per request
- attributes: 64 per span/event/link; events and links: 128 per span
- attribute key: 128 characters; value: 2,048 characters
- normalized metadata: 16 KiB; AnyValue depth/items: 8/128

Both compressed and decompressed limits are enforced. AnyValue conversion is
recursive but bounded. The existing request limit and tenant-aware process-local
rate limiter remain active.

OTLP spans converge into the existing AgentGuard event model. No OTLP-specific
tables or migration are used. Span and trace lifecycle events are idempotent;
retransmitting a span does not allocate another evidence-chain record. An
export request does not claim that a trace is complete, so partial and late
exports remain possible. Once the server accepts and commits events, AgentGuard
guarantees their persistence according to the existing transaction; durability
before acceptance depends on the remote client's exporter retry/queue setup,
not the Python SDK's local SQLite spool.

`capture_content=false` remains the default. Prompt/completion/message,
tool-content, authorization, token, password, key, pepper, integrity-key, and
database-URL material is redacted or omitted before persistence. OTLP data is
never replay authority or execution authority. V3 integrity verification,
V4 dry-run replay policy, and V5 deterministic failure analysis apply equally
to OTLP-origin events.

The protocol claim is language-neutral, but the acceptance test uses the
official OpenTelemetry Python OTLP/HTTP exporter. Java, Go, and .NET framework
semantics are not claimed as separately tested. OTLP/gRPC, metrics, logs, and
profiles are not supported in V7. Production TLS termination remains a
deployment responsibility.
