# OpenTelemetry interoperability

V7 adds a protocol-level receiver at `POST /otlp/v1/traces` for OTLP/HTTP
protobuf traces. It accepts standard `application/x-protobuf` requests with
identity/absent or gzip content encoding, authenticates with the existing
`ingest:write` API-key scope, and returns an OTLP protobuf response. It calls
the same V6 `normalize_otel_span` seam as the in-process Python bridge, then
uses the existing event, redaction, server ingestion, PostgreSQL integrity,
replay, and analysis paths. See [otlp-ingestion.md](otlp-ingestion.md) for
limits and delivery semantics.

AgentGuard V6 provides a provider-neutral Python OpenTelemetry bridge. The
public seam is `AgentGuardOpenTelemetrySpanProcessor`, which implements the
official OpenTelemetry Python SDK `SpanProcessor` interface. It converts
`ReadableSpan` lifecycle callbacks into the existing `trace.started`,
`span.started`, `span.ended`, and `trace.ended` events. Those events pass
through the existing redaction, durable SQLite spool, HTTP ingestion,
PostgreSQL, integrity, replay, and failure-analysis paths. There is no second
OpenTelemetry storage pipeline.

## Mapping

The bridge reads the evolving GenAI attributes `gen_ai.operation.name`,
`gen_ai.provider.name`, and related agent/workflow/model attributes when
present. The deterministic mapping is:

| OTel operation | AgentGuard span type |
| --- | --- |
| `invoke_agent`, `invoke_workflow`, `plan` | `agent` |
| `execute_tool` | `tool` |
| `chat`, `generate_content`, `text_completion` | `llm` |
| `retrieval` | `custom` |
| MCP tool attributes | `tool` |
| unknown operation | `unknown` |

The original operation is retained only as a bounded, redacted observational
attribute for unknown operations. Provider is preserved in the trace lifecycle
when available and in the normalized span attributes. `openai`, `anthropic`,
and unknown providers use the same storage model. Provider and span type never
grant authorization or alter tenant identity.

Mapping metadata is emitted with `otel_semconv_version=otel-genai-evolving` and
`agentguard_mapping_version=otel-genai-v1`. Future convention attributes are
ignored or bounded rather than treated as authority. A mapping change must
use a new mapping version; historical events are not silently reinterpreted.

## Lifecycle and identity

Valid upstream OpenTelemetry trace and span IDs are rendered as fixed-width
lowercase hexadecimal AgentGuard IDs. Parent IDs are preserved. A root span's
`on_start` emits one `trace.started`; a root span's `on_end` emits one
`trace.ended` only when the root start was observed. Duplicate end callbacks
are ignored. If a process ends before a root start or end is observed, the
bridge does not invent a successful completion.

## Trust and privacy

OpenTelemetry telemetry is data, not authority. Attributes cannot set tenant,
scopes, API authorization, integrity keys, database credentials, replay mode,
or analysis policy. Tenant identity continues to come from the authenticated
AgentGuard API credential.

Message, prompt, completion, tool argument/result, authorization, API-key,
password, pepper, integrity-key, and database-URL content is redacted or
omitted before durable persistence. `capture_content=false` remains the
default. Attribute count, key length, value length, nesting, and serialized
metadata size are bounded deterministically.

The bridge is fail-open for the monitored application: mapping, exporter,
serialization, and SQLite failures are caught and exposed through thread-safe
diagnostic counters. It reuses `HttpBatchExporter`, so outage recovery,
at-least-once delivery, and event idempotency retain V1 behavior.

## MCP and limitations

MCP-shaped attributes can be observed and normalized as tool telemetry only.
V6 does not connect to, execute, trust, install, or discover an MCP server.

OpenTelemetry GenAI conventions are evolving, and frameworks do not emit
identical attributes. Missing instrumentation produces missing evidence;
generic mapping cannot infer semantics that were never emitted. Disabled
content capture limits replay and diagnosis detail. V7 supports the
language-neutral OTLP/HTTP protobuf protocol, but this does not claim
framework-specific Java, Go, or .NET semantics unless separately tested.
OTLP/gRPC, metrics, logs, and profiles are out of scope.
