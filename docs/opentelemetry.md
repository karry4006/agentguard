# OpenTelemetry

The stable AgentGuard bridge is
AgentGuardOpenTelemetrySpanProcessor, which implements the OpenTelemetry
SpanProcessor interface and normalizes spans into AgentGuard events.
examples/opentelemetry_basic contains a small usage example.

Use the existing OTLP documentation for gateway and transport details:
docs/otlp-ingestion.md and docs/interoperability.md. OTLP telemetry is
diagnostic data, not authority. Authentication, tenant scope, and evidence
integrity remain server responsibilities.

The bridge covers spans and maps them into the AgentGuard event schema. OTLP
HTTP ingestion is bounded and authenticated; consult `docs/otlp-ingestion.md`
for limits and transport configuration. Logs, metrics, and profiles are not
represented by the current trace projection, so use their existing systems
for those signals. OpenTelemetry input is diagnostic telemetry and cannot
configure replay policy, witness trust, tenant scope, or destructive actions.
