# OpenTelemetry

The stable AgentGuard bridge is
AgentGuardOpenTelemetrySpanProcessor, which implements the OpenTelemetry
SpanProcessor interface and normalizes spans into AgentGuard events.
examples/opentelemetry_basic contains a small usage example.

Use the existing OTLP documentation for gateway and transport details:
docs/otlp-ingestion.md and docs/interoperability.md. OTLP telemetry is
diagnostic data, not authority. Authentication, tenant scope, and evidence
integrity remain server responsibilities.
