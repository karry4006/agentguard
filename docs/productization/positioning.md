# Product positioning

AgentGuard is a vendor-neutral flight recorder and reliability/debugging layer
for AI-agent applications. Its workflow combines bounded trace capture,
evidence integrity verification, safe replay planning, deterministic failure
analysis, and paired regression evaluation.

| Compared with | AgentGuard's scope |
| --- | --- |
| Application logs | Structured spans, tool boundaries, trace retrieval, and evidence links. |
| Generic APM | Agent-oriented spans and replay/evaluation workflows; it is not a replacement for every APM signal. |
| Agent framework | A recorder around the application; it does not plan, reason, or execute tools. |
| OpenTelemetry collector | Focused persistence and debugging; OTLP remains an optional input path. |
| Replay-only utilities | Adds integrity checks, policy-controlled simulation, analysis, and regression comparison. |

The project does not claim universal security, unrestricted replay, hosted SaaS,
paid-model availability, or compliance certification. The included Compose
topology is for local development and evaluation.
