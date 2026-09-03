# AgentGuard V4 Replay Security Contract

## Scope

V4 creates a reproducible simulation plan from a verified V3 trace. It is not an execution engine. The only accepted API mode is `dry_run`; the request model rejects additional fields such as `live`, `force`, and `unsafe`.

## Trust boundary

The V3 integrity verifier is a hard precondition. A trace with an invalid chain, projection mismatch, sequence gap, missing event, missing verification key, or unsupported canonicalization version is not replayed. Missing keys and unsupported versions remain `unverifiable`, and produce `REPLAY_REFUSED_INTEGRITY` rather than a tampering claim.

Recorded telemetry is attacker-controlled data. Recorded or client-declared tool classifications never select a simulator. The policy registry is application configuration, with an exact tool-name allowlist. `READ_ONLY` and `DETERMINISTIC` tools may use an explicitly configured deterministic simulator. `MUTATING`, `HIGH_IMPACT`, and `UNKNOWN` tools are blocked.

The built-in `get_weather` simulator is a pure local fixture. It has no network, shell, subprocess, filesystem-write, database-write outside replay tables, Docker, cloud, payment, browser, MCP, or user-action capability. No `eval`, `exec`, `pickle`, unsafe YAML, or shell interpolation is used.

## Data and limits

The planner reads V3 `event_log` and `integrity_records` in verified sequence order. It does not use projections or timestamps as authority and never updates or deletes source traces, spans, event log rows, or integrity rows. Content-capture placeholders produce `INSUFFICIENT_REPLAY_DATA` / `UNAVAILABLE`; invented output is forbidden.

Replay sessions are tenant-scoped and support an `Idempotency-Key`. Replay state is limited by maximum steps, input bytes, duration, concurrent sessions, and request rate. Only `replay_sessions` and `replay_steps` are writable by the runtime database role; source evidence remains append-only.

## Operator contract

Use `python -m agentguard_server.cli replay run --tenant <slug> --trace-id <trace-id>`. There are intentionally no live, force, unsafe, or skip-integrity options. Any future production execution or MCP integration requires a separate security review and version gate.
