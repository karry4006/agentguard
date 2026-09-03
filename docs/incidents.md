# AgentGuard V10 Incidents

AgentGuard incidents are bounded, tenant-scoped projections of verified V5
deterministic findings. They never replace or mutate `event_log`, integrity
records, traces, spans, replay records, or evaluation records.

## Fingerprints and grouping

The persisted fingerprint version is `incident-fingerprint-v1`. Its SHA-256
input is canonical JSON containing only bounded structured dimensions:
category, detector, component, and available workflow/agent/provider/model
identifiers. Natural-language reasons, prompts, users, model output, tool
payloads, credentials, and raw error messages are excluded. The title is a
safe deterministic value such as `TIMEOUT in get_weather`.

An occurrence is idempotent on tenant, trace, analysis, and finding identity.
The unique incident fingerprint constraint and PostgreSQL row locking make
same-tenant concurrent processing safe. A late occurrence never moves
`first_seen_at` forward.

## Status, severity, and trend

Statuses are `OPEN`, `ACKNOWLEDGED`, and `RESOLVED`. A new matching occurrence
reopens a resolved incident and records a `REOPENED` lifecycle event.

Severity is deterministic under `severity-v1`: LOW is the default, MEDIUM is
used after three occurrences, and HIGH is used for authentication,
authorization, timeout, or guardrail categories or ten occurrences. The
highest trusted V5 severity is retained; V10 has no configured automatic
CRITICAL condition. Telemetry cannot downgrade severity. Trend compares
bounded recent one-hour and preceding one-hour occurrence windows and returns
`INCREASING`, `STABLE`, `DECREASING`, or `INSUFFICIENT_DATA`.

## API and authorization

- `GET /v1/incidents` and `GET /v1/incidents/{id}` require `incidents:read`.
- `POST /v1/incidents/{id}/acknowledge`, `/resolve`, and `/reopen` require
  `incidents:manage`.
- All queries are tenant constrained; another tenant receives 404.
- Responses contain bounded occurrence/history/finding projections, never a
  raw trace dump or arbitrary error text.

Incident processing runs only for persisted V5 deterministic findings after
V3 integrity verification. V10 sends no notifications, runs no replay, and
performs no remediation or outbound side effects. V8 records are represented
only as `associated_with` metadata.

Migration `0007_incident_management` grants the runtime role SELECT,
INSERT, and UPDATE on the three incident tables and no DELETE. Migration and
runtime identities remain separate.
