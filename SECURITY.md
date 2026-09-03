# AgentGuard Security Policy

## Scope

This policy covers the V0 Flight Recorder, V1 durable SDK spool, V2 Trust Boundary, V3 Evidence Integrity, and V4 Safe Replay in this repository. Telemetry, trace metadata, tool output, errors, API keys, the key pepper, the integrity key, PostgreSQL, the local spool, and the Docker runtime are security-sensitive assets.

V6 adds an OpenTelemetry Python bridge, V7 adds an OTLP/HTTP protobuf gateway, and V8 adds an offline regression evaluation release gate. OpenTelemetry attributes and evaluation telemetry are untrusted data, not authority. Neither adapter can assign tenants, scopes, credentials, integrity keys, replay policy, or analysis policy; V8 policies are trusted, bounded, declarative operator configuration. GenAI messages, prompts, outputs, tool arguments/results, and credential-shaped values are redacted before spool or network delivery. The gateway applies bounded protobuf decoding and dual compressed/decompressed limits. MCP-shaped telemetry is observability-only; the bridge never connects to or executes an MCP server.

## Public release status

V20 core is sealed and complete. This repository is in local productization
and the initial GitHub repository is private. V21 has not started.

## Private reporting

For private vulnerability reports, email
`agentguard.project@gmail.com`. Security issues should **not** be filed as
public GitHub issues. Include the affected version, reproduction information,
impact, and suggested remediation where appropriate. Do not send secrets
unnecessarily; redact credentials, private telemetry, and other sensitive
values from reports. No response SLA or vulnerability bounty is promised.

Prefer private/encrypted reporting where available.

## Reporting

Do not include API keys, database passwords, pepper values, prompts, or private telemetry in a report. For a deployment, use the operator's private security-reporting channel and include a minimal reproduction, affected version, impact, and whether the issue is exploitable without authentication.

## Security invariants

- Server authentication and authorization fail closed.
- Tenant identity comes only from a verified API key; client telemetry cannot select a tenant.
- API key secrets are displayed once and stored only as HMAC digests with `AGENTGUARD_KEY_PEPPER`.
- SDK/exporter failures fail open for the monitored application and retain bounded durable telemetry where possible.
- Telemetry is untrusted data, never configuration or executable authority.
- V3 stores sanitized canonical evidence digests in an append-only event ledger and verifies an HMAC-SHA256 per-trace chain; missing keys or unsupported versions are unverifiable, never valid.
- Integrity keys are supplied by protected environment/secret injection and are never persisted in PostgreSQL, SQLite, telemetry, logs, or repository files.
- V4 replay is dry-run only: telemetry cannot define policy, and only trusted local deterministic simulators may produce output. No replay path has production side effects.
- Replay requires a valid V3 integrity result, is tenant-scoped and idempotent, and persists only replay session/step rows; original evidence remains append-only.
- V5 analysis is read-only against source evidence, deterministic-first, tenant-scoped, bounded, and separately authorized by `analysis:run`. Optional AI judges receive minimized evidence only, have no tools, and cannot trigger replay or mutations.
- V8 evaluation is offline, deterministic, integrity-gated, paired by explicit case IDs, tenant-scoped, bounded, and separately authorized by `evaluations:read`, `evaluations:run`, and `evaluations:manage`. It accepts no executable evaluator, arbitrary SQL/Python, telemetry policy override, deployment, rollback, replay, tool execution, or AI gate decision.
- Production deployments must provide PostgreSQL credentials and pepper through an external secret mechanism; `.env` is for local development only.
- V9 release metadata contains only version, source/build provenance, migration head, Python version, lockfile checksums, SBOM status, and test summary. It must never contain credentials or secret values.
- Startup rejects missing/placeholder authentication or integrity configuration, invalid database URLs, direct plus `_FILE` conflicts, empty/multiline secret files, and production SQLite.
- Readiness is separate from liveness and checks the database, expected migration head, and required security configuration. Application workers never run migrations.
- PostgreSQL runtime connections use bounded pool/connect/statement timeouts and the existing runtime role remains non-superuser with no privileged memberships.
- V13 human identity is the verified OIDC `(issuer, subject)` pair; email,
  display name, telemetry, and AI output never grant identity or permissions.
- Human sessions revalidate active user, organization membership, fixed role,
  and tenant on every request. Unknown roles/permissions deny by default, the
  last ADMIN is protected, and human principals remain separate from API keys.
- V9.2 promotes only the pinned Distroless Python 3.13 Debian 13 runtime;
  the final image is nonroot, read-only, capability-free, no-shell, and uses
  direct exec-form server and healthcheck commands. The SDK remains supported
  on Python >=3.12 and the server lockfile is installed in a clean Python 3.13
  builder.

## Supported security checks

The repository security workflow runs compile checks, pytest, Bandit, pip-audit, and secret-safe regression tests. Docker live acceptance is an operator-controlled check because it requires a running Docker Desktop and a real PostgreSQL service.

## Container vulnerability triage

Docker Scout findings from upstream base images are recorded separately from
fixable findings. A raw Critical/High count is not automatically treated as a
defect, but every finding must be mapped to `FIXED`, `NOT_AFFECTED`, or
`AFFECTED_NO_FIX` with technical evidence. The release gate fails on any
fixable Critical/High, CISA KEV, or untriaged finding. `AFFECTED_NO_FIX` also
blocks the gate unless an operator-approved risk exception is supplied with a
traceable reference. VEX is permitted only for objective `NOT_AFFECTED`
evidence and is never used to hide an affected package. The current V9
dispositions are maintained in `security/v9-scout-triage.json`.

V9.2 promotion re-scanned the selected immutable image and recorded 0 raw
Critical/High, 0 fixable Critical/High, and 0 CISA KEV findings. The prior V9
Bookworm base-image findings remain historical evidence; they are not present
in the promoted Distroless image. The release manifest and CycloneDX SBOM
record the selected image and base digest.

## V10 incident management

Incident records are derived projections only. V3 integrity must be valid and
only V5 deterministic findings are automatically projected. V10 uses bounded
allowlisted dimensions for versioned fingerprints, stores no raw prompt/user/
model/tool content in incident identity, enforces tenant predicates, and adds
`incidents:read`/`incidents:manage` without auto-granting existing keys. No
notifications, replay, remediation, or outbound side effects are performed.
Runtime PostgreSQL access to incident tables is SELECT/INSERT/UPDATE only;
DELETE remains unavailable.

## V12 dashboard boundary

The operator console is a tenant-scoped observation/control plane, not an
admin shell or deployment/remediation system. Dashboard login requires the
separate `dashboard:access` scope and creates an opaque eight-hour session
whose session and CSRF token hashes are stored in `dashboard_sessions`.
Requests revalidate the originating API key and current scopes; revocation or
expiry invalidates existing sessions. Production cookies are HttpOnly, Secure,
SameSite=Strict, and path-rooted. Mutations are POST-only with a session-bound
CSRF check.

Templates use autoescaping and plain text for attacker-controlled telemetry or
AI output. The strict self-only CSP forbids inline/eval scripts, and all UI
responses are `no-store`. Runtime access to `dashboard_sessions` is
SELECT/INSERT/UPDATE only; session cleanup does not require DELETE. The UI
never displays API keys, token values, secrets, raw prompts/tool content,
database URLs, or Docker environment, and it exposes no shell, SQL console,
arbitrary HTTP client, MCP executor, deployment, or production remediation.

## V13 identity and authorization boundary

OIDC uses Authorization Code with PKCE S256, one-use state, nonce, bounded
trusted-issuer discovery/JWKS/token calls, explicit RS256, and complete issuer,
audience, lifetime, and signature validation. Provider tokens and raw claims
are not persisted or rendered. Organization-to-tenant mapping and fixed-role
permissions are server-owned; browser fields and IdP presentation claims
cannot select roles. Human administration is CSRF protected, tenant scoped,
audited, and immediately reflected in existing sessions. Machine API-key paths
remain independently authenticated and scoped.


## V14 coordination security

Shared security-sensitive state is PostgreSQL-authoritative. Rate-limit keys
are bounded SHA-256 digests of controlled identities, notification ownership
uses row locks plus per-claim tokens, and OIDC state is one-time consumed in
the database. Database outage behavior fails closed for security-sensitive
server operations; SDK monitoring remains fail-open.
## V15 external integrity anchoring

V15 checkpoints only eligible V3 chain heads and sends a compact digest to an
independent `https-signed-witness-v1` Ed25519 witness. AgentGuard stores trusted
public verification keys only; the witness private key stays outside the
AgentGuard image, database, repository, logs, and backup. Remote continuity
explicitly reports `MATCH`, `REMOTE_AHEAD`, `LOCAL_AHEAD`, `DIVERGED`, or
`WITNESS_UNAVAILABLE`; it does not auto-repair, replay, remediate, or deploy.
See [docs/external-integrity-anchoring.md](docs/external-integrity-anchoring.md).
## V16 retention and archival

Cold archival is disabled by default and is controlled only by trusted
deployment configuration. Archive eligibility is deterministic and requires
valid V3 evidence and V15 checkpoint coverage. Purge is fail-closed on active
holds, stale projections, missing/tampered objects, invalid V3/V15 evidence,
or non-MATCH remote continuity. V16 never deletes the V3 ledger or V15
checkpoint/receipt data and exposes no archive-object delete operation.
Archive keys and S3 credentials remain outside PostgreSQL and images.
