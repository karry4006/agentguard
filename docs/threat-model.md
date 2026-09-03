# AgentGuard Threat Model

## Trust boundaries

```text
Monitored Agent (untrusted behavior)
  -> AgentGuard SDK (validation/redaction)
  -> local SQLite spool (local-user boundary)
  -> network/TLS boundary
  -> AgentGuard API (authentication/authorization)
  -> OTLP protobuf decoder (bounded decompression/AnyValue conversion)
  -> tenant boundary
  -> PostgreSQL event ledger (canonical digest + HMAC chain)
```

## Assets and attackers

Assets include PostgreSQL telemetry and integrity ledger, SQLite spool contents, API keys, the key pepper, the integrity key, tenant data, trace metadata, future prompt/tool content, the server host, and the Docker runtime. Attackers include malicious API clients, compromised or prompt-injected agents, malicious telemetry producers, malicious tenants, stolen-key holders, database-only tamperers, compromised dependencies, malicious future tools/MCP servers, local users reading the spool, and denial-of-service actors.

## Threat register

| Threat | Attack path | Impact | Existing mitigation | Test/evidence | Residual risk |
|---|---|---|---|---|---|
| Prompt injection in telemetry | Metadata/tool/error text reaches server or replay planner | Unauthorized action if treated as authority | Telemetry is persisted as data; V4 uses trusted policy configuration, dry-run-only deterministic simulators, and no command/tool execution | Replay policy and adversarial regression tests | A future policy registry change requires review |
| Cross-tenant object access | Valid key queries another tenant's IDs | Data disclosure | Auth-derived tenant predicates and composite constraints | V2 isolation tests, live A/B test | DB credentials can bypass API predicates without RLS |
| Credential theft | Key in logs/spool/request | Account takeover | HMAC digest storage, one-time CLI display, redaction, HTTPS requirement for remote SDK endpoints | secret/log tests | Local spool is not encrypted |
| Resource exhaustion | Huge/chunked body, deep JSON, large batch, repeated calls | RAM/CPU/DB exhaustion | Streaming request cap, bounded schema data, batch cap, tenant rate limits, spool bounds | adversarial input tests | Rate limiter is process-local |
| Supply-chain compromise | Floating package/image versions | Code execution or data theft | upper-bounded dependencies, Bandit/pip-audit/Dependabot workflow | CI configuration and audit run | Full hash lock and image-signature verification are deployment responsibilities |
| Malicious OpenTelemetry attributes | OTel telemetry attempts tenant/scope/policy override or resource exhaustion | Cross-tenant access, unsafe action, or denial of service | authenticated tenant context, observational-only mapping, bounded attributes, redaction, fail-open processor, existing spool limits | V6 OTel mapping/privacy/limit tests | Python bridge is not a universal OTLP collector |
| Evidence payload tampering | Database-only writer edits canonical payload | False trace history | SHA-256 digest is chained with tenant/trace/sequence and HMAC-SHA256; runtime role cannot update/delete ledger rows | V3 tamper regression and live acceptance | A DB administrator with the integrity key can forge evidence |
| Ledger deletion | Database-only writer removes a record or chain head | Missing or reordered evidence | Event/record count, sequence, links, and chain-head checks | V3 deletion regression | Deleting all copies needs an external existence anchor |
| Integrity key loss | Key is absent or retired key is unavailable | Verification cannot complete | Fail-closed startup and explicit `UNVERIFIABLE_KEY_MISSING` result; keys stay outside the database | V3 key-version tests | Secret-manager retention/rotation is an operational responsibility |
| OTLP payload abuse | Malformed protobuf, gzip expansion, nested AnyValue, or oversized batch reaches the gateway | CPU/RAM/DB exhaustion or unsafe telemetry | Official protobuf parser, dual compressed/decompressed limits, bounded recursive conversion, batch/attribute/event/link limits, tenant-aware rate limit, and safe client errors | V7 protocol and adversarial gateway tests | Process-local rate limiter is not shared across replicas |
| Evaluation policy injection | Telemetry or a candidate run attempts to alter release criteria or submit executable evaluator logic | False release decision or code execution | V8 accepts only trusted operator policy with allow-listed metrics/operators, bounded JSON, exact pairing, and V3 integrity preconditions; no `eval`, `exec`, arbitrary SQL/Python, replay, deployment, or rollback | V8 policy validation, paired comparison, and live 20-case gate tests | Operator credentials and database administrators remain trusted deployment actors |
| Incomplete or tampered evaluation evidence | Invalid, missing, or cross-tenant traces are supplied as baseline/candidate cases | Unjustified PASS or data disclosure | Invalid/unverifiable traces are rejected and not scored; minimum sample/coverage policies, tenant predicates, structured reasons, and explicit `INSUFFICIENT_DATA` | V3 integrity suite, V8 tamper/coverage/tenant live tests | Statistical significance and external evidence anchoring are not implemented |

## V4 replay/MCP boundary

Recorded telemetry remains untrusted. V4 replay defaults to dry-run and requires structured schema validation and policy checks. Mutating, high-impact, unknown, or unavailable tools are blocked. The V4 simulator has no network, shell, subprocess, filesystem-write, database-write, Docker, cloud, payment, browser, MCP, or user-action capability. Production execution and MCP integration are out of scope; no V4 path invokes them. OTLP delivery does not close a trace merely because an export request ended.

## V5 analysis boundary

V5 analysis is derived, read-only output. It is integrity-gated, tenant-scoped, bounded, and deterministic-first. An optional FailureJudge receives only an allowlisted and redacted evidence packet, has no tools, and cannot invoke replay or change policy. Structured deterministic facts take precedence over conflicting AI hypotheses; invalid evidence references are rejected. Residual risks include model misdiagnosis, uncalibrated confidence, missing telemetry, taxonomy gaps, and external-provider data processing.

## V10 incident boundary

Incident data is a derived, tenant-scoped projection over verified deterministic
V5 findings. Fingerprints use versioned canonical SHA-256 of bounded structured
dimensions; attacker-controlled natural language is not an identity input.
Integrity-invalid traces cannot create incidents. Lifecycle changes are
append-only history events with safe actor metadata. Incident APIs are
read/manage scoped and return bounded projections; they cannot replay, notify,
remediate, or modify V0–V8 source records. Residual risks include incomplete
telemetry, deterministic taxonomy gaps, process-local rate limits, and a
database administrator who can access both source and derived tables.

## V12 dashboard boundary

The browser is an untrusted operator surface. API-key login is exchanged once
for a high-entropy opaque session cookie; only SHA-256 token hashes and a
session-bound CSRF hash are stored. The session revalidates the originating
API key and current scopes on every request, with bounded lifetime, idle timeout,
active-session cardinality, logout revocation, and process-local login rate
limiting. `dashboard:access` does not grant any data or mutation scope.

Telemetry, incident titles, tool/model names, error metadata, and AI advisory
text are attacker-controlled. Jinja autoescaping, plain-text rendering,
self-only CSP, no-store responses, and no inline/eval JavaScript prevent them
from becoming HTML or script. Every resource query includes the authenticated
tenant predicate; incident actions reuse V10 transitions, and analysis/replay
reuse V5/V4 gates. The console contains no shell, SQL, arbitrary HTTP, MCP,
deployment, or remediation capability.

Residual risks are API-key-derived human identity without SSO/RBAC, process-
local rate limiting in multi-instance deployments, external receiver and
database-admin trust boundaries, and conservative session invalidation after
disaster recovery remaining an operator procedure.

## V13 OIDC and RBAC boundary

The external IdP authenticates humans but does not assign AgentGuard roles or
tenants. AgentGuard accepts only one trusted operator-configured issuer and
uses issuer/subject as identity. State, nonce, PKCE, explicit algorithm,
signature, issuer, audience, and time checks defend callback substitution,
token replay, mix-up, and forged-token attacks. Discovery and JWKS remain an
outbound dependency with bounded timeout/size/cache and same-host endpoints.

Organizations map one-to-one to tenants; membership is the only human
authorization path. Every request reloads membership and fixed-role
permissions, multi-org selection is server validated, and admin/member/key
mutations require CSRF plus tenant-scoped permission. IdP names/emails and all
telemetry are untrusted presentation data escaped under the V12 CSP.

Residual risks are IdP compromise, process-local rate limiting across replicas,
operator bootstrap mistakes, one configured issuer, absence of SCIM/SAML/LDAP,
and database administrators bypassing application predicates without RLS.


## V14 distributed coordination

Replica-local memory is not authority for rate limits, notification
ownership, circuit state, OIDC transactions, sessions, or RBAC. PostgreSQL
row locks and atomic upserts provide the shared boundary. Residual risk is
at-least-once external webhook delivery after a worker crash.
## V15 external witness

V15 adds an independent Ed25519-signed checkpoint witness. The trusted public
key registry is operator configuration; telemetry, browser input, AI output,
and witness responses cannot change it. See
[external-integrity-anchoring.md](external-integrity-anchoring.md) for exact
coverage, `REMOTE_AHEAD` rollback detection, freshness, and residual risks.
