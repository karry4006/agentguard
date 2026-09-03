# AgentGuard Security Gate Audit

Status: **PASS — latest closure is V13; historical audit sections are retained below**

## V9.2 Python 3.13 Compatibility & Distroless Promotion

Current closure status: **PASS**

- Selected runtime: `gcr.io/distroless/python3-debian13:nonroot` at
  `sha256:f3d5ddc6c64a019fe520e7f005f2880be21e6afc461b10a3c15ef2e4edc71e33`;
  Python 3.13.5, Debian 13, UID 65532, no shell/package manager.
- Builder: `python:3.13-slim-trixie`; clean locked install succeeded. The
  final image has no pip/compiler/build tools, read-only rootfs, dropped caps,
  and direct exec-form server/healthcheck commands.
- Runtime proof: `sys.executable=/usr/bin/python3.13`, expected `PYTHONPATH`,
  OpenSSL 3.5.7, and no `/bin/sh`, `/bin/bash`, or pip.
- Compatibility: Python 3.13 full server/live suite **85 passed, 0 skipped**;
  Python 3.12 clean SDK/core suite **22 passed, 0 skipped**.
- Docker/PostgreSQL: Compose build/start, PostgreSQL healthy, migrations
  `0001_initial` through `0006_regression_evaluation`, readiness, graceful
  stop/restart, and isolated backup/restore passed.
- Identity/least privilege: FastAPI reported `current_user=agentguard_runtime`;
  runtime is not superuser/CREATEDB/CREATEROLE/replication, has no AgentGuard
  privileged memberships, and has no database/schema CREATE or TEMP privilege.
- V0-V8 live behavior, tenant isolation, evidence integrity, replay, analysis,
  OpenTelemetry/OTLP, evaluation, spool recovery, and secret-file injection
  passed. V9.2-created temporary tenants/schemas/spools/dumps were cleaned;
  nine pre-existing ACL-protected pytest artifact directories from earlier
  acceptance runs remain outside the V9.2 test containers.
- Security: compile, Bandit, pip-audit, secret scan, SBOM, release manifest,
  and release-check passed. Selected-image Scout raw Critical/High **0/0**,
  fixable **0/0**, CISA KEV **0**; known application Critical/High **0**.

The following V9/V9.1 material is retained as historical pre-promotion
evidence. The former Bookworm CVEs are not present in the promoted image.

## V8 Offline Regression Evaluation

Status: **PASS**

- Scope: PASS; V8 is offline and advisory. It has no deployment, rollback, tool execution, automatic replay, or AI gate decision path.
- Migration/data model: PASS; `0006_regression_evaluation` adds versioned suites, baseline/candidate runs, case results, comparisons, and release-gate results without deleting the PostgreSQL volume or existing non-test data.
- Integrity/pairing: PASS; only V3-valid traces are scored, invalid/unverifiable cases are rejected, and exact `case_id` pairing plus minimum sample/coverage policy prevents incomplete samples from becoming a false PASS.
- Metrics/rules: PASS; deterministic V5 failure categories, success, tool/model/span counts, p50/p95 latency, available token data, and existing V4 mismatch evidence are evaluated. Missing tokens remain unavailable, not zero. Rules are bounded allow-listed declarative JSON; no `eval`, `exec`, arbitrary SQL/Python, uploaded code, or telemetry override.
- Authorization: PASS; `evaluations:manage`, `evaluations:run`, and `evaluations:read` are explicit scopes and existing keys were not auto-granted. Objects are tenant-scoped and run/comparison idempotency is tenant-scoped.
- Live acceptance: PASS; a 20-case Compose PostgreSQL corpus produced `PASS`, a 4/20 timeout regression produced `FAIL` with structured success/timeout reasons, tampered evidence was rejected, cross-tenant lookup returned `404`, and credential-shaped environment metadata was redacted.
- CLI: PASS; `eval compare` returns `0=PASS`, `2=FAIL`, `3=INSUFFICIENT_DATA`, or `1` for system/input error, with no deployment or rollback behavior.
- Runtime DB: PASS; FastAPI uses `agentguard_runtime`, migration uses `agentguard_migration`, runtime flags are false, privileged memberships are zero, and evaluation tables have required `SELECT/INSERT/UPDATE` grants with `DELETE` revoked.
- Regression/static acceptance: PASS; full pytest **78 passed, 0 skipped**, security subset **10 passed, 0 skipped**, Docker/PostgreSQL health, compile, Bandit, pip-audit, and secret/log checks completed.

### V8 residual risks

- Thresholds are deterministic policy checks, not statistical significance tests; operators remain responsible for corpus quality and approval.
- Token metrics are unavailable when source spans do not carry token attributes; V8 does not infer usage.
- A database administrator controlling both PostgreSQL and the integrity key can forge evidence.
- Existing deployment residuals remain: process-local rate limiting, unencrypted local spool, optional PostgreSQL RLS, dependency lockfile/image-signature hardening, TLS termination, and external secret-manager injection.

The V0/V1/V2 Security Gate, V3 Evidence Integrity, V4 Safe Replay, V5 Failure Analysis, V6 OpenTelemetry, and V7 OTLP baselines remain closed and passing. V8 offline regression evaluation has passed its release-gate acceptance.

## Historical V9 Production Readiness & Operational Resilience

Status: **INCOMPLETE — blocked on upstream base-image CVEs**

- Version/provenance: PASS; `VERSION` is `0.1.0-alpha.1`, `/version` and the
  `agentguard-server version` CLI command expose secret-free metadata.
- Configuration/health: PASS in unit/live checks; direct and `_FILE` conflicts,
  malformed secret files, placeholders, invalid URLs, production SQLite, and
  unbounded settings fail closed. `/health/live`, `/health/ready`, and legacy
  `/health` are covered; readiness checks PostgreSQL and migration head
  `0006_regression_evaluation`.
- Build/dependencies: PASS; Docker uses the pinned lock file and digest-pinned
  Python base, removes pip from the runtime image, and containers run non-root
  with read-only rootfs, dropped capabilities, and no-new-privileges.
- Controlled development secret rotation: PASS; new pepper and integrity key
  are stored in separate protected host files and injected through read-only
  Compose secret mounts. The integrity key id is `v9-dev-1`; no secret value is
  stored in the repository, image, database, manifest, SBOM, logs, or telemetry.
- The new development API credential was issued through the existing CLI flow,
  verified live, and stored only in a protected external operator file. The
  previously undisclosed test credential was revoked.
- New baseline: PASS; a fresh trace has two integrity records and CLI/API
  verification returned `valid` after restart. Existing pre-baseline `event_log`
  rows remain intact and are not claimed as V3-verified.
- Regression: PASS in the final complete run: **85 passed, 0 skipped**,
  including PostgreSQL integration and V3–V8 live acceptance.
- Compile/Bandit/pip-audit/secret scan: PASS; pip-audit found no known
  vulnerabilities in the audited environment and the secret scan found zero
  unexpected files (three explicit synthetic test fixtures are allowlisted).
- Backup/restore: PASS; custom dump restored into and removed from a temporary
  isolated schema without deleting the PostgreSQL volume or existing data.
- Restart: PASS; FastAPI restarted gracefully, PostgreSQL stayed healthy, and
  readiness returned after restart.
- Docker Scout: **FAIL / residual blocker**; final image scan reports 2
  Critical and 5 High CVEs in the Debian Perl/OpenSSL base packages, each with
  `Fixed version: not fixed` in the current Scout advisory data. Official
  Python Bookworm, Trixie, and Alpine candidates were checked; they did not
  provide a zero Critical/High result.
- Final live closure: BLOCKED only on the upstream base-image findings. No
  historical evidence was rewritten and no runtime privilege was increased.

V9.1 minimal-runtime remediation experiment: **SUPERSEDED BY V9.2**.
Official Distroless Python 3.13 and public Chainguard Python 3.14 proof
runtimes each scanned at 0 Critical/High and passed nonroot/no-shell
application sanity, but neither can replace the declared Python 3.12 baseline
without a separate compatibility decision. The exact experiment, digests,
SBOM results, and decision are recorded in
`docs/v9.1-runtime-remediation.md`.

### V9 Docker Scout CVE exploitability triage

The final scan targeted `local://agentguard-agentguard-server:latest` using
`docker scout cves --only-severity critical,high` plus the Scout CISA KEV
filter. Raw upstream findings are reported, but raw count alone is not a
release defect. Scout reported **7 raw findings (2 Critical, 5 High)**,
**0 fixable Critical/High**, and **0 CISA KEV findings**. Every raw finding is
explicitly triaged below; no VEX exception is asserted.

| CVE | Severity | Package / installed | Fixed | Layer / location | EPSS | KEV | Disposition |
|---|---|---|---|---|---:|---|---|
| CVE-2026-13221 | Critical | perl / 5.36.0-7+deb12u3 | not fixed | base / perl-base dpkg metadata, `/usr/bin/perl` | 0.004320 | no | AFFECTED_NO_FIX |
| CVE-2026-12087 | Critical | perl / 5.36.0-7+deb12u3 | not fixed | base / perl-base dpkg metadata, `/usr/bin/perl` | 0.003740 | no | AFFECTED_NO_FIX |
| CVE-2026-48959 | High | perl / 5.36.0-7+deb12u3 | not fixed | base / perl-base dpkg metadata, `/usr/bin/perl` | 0.003730 | no | AFFECTED_NO_FIX |
| CVE-2026-48962 | High | perl / 5.36.0-7+deb12u3 | not fixed | base / perl-base dpkg metadata, `/usr/bin/perl` | 0.002920 | no | AFFECTED_NO_FIX |
| CVE-2026-54874 | High | openssl / 3.0.20-1~deb12u2 | not fixed | base / `/etc/ssl/openssl.cnf`, OpenSSL dpkg metadata | 0.005160 | no | AFFECTED_NO_FIX |
| CVE-2026-63072 | High | openssl / 3.0.20-1~deb12u2 | not fixed | base / `/etc/ssl/openssl.cnf`, OpenSSL dpkg metadata | 0.006120 | no | AFFECTED_NO_FIX |
| CVE-2026-63076 | High | openssl / 3.0.20-1~deb12u2 | not fixed | base / `/etc/ssl/openssl.cnf`, OpenSSL dpkg metadata | 0.013300 | no | AFFECTED_NO_FIX |

Perl removal was tested with `apt-get -s purge perl-base`; Debian marks it as
essential, so it was not removed. `/usr/bin/perl` is present, but AgentGuard
does not invoke Perl or expose a Perl protocol. This reduces reachability but
does not establish objective `NOT_AFFECTED` evidence while no fix exists.
OpenSSL was not removed: Python `ssl` imports and loads OpenSSL 3.0.20. The
default server listener is HTTP and has no server-side TLS listener, but
configurable HTTPS-capable functionality makes a blanket `NOT_AFFECTED`
claim unjustified.

The committed policy is `security/v9-scout-triage.json`; the release script
cross-checks every current Scout CVE against it and emits
`RAW_FINDINGS`, `FIXABLE_FINDINGS`, `UNFIXED_TRIAGED_FINDINGS`,
`UNTRIAGED_FINDINGS`, and `CISA_KEV_FINDINGS`. Fixable Critical/High,
untriaged, and KEV findings fail the gate. `AFFECTED_NO_FIX` remains blocked
unless an operator supplies an approved risk-exception reference; no such
exception is present for this acceptance.

### V9 Secret Provenance / Recovery Investigation

- Workspace search: `AGENTGUARD_KEY_PEPPER`, `AGENTGUARD_INTEGRITY_KEY`, and
  their `_FILE` references exist in source, Compose, examples, tests, and
  documentation. No non-example secret file or protected secret directory was
  found in the AgentGuard workspace.
- `.env`: present for local development, but it contains no pepper or integrity
  key reference. `.env.example` contains placeholders and empty `_FILE`
  settings only.
- Current process: neither secret nor either `_FILE` path is present.
- AgentGuard containers: the server config contains the mapped variable names
  but their current values are empty; the migration and PostgreSQL containers
  do not contain application signing/authentication keys. The server has zero
  mounts, so no mounted secret file source is present.
- Test fixtures: test/live modules use process/test configuration and temporary
  data; they are not a persistent recovery source for the deployment keys.
- PostgreSQL historical metadata: `integrity_records` count is zero, distinct
  historical `key_id` is none, and distinct canonicalization version is none.
  Therefore historical key compatibility cannot be tested against this current
  database state. `event_log` has 11 rows, but no corresponding integrity
  records proving a recoverable V3 key.
- Classification: **SECRET_NOT_FOUND_BUT_PROVENANCE_UNKNOWN**. The evidence
  does not prove whether the former keys were ephemeral development values or
  were stored in an operator-controlled source outside the authorized scope.
- No replacement keys were generated and no historical evidence was modified.

### V9 residual risks / closure conditions

- Keep protected recovery copies of the new development secrets outside the
  repository and rotate/reissue development API credentials when pepper
  provenance is lost. The one-time key output was not exposed in chat.
- Replace the pinned base image when upstream fixes are available, then rerun
  Docker Scout and the complete V9 gate before marking closure PASS.
- The lock strategy is pin-based and does not include per-line hashes.
- TLS termination, encrypted/off-host backups, process-local rate limiting, and
  multi-region failover remain deployment responsibilities.

## Evidence

- Docker Engine: PASS (`29.7.2`)
- Docker Compose: PASS (`v5.4.0`)
- Compose build/start: PASS
- Current migration head: PASS (`0006_regression_evaluation`); the complete chain is `0001_initial` → `0002_trust_boundary` → `0003_evidence_integrity` → `0004_safe_replay` → `0005_failure_analysis` → `0006_regression_evaluation`
- PostgreSQL container: PASS (`healthy`)
- PostgreSQL migration: PASS (`0001_initial` → `0002_trust_boundary` → `0003_evidence_integrity` → `0004_safe_replay`)
- Full regression suite: **85 passed, 0 skipped** (V9 final)
- PostgreSQL integration: PASS against the live Compose database; the fixture creates a unique temporary schema and drops it afterward
- PostgreSQL least privilege: PASS; FastAPI uses `agentguard_runtime`, while the one-shot migration service uses `agentguard_migration`
- FastAPI container database session: PASS (`current_user=agentguard_runtime`)
- Runtime negative privilege tests: PASS (`CREATE DATABASE`, `CREATE ROLE`, `ALTER ROLE`, `DROP TABLE`, `CREATE TABLE`, and `SET ROLE agentguard_breakglass` all denied)
- Live tenant isolation: PASS (cross-tenant query returned `404`)
- Live authorization: PASS (wrong scope `403`)
- Live expiration: PASS (`401`)
- Live revocation: PASS (`401`)
- Live request limit: PASS (`413`)
- Live content boundary: PASS (instruction content stored as `[CONTENT_CAPTURE_DISABLED]`)
- Live log check: PASS (generated API keys were absent from server logs)
- Bandit: PASS, no findings
- pip-audit: PASS, no known vulnerabilities in the audited environment
- Python compile check: PASS
- Compose/workflow YAML parse: PASS
- Repository secret-pattern scan: PASS for real credentials; one match is an intentional test fixture (`tests/test_sdk.py`)
- Git history secret scan: NOT AVAILABLE; this workspace has no `.git` history

## V4 Safe Replay

Status: **PASS**

- Policy registry/simulator: PASS locally; only trusted application policy can classify tools, and the fixture is deterministic and local.
- Integrity precondition: PASS locally; invalid and unverifiable traces are refused with `REPLAY_REFUSED_INTEGRITY`.
- Schema/limits: PASS locally; dry-run-only request validation, bounded JSON, step/input/time/concurrency/rate limits.
- Persistence: PASS locally; replay sessions and steps are separate tables, source evidence is never mutated, and idempotency is tenant-scoped.
- Authorization: PASS locally; replay requires both `traces:read` and `replay:run`.
- API/CLI: PASS locally; only `mode=dry_run` is exposed and no live/force/unsafe/skip-integrity flag exists.
- Adversarial local regression: PASS; recorded classifications/prompt text cannot alter trusted policy, projection mismatch is refused, and content-disabled input is unavailable rather than invented.
- Migration/live database: PASS; Docker applied `0004_safe_replay`, PostgreSQL was healthy, and the runtime grants/owners were inspected.
- Live authenticated replay: PASS; valid deterministic simulation matched, blocked mutating tool, tamper/projection refusal, missing-key unverifiable refusal, tenant isolation, idempotency, and source evidence immutability all passed.
- Live cleanup: PASS; temporary V3/V4 tenant counts and temporary test schema count were zero after teardown. PostgreSQL volume and pre-existing data were preserved.

## Controls implemented

- Telemetry is treated as untrusted data. Content-bearing fields are sanitized server-side when capture is disabled.
- Nested JSON has depth, field-count, list-size, string-size, and serialized-size limits.
- Request size is enforced while receiving the body, including chunked requests.
- Authentication uses HMAC digests; plaintext API keys are not stored or logged.
- Scope checks, tenant predicates, expiry, revocation, and safe error responses are enforced.
- Span-tree construction is iterative to avoid recursive input exhaustion.
- Per-tenant ingest/read rate limits and bounded spool behavior are enabled.
- Remote SDK endpoints require HTTPS unless an explicit insecure-local override is used; Compose ports bind to loopback.
- Server container runs non-root with a read-only root filesystem, dropped capabilities, `no-new-privileges`, bounded memory, and a `noexec` temporary filesystem.
- Docker base images are digest-pinned. Dependabot and a local security workflow were added.
- API key rotation/auth failure retains durable spool data and enters cooldown.
- Bootstrap `agentguard` is `SUPERUSER` but `NOLOGIN`; it is not present in the runtime or migration connection URLs.
- `agentguard_runtime` has no privileged role memberships or `SET ROLE` path, no database `CREATE`/`TEMP`, schema `USAGE` only, application table DML, and required sequence privileges.
- `agentguard_migration` is non-superuser, has database `CONNECT`/`CREATE` but no `TEMP`, schema `USAGE`/`CREATE`, and owns migration objects needed by Alembic.
- `agentguard_breakglass` is `SUPERUSER NOLOGIN`, has no runtime membership, and has no plaintext password.

## Open findings and residual risks

### Medium

- The in-process rate limiter does not coordinate across multiple workers or replicas; production should use a shared limiter at the gateway or datastore layer.
- The local SQLite spool is permission-hardened but not encrypted; protect the host filesystem or use an encrypted storage layer.
- PostgreSQL row-level security is not enabled; API-level tenant predicates remain the enforced boundary, so direct database credentials must remain restricted.
- Python dependency ranges are bounded but not fully lockfile-pinned; CI auditing and Dependabot reduce, but do not eliminate, dependency drift.

### Low / deployment responsibilities

- TLS termination is not implemented by the local Uvicorn process; production must put the API behind an HTTPS reverse proxy or ingress.
- `.env` is suitable only for local development. Production secrets must come from Docker Secrets, an external secret manager, or equivalent protected injection.
- Git-history scanning must be run once a real Git repository/history is available.
- FastAPI/Starlette deprecation warnings remain non-security cleanup items.

The live test `AGENTGUARD_TEST_DATABASE_URL` was supplied from the separate migration URL in process memory, with the Docker hostname translated to `127.0.0.1`; no credential value was committed or printed. A normal local Compose run must provide `DATABASE_URL`, `AGENTGUARD_MIGRATION_DATABASE_URL`, and the corresponding role passwords through `.env` or an external secret mechanism.

## V3 Evidence Integrity

Status: **PASS**

- Canonicalization: PASS locally (`jcs-lite-v1`), with sorted object keys, NFC strings, UTC timestamp normalization, finite-number enforcement, and deterministic UTF-8 JSON.
- Evidence digest: PASS locally (SHA-256 over sanitized canonical evidence).
- Chain: PASS locally (HMAC-SHA256, tenant/trace/sequence/event/key/version bound, constant-time verification).
- Ledger: migration `0003_evidence_integrity` adds `integrity_records`, `integrity_chain_heads`, and canonical sanitized `event_log` payload/digest columns.
- Concurrency design: per-trace PostgreSQL advisory lock plus `SELECT ... FOR UPDATE`; sequence allocation does not use `MAX(sequence)+1`.
- Verification: detects payload/MAC/previous-link/sequence/missing-record/chain-head/projection tampering and reports missing keys or unsupported versions as unverifiable.
- API/CLI: tenant-scoped `GET /v1/traces/{trace_id}/integrity` and `integrity verify`; responses exclude payloads, MACs, and key material.
- Key handling: active key and optional verification-only retired-key ring come from environment; no key is stored in PostgreSQL, SQLite, logs, or telemetry; startup rejects missing/short active keys.
- Runtime grants: V3 migration revokes runtime `UPDATE`/`DELETE` on `event_log` and `integrity_records`, grants only `SELECT`/`INSERT` there, and permits `SELECT`/`INSERT`/`UPDATE` on chain heads.
- Docker/PostgreSQL live acceptance: PASS; PostgreSQL healthy, migration `0003_evidence_integrity`, runtime `current_user=agentguard_runtime`, and all temporary acceptance data cleaned.
- Live acceptance: PASS; payload/MAC/link/sequence/projection tampering, duplicate retry, tenant isolation, concurrent append, missing-key behavior, spool recovery, and CLI verification all passed.
- Full regression: **39 passed, 0 skipped**.

V4 Safe Replay remains PASS; V5 work is tracked separately below and is not yet live-accepted.

### V3 residual risks

- An attacker controlling both PostgreSQL and the integrity key can forge a consistent ledger; deploy the key through a protected secret manager and consider an external anchor for stronger non-repudiation.
- Deleting every copy of a trace and its chain head cannot be detected without an external existence anchor.
- Key rotation requires retaining retired verification keys outside the database; missing keys make evidence unverifiable, never valid.
- Existing pre-V3 event rows have no canonical payload and are reported as not verifiable until re-recorded; they are not silently treated as valid.

## Gate decision

## V5 Failure Analysis

Status: **PASS**

- Docker Compose rebuild/start: PASS; PostgreSQL healthy and FastAPI `/health` healthy.
- Migration chain: PASS (`0001_initial` → `0002_trust_boundary` → `0003_evidence_integrity` → `0004_safe_replay` → `0005_failure_analysis`).
- FastAPI database identity: PASS (`current_user=agentguard_runtime`).
- Runtime least privilege: PASS; all role escalation flags are false, membership count is zero, and analysis tables allow only required DML (no DELETE).
- Versioned taxonomy `v1`, deterministic detectors, and symptom/root-cause separation: PASS.
- Bounded evidence packet and hallucinated-reference rejection: PASS; packets are allowlisted, redacted, size-limited, and tenant-scoped.
- Provider-neutral FailureJudge and deterministic fallback: PASS; AI-assisted failures leave deterministic findings available and cannot invoke tools or mutations.
- Integrity precondition: PASS; invalid/unverifiable traces are refused with `ANALYSIS_REFUSED_INTEGRITY`.
- Analysis API/CLI, `analysis:run` plus `traces:read` authorization, tenant isolation, and idempotency: PASS.
- Resource controls: PASS; span/event/evidence/output/model-call/time/concurrency limits are enforced fail-closed.
- V5 live acceptance: PASS; deterministic taxonomy, fake judge, provider failure fallback, tamper refusal, and cross-tenant lookup were exercised against Compose PostgreSQL.
- Security regression subset: **19 passed, 0 skipped**.
- Full regression: **57 passed, 0 skipped**.
- Compile check, Bandit, and pip-audit: PASS; pip-audit reported no known vulnerabilities for auditable dependencies (local editable packages were not found on PyPI).
- Temporary V5 tenants, analysis rows, schemas, pytest artifacts, and audit cache: cleaned; PostgreSQL volume and existing non-test data preserved.

### V5 residual risks

- The default deployment has no external AI provider; any future provider adapter requires a separate review for HTTPS, timeout enforcement, output validation, privacy minimization, and provider-specific egress controls.
- Confidence is a bounded model field, not a calibrated probability; calibration and benchmark datasets remain future hardening work.
- Existing platform residual risks remain documented above (shared rate limiting, encrypted spool, PostgreSQL RLS, dependency lockfile, TLS termination, and deployment secret management).

The V0/V1/V2 Security Gate, V3 Evidence Integrity, V4 Safe Replay, and V5 Failure Analysis acceptance remain PASS.

## V6 OpenTelemetry interoperability

Status: **PASS**

- Official OpenTelemetry Python SDK bridge: PASS; `AgentGuardOpenTelemetrySpanProcessor` implements the public `SpanProcessor` interface.
- Existing OpenAI native adapter regression: PASS; native `AgentGuardTracingProcessor` remains unchanged as a supported adapter.
- Mapping: PASS; workflow/agent, model/LLM, tool, retrieval/custom, MCP-shaped/tool, and unknown operations use the existing span taxonomy.
- Provider handling: PASS; OpenAI, Anthropic, generic, and future provider names are observational data only.
- Identity/lifecycle: PASS; upstream trace/span/parent IDs are preserved, root lifecycle events are deterministic, duplicate ends are idempotent, and incomplete traces are not completed artificially.
- Mapping metadata: PASS (`otel_semconv_version=otel-genai-evolving`, `agentguard_mapping_version=otel-genai-v1`).
- Privacy and trust: PASS; content/credential fields are redacted before the existing durable spool, OTel tenant attributes cannot override authenticated tenant identity, and MCP is observability-only.
- Resource and failure controls: PASS; attribute count/key/value/serialized-size bounds and fail-open diagnostics are enforced.
- Durable delivery: PASS; the bridge reuses `HttpBatchExporter` and SQLite spool, with no OTel-specific storage path.
- Compatibility live test: PASS; synthetic OTel workflow was ingested through HTTP into PostgreSQL, queried, integrity-verified, and analyzed by V5 as `TIMEOUT`.
- Full regression: **65 passed, 0 skipped**.
- Security regression: **27 passed, 0 skipped**.
- Docker/PostgreSQL: PASS; Compose rebuilt, PostgreSQL healthy, migration service exited 0, FastAPI healthy, runtime remained least-privileged.
- Compile check, Bandit, pip-audit, secret/log scan: PASS.

### V6 residual risks

- GenAI semantic conventions are evolving; mapping metadata versions changes must be reviewed and historical interpretations must not be silently rewritten.
- This is a Python SDK bridge, not a universal language-neutral OTLP collector. Only the tested official Python SDK integration is claimed.
- Missing instrumentation and disabled content capture produce incomplete evidence and may limit replay/diagnosis detail.
- No external AI provider, MCP connection, or MCP execution is introduced by V6.

V0–V5 remain PASS.

## V7 OTLP/HTTP ingestion gateway

Status: **PASS**

- Protocol: PASS; the live acceptance used the official OpenTelemetry OTLP/HTTP protobuf exporter against `POST /otlp/v1/traces`.
- Authentication and tenant boundary: PASS; the existing `ingest:write` scope is required and tenant identity remains exclusively AuthContext-derived. Telemetry tenant spoof attributes are observational data.
- Protobuf and compression: PASS; official OpenTelemetry protobuf definitions are used, with identity/absent and gzip transport. Malformed protobuf/gzip returns safe client errors.
- Resource limits: PASS; compressed/decompressed body, ResourceSpans, ScopeSpans, span, attribute, event, link, key/value, metadata, and recursive AnyValue bounds are enforced.
- Shared pipeline: PASS; the gateway calls the V6 `normalize_otel_span` seam and converges into the existing EventLog/Span/Trace, redaction, integrity, replay, and analysis paths. No V7 migration or duplicate storage model was added.
- Privacy: PASS; synthetic bearer, OpenAI-shaped, and content-bearing attributes were absent from query responses and server secret-pattern log scan. `capture_content=false` remains the default.
- Compatibility: PASS; OTLP-origin telemetry was queried, integrity-verified, and classified by V5 deterministic TIMEOUT/AUTHENTICATION analysis. Existing native OpenAI and V6 Python bridge tests remain passing.
- Reliability: PASS; duplicate official-exporter retransmission did not duplicate spans or invalidate the V3 chain; concurrent retransmissions remained successful and valid.
- Docker/PostgreSQL: PASS; server image rebuilt, PostgreSQL healthy, migration container exit 0, migration head `0005_failure_analysis`, FastAPI current user `agentguard_runtime`, and runtime least privilege unchanged.
- Tests: **72 passed, 0 skipped**; security subset **11 passed, 0 skipped**.
- Static checks: compile, Bandit, and pip-audit PASS; pip-audit reported no known vulnerabilities for auditable dependencies.
- Cleanup: V7 temporary tenants were removed; count of `v7-*` tenants was zero. The PostgreSQL volume and pre-existing data were preserved.

### V7 residual risks

- OTLP/gRPC, logs, metrics, and profiles are not supported.
- Remote OTLP client durability before server acceptance depends partly on that client's exporter retry/queue configuration; the AgentGuard Python SDK SQLite spool is not claimed for generic remote clients.
- The rate limiter remains process-local and is not coordinated across workers or replicas.
- Protocol interoperability does not claim framework-specific Java, Go, or .NET semantics without separate tests.
- Production TLS termination and secret-manager injection remain deployment responsibilities.

V0–V7 remain PASS. V8 is documented above; V9 was not started.

## V10 Incident Detection & Management — current closure

Status: **PASS**

- Model/migration: PASS; `0007_incident_management` adds independent
  `incidents`, `incident_occurrences`, and `incident_events` tables without
  modifying migrations 0001–0006 or deleting the PostgreSQL volume.
- Evidence boundary: PASS; only V3-valid, V5 deterministic findings are
  projected. Source event, integrity, trace/span, replay, and evaluation rows
  are not mutated. V8 links are informational `associated_with` only.
- Fingerprint/grouping: PASS; `incident-fingerprint-v1` uses canonical SHA-256
  over bounded structured dimensions and excludes raw sensitive content.
- Idempotency/concurrency: PASS; unique occurrence keys and PostgreSQL
  conflict-safe insert/row locking were live-tested with 50 concurrent
  occurrences and one incident.
- Tenant/lifecycle: PASS; cross-tenant incident IDs return 404; acknowledge,
  resolve, reopen, and append-only history were live-tested.
- Severity/trend: PASS; deterministic `severity-v1`, bounded one-hour windows,
  and explicit no-automatic-CRITICAL policy are documented in
  [incidents.md](incidents.md).
- Runtime/security: PASS; server and migration use Distroless Debian 13,
  UID 65532, read-only/no-new-privileges/cap-drop; runtime identity is
  `agentguard_runtime`, with no privileged memberships and no DELETE on
  incident tables.
- Verification: PASS; Docker/PostgreSQL healthy, ready at 0007,
  `92 passed, 0 skipped`, Bandit PASS, pip-audit reported no known
  vulnerabilities, compile and secret scans PASS, and Docker Scout reported
  0 Critical / 0 High CVEs for the promoted image.
- Side effects: PASS; no replay, notification, remediation, or outbound action
  is implemented by V10. Temporary live tenants and test containers were
  cleaned; existing PostgreSQL volume/non-test data were preserved.

### V10 residual risks

- Incident correctness remains bounded by V5 deterministic taxonomy and source
  telemetry completeness; V10 does not claim business impact or causality.
- Rate limiting remains process-local, and database administrators remain a
  trusted boundary.
- Optional AI summaries and automated remediation are not part of V10. V11
  notification alerting is delivered as a separately gated layer.

## V11 Secure Notification & Alerting — final closure

Status: **PASS**

V11 migration `0008_notification_alerting`, Docker/PostgreSQL live acceptance,
notification delivery, authorization, tenant isolation, and durable delivery
checks passed. The protected migration DSN is stored outside the repository and
mounted only into the one-shot migration service; the FastAPI server uses
`agentguard_runtime` and never receives that secret.

- Security boundary: PASS; HTTPS-only by default, test-only private override,
  DNS/private-address rejection, no redirects, POST-only delivery, bounded
  timeouts, and no proxy configuration from telemetry.
- Payload/signing: PASS; fixed `webhook-v1` allowlist, payload digest, optional
  separate HMAC signing reference, and exclusion of prompts, model output,
  tools, credentials, API keys, pepper, and integrity keys.
- Authorization/tenant isolation: PASS; notification scopes and resources are
  tenant scoped, with cross-tenant access denied.
- Durable delivery: PASS; intent-before-send, stable idempotency, bounded
  retries, circuit state, and duplicate dispatch behavior were verified.
- Verification: PASS; `102 passed, 0 skipped`, migration head 0008, Docker
  health/readiness, isolated backup/restore, SBOM, Scout 0 Critical/0 High,
  compile, Bandit, pip-audit, and secret/log scans passed.
- Cleanup: PASS; temporary tenants, deliveries, receiver/signing test data,
  pytest artifacts, and backup dump were removed. Existing PostgreSQL volume
  and non-test data were preserved.

### V11 residual risks

- External webhook delivery remains at-least-once and depends on receiver
  availability; rate and circuit state are process-local.
- The Docker Scout policy still reports copyleft-package and missing-attestation
  warnings, but no Critical or High vulnerability was detected.

## V12 Secure Web Dashboard & Operator Console — final closure

Status: **PASS**

- Dashboard boundary: PASS; server-rendered Jinja templates, local static assets,
  strict CSP, no-store UI responses, autoescaping, bounded output, and no shell,
  arbitrary HTTP, deployment, or remediation surface.
- Session security: PASS; `dashboard:access` is explicit, API keys are accepted
  only at login, opaque session and CSRF hashes are stored, cookies are HttpOnly
  and SameSite=Strict, and revocation/expiry/idle timeout are revalidated per
  request. Existing API keys and non-dashboard scopes were not auto-granted.
- Tenant/action boundary: PASS; all reads and incident actions are tenant scoped,
  CSRF protected, scope checked, and routed through the existing incident,
  analysis, replay, and query services. No raw API key or secret is rendered.
- Database: PASS; migration `0009_dashboard_sessions` applied over 0008,
  server `current_user=agentguard_runtime`, runtime role has no privileged
  membership, database CREATE/TEMP/schema CREATE are false, and migration
  credentials remain isolated from FastAPI.
- Docker/live acceptance: PASS; PostgreSQL and server healthy, readiness head
  `0009_dashboard_sessions`, isolated backup/restore succeeded, and temporary
  signing/test data were removed without deleting the PostgreSQL volume or
  existing non-test data.
- Verification: PASS; full suite **108 passed, 0 skipped**; release static lane
  **91 passed, 1 intentional non-live skip** plus security subset **11 passed**;
  compile, Bandit, pip-audit, secret scan, SBOM, Docker Scout CVE policy, and
  release-check completed with 0 Critical / 0 High CVEs.

### V12 residual risks

- The login rate limiter remains process-local and should be coordinated by the
  deployment layer for multi-worker or multi-replica production operation.
- Docker Scout still reports copyleft-package and missing-supply-chain-attestation
  policy warnings; these are not vulnerability findings and do not create a
  known Critical or High security finding.
- Dashboard presentation remains intentionally bounded and does not provide
  arbitrary database, shell, deployment, notification-destination, or model
  control capabilities.

V0–V12 remained PASS at the V12 closure recorded above.

## V13 Human Identity, Organizations & RBAC — final closure

Status: **PASS**

- Regression: PASS; final PostgreSQL/Docker-enabled suite **134 passed,
  0 skipped**. V0-V12 machine API, SDK, OTLP, evidence, replay, analysis,
  evaluation, incident, notification, and V12 dashboard flows remain green.
- Python compatibility: PASS; the declared Python 3.12 SDK/spool lane completed
  **15 passed, 0 skipped** in an isolated official Python 3.12 container.
- Migration: PASS; the Alembic chain is `0001_initial` through
  `0011_distributed_coordination`. The migration container exited 0, readiness and
  isolated backup/restore verified the same head.
- Human identity/RBAC: PASS; immutable issuer/subject identity, explicit
  one-shot first-ADMIN bootstrap, one-to-one Organization/Tenant mapping,
  fixed VIEWER/ENGINEER/ADMIN roles, immediate role/member/user revalidation,
  last-admin locking, explicit multi-org selection, and append-only audit
  events are implemented. Email and display name have zero authorization
  authority.
- OIDC: PASS; Authorization Code, PKCE S256, browser-bound one-use state,
  nonce, issuer, audience, exp/nbf/iat, explicit RS256 signature, bounded
  trusted-issuer discovery/token/JWKS I/O, cache bounds, and JWKS rotation were
  tested. Unknown users and forged/malformed/mix-up tokens fail closed.
  Provider tokens are not persisted or rendered.
- Dependency decision: PASS; Authlib 1.7.2 supplies standards-level OIDC
  validation, with joserfc 1.7.4 and cryptography 50.0.1 for explicit RS256/JWK
  handling. Authlib is maintained and BSD-3-Clause; no custom JWT cryptography
  was implemented.
- Session/browser security: PASS; transient state and dashboard cookies are
  HttpOnly with bounded lifetime and correct SameSite/Secure policy. V12 CSRF,
  CSP, autoescaping, no-store, tenant predicates, and revocation remain valid.
  Login limits are separated by client and flow with a bounded global backstop.
- Principal separation: PASS; machine API keys retain V0-V12 behavior and
  never become HumanUser records. Machine dashboard sessions cannot call human
  ADMIN key-management UI. New machine secrets are shown once; existing
  secrets are never shown.
- Live authorization: PASS; the isolated test issuer exercised real RS256
  OIDC for VIEWER, ENGINEER, and ADMIN against Docker. Last-admin rejection,
  second-admin demotion, immediate engineer demotion, immediate membership
  revocation, shared trace IDs, multi-org switching, and tenant isolation
  passed.
- PostgreSQL least privilege: PASS; FastAPI used `agentguard_runtime`, which
  remains LOGIN/NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOREPLICATION, with no
  privileged memberships or database/schema CREATE/TEMP. V13 tables grant
  only required operations and no runtime DELETE. `agentguard_breakglass`
  remains SUPERUSER/NOLOGIN. Migration DSN is mounted only into migration.
- Security review: five findings were found and fixed: one High login-CSRF
  session-swapping path, three Medium findings (machine-principal admin UI,
  global login-bucket denial of service, mixed-case production Secure cookie),
  and one Low callback-consumption race. Security regression suite completed
  **41 passed, 0 skipped**. Known unresolved Critical: **0**; High: **0**.
- Static/dependency: compile PASS, Bandit PASS, pip-audit found no known
  vulnerabilities (two local unpublished AgentGuard distributions are
  non-PyPI), and repository/container-log secret scans PASS.
- Container/release: Distroless nonroot/read-only/cap-drop/no-new-privileges is
  unchanged. Docker Scout indexed 114 packages and reported **0 Critical,
  0 High, 0 fixable Critical/High, 0 CISA KEV, 0 untriaged**. CycloneDX SBOM,
  secret-free manifest, and release-check passed. License-policy and missing-
  attestation warnings remain policy warnings, not vulnerability findings.
- Cleanup: PASS; V13-prefixed tenants/HumanUsers and restore schemas are zero.
  Temporary issuer, spool, pytest, backup, and webhook-signing material were
  removed during final cleanup; PostgreSQL volume and non-test data remain.

### V13 residual risks

- IdP compromise/account takeover and IdP availability remain external human-
  identity trust risks; machine API ingestion remains independent.
- Rate-limit state is process-local; multi-replica deployments need a shared
  edge or coordinated limiter that stays independent from ingestion limits.
- One issuer only; no SCIM, SAML, LDAP, public signup, invitation email, domain
  enrollment, custom roles, or policy language.
- PostgreSQL RLS is not enabled. TLS termination, secret-manager injection,
  IdP lifecycle governance, and supply-chain attestations are deployment
  responsibilities.
- FastAPI/Starlette lifecycle and TestClient deprecation warnings are known
  maintenance items, not known Critical or High findings.

Recommended V14 candidate only (not started): coordinated identity/session
operations should be separately specified and security-reviewed.


## V14 distributed coordination closure

V14 adds PostgreSQL-backed shared rate limiting, delivery leases, and
destination circuit state. The detailed threat boundary and residual
at-least-once webhook risk are recorded in distributed-coordination.md.
## V15 external anchoring implementation note

The V15 implementation adds migration `0012_external_integrity_anchoring`,
transactional `checkpoint-v1` canonicalization, Ed25519 receipt verification,
trusted public-key configuration, PostgreSQL-coordinated leases, and explicit
continuity/freshness states. Focused V15 tests pass. Full live PostgreSQL
rollback/`REMOTE_AHEAD`, supply-chain, and image scans remain acceptance
activities for an environment with the required secrets and Linux container
runtime; this note does not claim those checks passed here.
