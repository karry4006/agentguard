# AgentGuard V5 Failure Analysis

## Contract

V5 diagnoses failures; it does not remediate them. Diagnosis is not authorization and a recommendation is not execution. The analysis interface has no shell, filesystem, PostgreSQL mutation, replay, production tool, cloud, email, payment, or MCP adapter.

## Deterministic-first flow

The analysis module first verifies the V3 integrity chain and projection. Invalid or unverifiable evidence returns `ANALYSIS_REFUSED_INTEGRITY`. It then reads bounded, tenant-scoped spans/events and applies structured detectors before any optional judge: explicit errors, timeout, HTTP 401/403/429, loops, tool budget, guardrail, handoff, and V4 replay mismatch. The V3/V4 source rows are never changed.

The taxonomy is versioned as `v1`: `MODEL_REASONING`, `TOOL_SELECTION`, `TOOL_EXECUTION`, `TOOL_RESULT_INTERPRETATION`, `AUTHENTICATION`, `AUTHORIZATION`, `RATE_LIMIT`, `TIMEOUT`, `INVALID_INPUT`, `INCOMPLETE_EXPLORATION`, `LOOP_OR_REPETITION`, `HANDOFF_FAILURE`, `GUARDRAIL_FAILURE`, `ENVIRONMENT_DRIFT`, `DATA_QUALITY`, `DEPENDENCY_FAILURE`, `PROJECTION_MISMATCH`, `EVIDENCE_INTEGRITY`, and `UNKNOWN`. Categories are enum values, not free-form model labels.

Findings store `root_cause_span_id` and `symptom_span_id` separately. Evidence references are actual span/event/replay IDs supplied to the analysis; hallucinated references are rejected. Deterministic facts remain authoritative if an AI hypothesis conflicts with them.

## Optional AI judge

`ai_assisted` is optional and requires a provider-neutral `FailureJudge` adapter. The mandatory path does not require an API key or paid provider. The judge receives an allowlisted, redacted, bounded evidence packet as untrusted data and has no tools. Its structured output must use taxonomy `v1`, confidence in `[0,1]`, and valid evidence references. Provider timeout, HTTP failure, rate limit, invalid JSON/schema, or hallucinated IDs changes `ai_status` to unavailable/failed while retaining deterministic findings. `model_confidence` is not a calibrated probability.

No hidden chain-of-thought is requested or stored. Only short rationale, structured findings, evidence IDs, provider/model metadata, usage metadata when available, and bounded latency are retained.

## API and operations

Use `POST /v1/traces/{trace_id}/analysis` with `{"mode":"deterministic"}` and an `Idempotency-Key`. Use `GET /v1/analyses/{analysis_id}` for tenant-scoped results. The CLI equivalent is `python -m agentguard_server.cli analysis run --tenant <slug> --trace-id <trace-id>`. There are no autonomous, repair, execute, force, or skip-integrity modes.

Analysis limits include maximum spans/events/evidence bytes, model calls, output bytes, duration, concurrent runs, and a stricter tenant-aware rate limit. The external provider trust boundary is disabled unless an explicit provider adapter is configured; any future adapter must use HTTPS, an allowlisted endpoint, bounded timeout, secret-safe minimization, and no arbitrary URL/proxy from telemetry.

## Evaluation and residual risks

The local synthetic evaluation covers timeout, 401, 403, 429, tool error, wrong selection, loop, guardrail, handoff, replay mismatch, incomplete evidence, and prompt-injection evidence. Metrics include category accuracy, root/symptom localization, citation validity, and invalid-reference rate. Remaining risks include model misdiagnosis, uncalibrated confidence, missing telemetry, taxonomy gaps, provider data processing, and existing process-local rate limiting, unencrypted local spool, lack of PostgreSQL RLS, ingress-managed TLS, and no external integrity anchor.
