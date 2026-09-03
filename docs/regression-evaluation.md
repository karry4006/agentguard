# V8 Offline Regression Evaluation

AgentGuard V8 compares an immutable, integrity-verified baseline run with a candidate run. It is an offline release-gate evaluator: it never deploys, rolls back, executes tools, replays traces, or invokes an AI judge.

## Flow

1. An operator creates a versioned suite with a bounded declarative policy.
2. The operator records a baseline and candidate run as paired `case_id`/`trace_id` references.
3. Each referenced trace is verified by the V3 evidence-integrity chain before it is scored. Invalid or unverifiable cases are rejected and are never silently treated as success.
4. A comparison computes deterministic metrics and structured case-level diffs, then returns only `PASS`, `FAIL`, or `INSUFFICIENT_DATA`.

Pairing is by exact `case_id`. `minimum_cases` and `minimum_pair_coverage` protect against small or incomplete samples. `missing_case_policy` can be `FAIL`, `IGNORE`, or `INSUFFICIENT_DATA`; the default is the safest latter value.

## Metrics and policies

The evaluator derives success and V5 failure-category rates (timeout, authentication, authorization, rate limit, tool execution, loop/repetition, guardrail, and handoff), tool/model/span counts, p50/p95 duration, available token statistics, and existing V4 replay mismatch evidence. Missing token data remains `null`, never zero. Rules use only bounded JSON with an allow-listed metric, one of `>=`, `>`, `<=`, `<`, `==`, and either an absolute value or a baseline-relative offset. There is no `eval`, `exec`, arbitrary SQL, uploaded evaluator code, telemetry-policy override, or AI-generated gate decision.

## API and authorization

The endpoints are:

- `POST/GET /v1/evaluation-suites`
- `POST/GET /v1/evaluation-runs`
- `POST/GET /v1/evaluation-comparisons`

They use `evaluations:manage` for suite creation, `evaluations:run` for creating runs/comparisons, and `evaluations:read` for reads. Scopes are explicit; existing keys do not receive evaluation permissions automatically. All objects and traces are tenant-scoped and request bodies are bounded by the existing middleware and evaluation case/rule limits. Idempotency keys make repeated run and comparison submissions safe.

## CLI and CI

`agentguard-server eval compare --tenant SLUG --suite UUID --baseline-run UUID --candidate-run UUID` prints a bounded summary. Exit codes are `0` for `PASS`, `2` for `FAIL`, `3` for `INSUFFICIENT_DATA`, and `1` for a system or input error.

V8 is advisory evidence for a release decision. It does not perform deployment or rollback. The evaluation tables preserve the suite policy, run metadata, evaluator versions, metrics, reasons, and case diffs so a result can be audited and reproduced against the referenced evidence.

## Limitations

The evaluator is deterministic and currently uses the existing normalized trace model. It does not claim statistical significance, causal attribution, universal OTLP coverage, or protection against a compromised database administrator. Token metrics are unavailable when source spans do not carry token attributes. Distributed rate limiting and a separate migration-only schema owner remain deployment hardening concerns.
