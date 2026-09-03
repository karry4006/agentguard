# V18 live-skip reconciliation

The pre-reconciliation baseline was 158 passed and 18 skipped. With the
disposable PostgreSQL 0015 database, runtime API, OIDC issuer, webhook
receiver, and runtime CLI DSN provided, the complete suite finished with
176 passed, 0 skipped, 0 failed, and 0 errors.

All entries below were mandatory V0–V17 live acceptance tests and were
executed; no decorators, markers, xfail, mocks, `-k`, or `--ignore` filters
were used.

| # | Test | Original skip reason | Required fixture | Result |
|---:|---|---|---|---|
| 1 | `tests/test_server.py::test_postgresql_integration_trace_spans_jsonb_idempotency_and_query` | PostgreSQL test and setup URLs required | PostgreSQL 0015 + setup DSN | PASS |
| 2 | `tests/test_v10_live.py::test_live_v5_projection_lifecycle_and_tenant_isolation` | PostgreSQL live URL required | PostgreSQL + API | PASS |
| 3 | `tests/test_v10_live.py::test_live_postgres_incident_idempotency_and_concurrency` | PostgreSQL live URL required | PostgreSQL + API | PASS |
| 4 | `tests/test_v10_live.py::test_live_v10_bounded_1000_occurrence_corpus` | PostgreSQL live URL required | PostgreSQL + API | PASS |
| 5 | `tests/test_v11_live.py::test_live_https_webhook_delivery_signature_dedup_and_tenant_boundary` | PostgreSQL live URL required | PostgreSQL + API + receiver | PASS |
| 6 | `tests/test_v12_live.py::test_live_dashboard_session_csrf_xss_tenant_boundary_and_incident_action` | PostgreSQL live URL required | PostgreSQL + API | PASS |
| 7 | `tests/test_v13_live.py::test_v13_live_oidc_multi_org_rbac_runtime_privileges_and_cleanup` | PostgreSQL, OIDC issuer, and pepper required | PostgreSQL + API + HTTP OIDC issuer | PASS |
| 8 | `tests/test_v3_live.py::test_live_tamper_modes_duplicate_and_tenant_isolation` | PostgreSQL live URL required | PostgreSQL + API | PASS |
| 9 | `tests/test_v3_live.py::test_live_concurrent_append_and_missing_key` | PostgreSQL live URL required | PostgreSQL + API + integrity key | PASS |
| 10 | `tests/test_v3_live.py::test_live_spool_recovery` | PostgreSQL live URL required | PostgreSQL + API | PASS |
| 11 | `tests/test_v3_live.py::test_live_cli_integrity_verify` | PostgreSQL live URL required | PostgreSQL + runtime CLI DSN | PASS |
| 12 | `tests/test_v4_live.py::test_v4_live_simulation_tamper_block_and_idempotency` | PostgreSQL live URL required | PostgreSQL + API + integrity key | PASS |
| 13 | `tests/test_v4_live.py::test_v4_live_projection_missing_key_and_tenant_isolation` | PostgreSQL live URL required | PostgreSQL + API + integrity key | PASS |
| 14 | `tests/test_v5_live.py::test_v5_live_deterministic_taxonomy_tamper_and_tenant_isolation` | PostgreSQL live URL required | PostgreSQL + API + integrity key | PASS |
| 15 | `tests/test_v5_live.py::test_v5_live_fake_judge_and_provider_failure_fallback` | PostgreSQL live URL required | PostgreSQL + API + integrity key | PASS |
| 16 | `tests/test_v6_live.py::test_v6_otel_trace_is_queryable_integrity_checked_and_analyzed` | PostgreSQL live URL required | PostgreSQL + API + OTel exporter | PASS |
| 17 | `tests/test_v7_live.py::test_v7_official_otlp_exporter_live_pipeline` | PostgreSQL live URL required | PostgreSQL + API + OTLP exporter | PASS |
| 18 | `tests/test_v8_live.py::test_v8_live_release_gate_with_20_paired_cases_and_tamper` | PostgreSQL live URL required | PostgreSQL + API | PASS |

The canonical Python 3.13 run also completed with 176 passed, 0 skipped,
0 failed, and 0 errors. The defined Python 3.12 compatibility lane is the
SDK/core lane (`test_sdk.py`, `test_spool.py`, `test_opentelemetry.py`) and
completed with 22 passed, 0 skipped.
