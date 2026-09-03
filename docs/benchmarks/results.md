# Phase 3 benchmark results

These are one local run, not performance guarantees or thresholds. Rerun the
commands in `benchmarks/README.md` when comparing machines.

- SDK event path: 500 samples, median plain 0.0004 ms, median instrumented
  0.3646 ms, p95 instrumented 1.5780 ms, reported relative overhead 1442.0922.
  This includes the SDK's real event normalization and local SQLite spool.
- Ingestion: 600 events across 100 traces, 342.30 events/second, batch latency
  median 171.8077 ms and p95 205.8919 ms.
- Query: 50 seeded traces; `list_traces` median 0.7648 ms, `get_trace` median
  0.4965 ms, and `make_span_tree` median 0.0028 ms.
- Quorum: 200 local evaluations; median 0.3895 ms and p95 0.7819 ms, state
  `QUORUM_MATCH`.

The full machine-readable record is
`artifacts/productization-phase3-benchmark.json`. CI runs benchmark smoke
commands only and does not enforce these machine-dependent values.
