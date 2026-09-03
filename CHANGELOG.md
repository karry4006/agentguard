# Changelog

## 1.0.0 — 2026-09-03

- AI-agent flight recording with bounded tracing, redaction, durable delivery,
  and authenticated multi-tenant trace ingestion.
- OpenTelemetry and OTLP ingestion for agent telemetry and evaluation data.
- Deterministic failure analysis, safe dry-run replay, and regression evaluation.
- Incident management, notifications, and a tenant-scoped operator dashboard.
- Human identity and RBAC with OIDC, tenant-scoped administration, and API-key
  authorization boundaries.
- Verifiable integrity evidence, external witness anchoring, archival and
  recovery controls, and multi-witness quorum continuity.
- Production and security hardening, including readiness checks, secret-file
  configuration, a pinned Distroless Python 3.13 image, and non-root execution.
- Public documentation, deterministic no-paid-API demos, SDK and benchmark
  runners, and the third-party license, notice, and source-compliance bundle.

## 1.0.0rc2 — Release candidate (historical)

- Corrected first-party package and SBOM identity to `1.0.0rc2`.
- Installed first-party package metadata during the production image build so clean
  clones produce the same release identity.
- Completed the exact third-party license artifact closure and release documentation.
- No runtime dependency, core behavior, schema, or migration changes.
- RC2 is a metadata-only successor; Docker Scout approval and release publication
  remain pending.

## 1.0.0rc1 — Release candidate (unreleased)

- Added six deterministic product demos for basic tracing, failure analysis,
  safe replay, regression evaluation, evidence integrity, and V20 quorum.
- Added reproducible SDK, ingestion, query, and quorum benchmark runners.
- Added public-surface positioning, configuration, SDK, OTel, operations,
  troubleshooting, and dependency-license review guidance.
- Added a distinct `agentguard:1.0.0-rc1` build target; no release, tag,
  PyPI publication, or container publication is implied.

Historical V0–V20 acceptance chronology remains in the repository's existing
acceptance artifacts and is not rewritten by productization work.
