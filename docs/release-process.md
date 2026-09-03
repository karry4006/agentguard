# AgentGuard release process

1. Review the version in `VERSION` and the two pinned requirement files.
2. Run `./scripts/ci.ps1` in a clean Python environment.
3. Run the Docker Compose config/build and live acceptance with PostgreSQL.
4. Run `scripts/backup.ps1` and `scripts/restore-check.ps1` against an
   isolated temporary restore database.
5. Run `scripts/sbom.ps1` and `scripts/release-check.ps1` with Docker Scout.
   The release check records raw Critical/High findings, fixable findings,
   triaged unfixed findings, untriaged findings, and CISA KEV findings. Raw
   upstream count alone does not fail the gate; fixable Critical/High,
   untriaged, and CISA KEV findings do. `AFFECTED_NO_FIX` findings require an
   explicit operator-approved risk-exception reference and are never silently
   accepted. If Docker Scout is unavailable, record `UNAVAILABLE` and do not
   claim a vulnerability scan or release PASS.
6. Run `scripts/release-manifest.ps1` and review the checksums and test summary.
7. Inspect logs for secret-shaped content and review the Git diff before any
   release packaging.

The Scout disposition file is `security/v9-scout-triage.json`. Each remaining
Critical/High finding must have an evidence-backed `FIXED`, `NOT_AFFECTED`, or
`AFFECTED_NO_FIX` disposition. VEX is used only for objective
`NOT_AFFECTED` findings; it is not a suppression mechanism.

The repository has no publish or credential workflow. A local Git repository is
used for provenance and review; an operator must configure their own Git
identity before making a commit. No identity or commit is invented by the
release scripts.

Rollback means deploying the previously approved image and restoring only into
an explicitly isolated database when recovery is required. Never use
`docker compose down -v` as a release or recovery operation.

## V9.2 promotion gate

The promoted server image is built with `python:3.13-slim-trixie` and runs
from the immutable `gcr.io/distroless/python3-debian13:nonroot` digest recorded
in `artifacts/release-manifest.json`. The final image has no shell or package
manager; use vector commands and a direct Python healthcheck. Run the clean
Python 3.13 server/live suite and the Python 3.12 SDK suite, both with zero
skips, before promotion. Confirm migration `0001` through `0006`, runtime
`current_user=agentguard_runtime`, least privilege, backup/restore, graceful
restart, secret-file injection, and V0-V8 behavior.

The promotion also requires the selected-image SBOM, Scout raw/fixable/KEV
results, Bandit, pip-audit, compile, secret scan, release-check, and the
secret-free manifest to pass. If any compatibility or security gate fails,
retain the existing Python 3.12 configuration as rollback; do not weaken
database privileges or delete the PostgreSQL volume.
