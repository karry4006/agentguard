# Dependency and license review

This is an engineering inventory, not a legal opinion or license
certification. Direct runtime dependencies are declared in the server and
Python SDK `pyproject.toml` files; transitive dependencies are pinned in the
lock files. Before a public release, generate a CycloneDX or SPDX inventory
from the exact build environment and have an owner review each package's
license expression and notice obligations.

The direct dependency families are FastAPI/Starlette/Pydantic, SQLAlchemy and
Alembic, PostgreSQL/psycopg, cryptography, Authlib/joserfc, boto3, Jinja2,
httpx, and OpenTelemetry. Optional development and integration families
include pytest, coverage/security tooling, OpenAI Agents, and OTLP exporters.

The prior V20 Scout review identified 118 packages requiring license review.
That residual remains open here: `MISSING_SUPPLY_CHAIN_ATTESTATIONS` is also
retained because no signed provenance or published attestation is claimed.
The Phase 3 RC Scout scan is intentionally not run on the new image without
exact-digest approval.

## Owner recommendations for Phase 4

1. Pin an SBOM format and publish it beside each approved digest.
2. Add signed build provenance and verification with an assigned key-rotation owner.
3. Review the 118-package license queue and record SPDX expressions and notices.
4. Add an approved private vulnerability-reporting channel before any public repository or release decision.
