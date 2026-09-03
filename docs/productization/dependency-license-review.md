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

## Phase 3 RC SBOM inventory

The exact approved RC image SBOM contains 122 CycloneDX 1.5 application
components. Fifteen unique direct runtime dependency names from the server and
SDK metadata match SBOM components. The remaining 107 components are
non-direct components; the SBOM does not cleanly separate Python transitive
packages from Debian base-image packages, so a pure transitive count is not
claimed.

License metadata was present for 97 components and absent for 25. Observed
SPDX identifiers are: `0BSD`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`,
`BSD-4-Clause`, `BSL-1.0`, `FSFAP`, `FSFUL`, `FSFULLR`, `GFDL-1.2-only`,
`GPL-1.0-only`, `GPL-1.0-or-later`, `GPL-2.0-only`, `GPL-2.0-or-later`,
`GPL-3.0-only`, `GPL-3.0-or-later`, `ISC`, `Kazlib`, `LGPL-2.0-only`,
`LGPL-2.0-or-later`, `LGPL-2.1-only`, `LGPL-2.1-or-later`, `LGPL-3.0-only`,
`LGPL-3.0-or-later`, `Latex2e`, `MIT`, `MIT-0`, `MPL-1.1`, `MPL-2.0`,
`MS-PL`, `PSF-2.0`, `Sleepycat`, `SunPro`, `Unicode-DFS-2016`, `X11`, and
`Zlib`.

The inventory classifies 50 components as permissive-only by observed SPDX
metadata, 47 as copyleft-related, and 25 as unknown/no-license metadata. The
copyleft-related set includes OS/runtime components plus `psycopg` and
`psycopg-binary`; this is a redistribution review queue, not a legal
conclusion. The no-metadata component names are `agentguard`,
`agentguard-server`, `boto3`, `botocore`, `cyrus-sasl-lib`, `gcc-14`,
`googleapis-common-protos`, `jinja2`, `keyutils-libs`, `krb5-libs`, `libcom_err`,
`libcrypt1`, `libselinux`, `libxcrypt`, `libzstd`, `media-types`, `protobuf`,
`python`, `python-dateutil`, `python3.13-venv`, `s3transfer`, `tzdata`,
`tzdata-legacy`, and `uvloop`.

The original 118-package manual-review residual remains open because SBOM
metadata does not replace owner review, notice collection, or supply-chain
attestation. The Phase 3 RC Scout scan is now complete for the approved exact
digest; its raw SARIF, summary, and SBOM remain local/internal artifacts.

## Owner recommendations for Phase 4

1. Pin an SBOM format and publish it beside each approved digest.
2. Add signed build provenance and verification with an assigned key-rotation owner.
3. Review the 118-package license queue and record SPDX expressions and notices.
4. Add an approved private vulnerability-reporting channel before any public repository or release decision.
