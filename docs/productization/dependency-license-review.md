# AgentGuard 1.0 — License Evidence Resolution

Status: `BLOCKED_LEGAL_REVIEW`

This is an engineering evidence and redistribution-planning record for the
sealed `1.0.0rc1` image. It is not legal certification and does not decide
derivative-work or license compatibility questions.

RC digest: `sha256:d67cdf9eab0bc00efe62f1535e0e954fa7b535fe69c87d0b075d12394c4acfd4`

## Previous state

The prior closure entered this gate with:

- 118 manual-review records in the earlier broad queue;
- 71 remaining manual-review candidates after the first engineering triage;
- 47 copyleft-related records (44 GPL/AGPL-family IDs and 3 LGPL/MPL-family IDs);
- 17 distributed records without usable license metadata;
- 38 dual/multi-license records.

Those counts were scanner/package-record counts, not legal findings.

## New state

| Measure | Result |
|---|---:|
| Exact SBOM components | 122 |
| First-party / third-party | 2 / 120 |
| Missing-license records resolved from exact evidence | 11 |
| Remaining missing-license records | 6 |
| Previous multi-license records normalized | 38 |
| Remaining ambiguous multi-license records | 0 factual metadata expressions |
| GPL-family identifiers observed | 44 |
| Actual primary strong-copyleft runtime records | 8 |
| GPL-family alternative-only records | 0 |
| GPL-family secondary/file-scoped records | 36 |
| GPL-family OS/runtime records | 44 |
| GPL-family Python/runtime records | 0 |
| GPL-family dev/build-only records | 0 |
| Remaining manual-review records | 18 |

The 18-item queue is now specific: 8 actual primary strong-copyleft runtime
records, 3 weak-copyleft runtime records, 1 custom Debian term, and the 6
embedded native records whose exact package license is still absent from the
embedded auditwheel SBOM. The 44 observed GPL-family identifiers are not
counted as 44 compatibility blockers.

## Evidence resolution

The curated lock in `licenses/license-evidence.json` records exact versions,
SPDX expressions where supported, file-scoped terms, selected options only
where the upstream wording grants a real choice, evidence source, runtime
boundary, and review status.

The 11 previously missing records resolved by exact evidence are `botocore`,
`python3.13-venv`, `libxcrypt`, `python`, `libzstd`, `media-types`,
`tzdata-legacy`, `libcrypt1`, `tzdata`, `gcc-14`, and `uvloop`. `botocore`
uses the exact 1.40.39 PyPI release metadata; `uvloop` uses the official
v0.22.1 upstream tag. Debian records use copyright files extracted from the
exact RC image. The host `botocore` version was not used.

The remaining six records are `libcom_err`, `krb5-libs`, `libselinux`,
`keyutils-libs`, `pcre`, and `cyrus-sasl-lib`. They are CentOS/RPM-looking
records nested under the exact `psycopg-binary` auditwheel SBOM, not Debian
base-image packages. They remain `UNRESOLVED_LICENSE_EVIDENCE` pending exact
official CentOS source RPM/spec and notice evidence. Their embedded auditwheel
SBOM hash is recorded in the evidence lock and source-bundle plan.

The exact first-party SBOM records identify the packages as `0.1.0a1`, while
the RC source/container identity is `1.0.0rc1`. This is a factual packaging
identity blocker for a future rebuild; it is not a license mismatch, and the
sealed image was not rebuilt here.

## Copyleft boundary facts

The actual primary GPL-family records are `base-files`, `netbase`,
`readline`, `libreadline8t64`, `libgcc-s1`, `libgomp1`, `libstdc++6`, and
`gcc-14-base`. The GCC runtime records carry the documented GCC Runtime
Library Exception terms; readline carries GPL library terms plus file-scoped
records. These facts require owner/legal decisions about compatibility and
source distribution; this inventory does not make those decisions.

The SBOM GPL identifiers on CPython, Kerberos, bzip2, and many Debian source
groups were reconciled against exact Debian copyright records as file-scoped,
packaging, documentation, or source-package aggregation. They remain in the
observed-ID totals and notices plan, but are not classified as Python GPL
runtime dependencies or actual primary GPL libraries.

Weak-copyleft records are `psycopg` and `psycopg-binary` under LGPL-3.0-only
and `certifi` under MPL-2.0. No AgentGuard source is copied into or modified
inside these dependencies. The exact engineering boundaries and required
notice/source actions remain recorded in the matrix. No AGPL runtime concern
was found; no AGPL identifier is present in the normalized exact-image set.

## Source, notices, and license bundle

`docs/productization/source-provenance.md` maps source packages/projects,
versions, origins, exact image evidence, modifications, and source-distribution
status. `artifacts/license-source-bundle-plan.json` is an engineering plan
only; it does not download or publish source archives.

`THIRD_PARTY_NOTICES.md` now separates the conservative project policy that
every distributed third-party record receives an inventory entry from
license-specific notice actions. It remains a candidate inventory. The
`licenses/third-party/` directory contains only a README until authoritative
exact license/copyright/NOTICE texts are assembled; no legal text was
fabricated.

Required final actions remain blocked pending the exact six native licenses,
final license-text and notice contents, source-bundle approach, GCC exception
and readline review, the `libzstd` BSD selection confirmation, and the first-
party package identity correction in a future image build.

## Gates

- `DEPENDENCY_LICENSE_GATE`: `BLOCKED_LEGAL_REVIEW`
- `SCOUT_SECURITY_GATE`: `PASS` for the exact digest; 0 Critical, High,
  Medium, Low, and KEV findings.
- `SECURITY_CONTACT_GATE`: `BLOCKED`, deferred until public release.
- `PUBLIC_RELEASE_READY`: `NO`.

The repository remains private. No GitHub Release, PyPI publication,
container publication, image rebuild, dependency change, V21, or Phase 4
work is part of this gate.

## Exact owner/legal decisions required

1. Confirm the six bundled CentOS native-library licenses and their exact
   notices/source records.
2. Decide the compatibility and corresponding-source path for the actual
   primary GPL-family runtime records, including GCC exception applicability
   and readline.
3. Confirm `libzstd` BSD-option use while retaining file-scoped zlib/Expat
   notices.
4. Approve final license-text, NOTICE/copyright, and source-bundle contents.
5. Correct first-party package version identity before any future RC rebuild.
