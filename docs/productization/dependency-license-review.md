# AgentGuard 1.0 — Final Factual License Resolution

Status: `BLOCKED`

This is an engineering evidence and redistribution-planning record for the
sealed `1.0.0rc1` image. It is not legal certification and does not decide
derivative-work or license compatibility questions.

RC digest: `sha256:d67cdf9eab0bc00efe62f1535e0e954fa7b535fe69c87d0b075d12394c4acfd4`

## Closure result

| Measure | Result |
|---|---:|
| Exact SBOM components | 122 |
| First-party / third-party | 2 / 120 |
| Previous manual-review queue | 18 |
| Remaining manual-review queue | 14 |
| Previous missing-license records | 6 |
| Resolved missing-license records | 6 |
| Remaining missing-license records | 0 |
| Multi-license records / normalized | 38 / 38 |
| Remaining ambiguous multi-license records | 0 |
| Unknown distributed licenses | 0 |
| GPL-family identifiers observed | 44 |
| Actual primary GPL-family runtime records | 8 |
| AGPL runtime records | 0 |

The six factual blockers—`libcom_err`, `krb5-libs`, `libselinux`,
`keyutils-libs`, `pcre`, and `cyrus-sasl-lib`—are resolved from the exact
`psycopg-binary` wheel filesystem, embedded auditwheel SBOM, ELF SONAMEs and
hashes, and official exact-version CentOS source RPM/spec evidence. The
complete mapping is in `artifacts/psycopg-binary-native-evidence.json`.

## Exact native-wheel evidence

The installed wheel is:

`psycopg_binary-3.3.4-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl`

Its official PyPI SHA-256 is recorded in the native evidence artifact. The
installed dist-info path is `/opt/site/psycopg_binary-3.3.4.dist-info`, and
the nested auditwheel SBOM is
`/opt/site/psycopg_binary-3.3.4.dist-info/sboms/auditwheel.cdx.json` with
auditwheel 6.6.0 and SBOM specification 1.4. All six mapped libraries are
present under `/opt/site/psycopg_binary.libs/`; no SBOM/filesystem mismatch
was found.

The wheel tags prove manylinux2014/glibc 2.17+ x86-64 compatibility. The
embedded RPM purls and `.el7` identifiers support CentOS/RPM package lineage,
but no separate build-host attestation was present, so a particular builder
image is not asserted.

## Factual resolutions

- `libcom_err`: MIT-style file-scoped evidence in `error_table.h`; mapped to
  `e2fsprogs-1.42.9-19.el7.src.rpm`.
- `krb5-libs`: MIT-style main license with preserved component notices;
  mapped to `krb5-1.15.1-55.el7_9.src.rpm` and four original auditwheel refs.
- `libselinux`: public-domain library with exact warranty/liability text;
  mapped to `libselinux-2.5-15.el7.src.rpm`.
- `keyutils-libs`: LGPL-2.0-or-later library; GPL command-line tools are
  separate and not in the bundled `.libs`; mapped to `keyutils-1.5.8-3.el7.src.rpm`.
- `pcre`: PCRE1 8.32, BSD license; it was not substituted with PCRE2.
- `cyrus-sasl-lib`: exact CMU BSD-style terms with required acknowledgment;
  no separate plugin was identified in the bundled `.libs`.

Exact source-RPM hashes, library SONAMEs, RC paths, original auditwheel
identifiers, and staged text paths are machine-readable in the native evidence
artifact. Actual resolved text excerpts are staged under `licenses/third-party/`.

Additional exact facts: `libzstd` retains a selectable BSD-3-Clause option;
the GPL alternative is not treated as a blocker merely because it is observed.
The GCC runtime exception and readline file-specific applicability are
identified factually but remain legal/release-bundle review items. `netbase`
6.5 is an exact GPL-2.0-only OS data/configuration package, not linked
AgentGuard code. `certifi` 2026.7.22 is MPL-2.0 and unmodified. `psycopg` and
`psycopg-binary` are both 3.3.4 and LGPL-3.0-only; the wheel is redistributed
and bundles native libraries, with no AgentGuard modification or vendored
source found.

## Separate gates

- `FACTUAL_LICENSE_GATE`: `PASS`
- `LEGAL_INTERPRETATION_GATE`: `BLOCKED`
- `LICENSE_ARTIFACT_BUNDLE_GATE`: `BLOCKED` — six exact native texts are
  staged, but the complete 120-component release bundle is not assembled.
- `DEPENDENCY_LICENSE_GATE`: `BLOCKED_LEGAL_REVIEW`
- `Required notices`: `BLOCKED` pending final reviewed bundle contents.
- `Source provenance`: `PASS` as an exact mapping/plan; no source archive is
  published by this gate.
- `Source bundle plan`: `PASS` as an engineering plan; legal approval and
  artifact assembly remain pending.

## Remaining legal/release questions

1. Determine compatibility and redistribution treatment for the actual
   primary GPL-family runtime records, including GCC Runtime Library Exception
   3.1 applicability per file and readline's exact library/file boundary.
2. Determine final corresponding-source/source-offer handling for LGPL
   `psycopg`/`psycopg-binary` and `keyutils-libs`.
3. Approve the final 120-component license/notice text bundle and preserve all
   file-scoped attributions.
4. Correct the first-party SBOM identity (`0.1.0a1`) to product version
   `1.0.0rc1` in a future RC2 rebuild.

Engineering avoidance options, if legal review rejects the current boundary,
are to change the packaging boundary, make the affected component optional,
or select a permitted alternative license/dependency. None is implemented.

## Protected release boundary

The RC1 image was not rebuilt and the Scout result was not rerun. The RC1
SBOM identity defect remains `SUPPLY_CHAIN_METADATA_DEFECT`; `RC2_CHANGE_CLASS`
is `METADATA_ONLY`. The repository remains private. No release, tag, PyPI
publication, container publication, Phase 4, or V21 work is authorized here.
