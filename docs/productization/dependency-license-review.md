# AgentGuard 1.0 — Final Factual License Resolution

Status: `PASS` for the engineering license gate

This is an engineering evidence and redistribution-planning record for the
sealed `1.0.0rc1` image. It is not legal certification and does not decide
derivative-work or broad license-compatibility questions.

RC digest: `sha256:d67cdf9eab0bc00efe62f1535e0e954fa7b535fe69c87d0b075d12394c4acfd4`

## Closure result

| Measure | Result |
|---|---:|
| Exact SBOM components | 122 |
| First-party / third-party | 2 / 120 |
| Previous missing exact-text mappings | 43 |
| Resolved exact-text mappings | 43 |
| Remaining exact-text mappings | 0 |
| Remaining manual-review queue | 0 |
| Remaining missing-license records | 0 |
| Multi-license records / normalized | 38 / 38 |
| Remaining ambiguous multi-license records | 0 |
| Unknown distributed licenses | 0 |
| GCC runtime exception gate | PASS |

The six earlier native-wheel license-evidence blockers were resolved from the
exact `psycopg-binary` wheel filesystem, embedded auditwheel SBOM, ELF SONAMEs
and hashes, and official exact-version CentOS source RPM/spec evidence. The
mapping is in `artifacts/psycopg-binary-native-evidence.json`.

## GCC Runtime Library Exception 3.1

The exact Debian `gcc-14-base` copyright evidence and RC1 package files support
the following narrow engineering result:

- `libgcc-s1` `14.2.0-19`: `CONFIRMED` for `/usr/lib/x86_64-linux-gnu/libgcc_s.so.1`.
- `libgomp1` `14.2.0-19`: `CONFIRMED` for `/usr/lib/x86_64-linux-gnu/libgomp.so.1.0.0`.
- `libstdc++6` `14.2.0-19`: `CONFIRMED` for `/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.33`.
- `gcc-14-base` `14.2.0-19`: `NOT_APPLICABLE`; exact package files are documentation/support metadata, not a standalone runtime library.

The exact source text, source subtrees, SONAMEs, and binary hashes are recorded
in `artifacts/gcc-runtime-exception-evidence.json`. No derivative-work or
proprietary-software safety conclusion is made.

## Source obligations

`psycopg`, `psycopg-binary`, and `keyutils-libs` are factually mapped with exact
license text, source provenance, and source-compliance entries. Their status is
`READY_FOR_RELEASE_PACKAGING`; these are packaging obligations, not unresolved
engineering license questions.

## Gates

- `FACTUAL_LICENSE_GATE`: `PASS`
- `LEGAL_INTERPRETATION_GATE`: `PASS` for the completed engineering evidence scope
- `LICENSE_ARTIFACT_BUNDLE_GATE`: `PASS`
- `DEPENDENCY_LICENSE_GATE`: `PASS`
- `ENGINEERING_LICENSE_REVIEW_COMPLETE`: `YES`
- `LEGAL_CERTIFICATION`: `NOT_PERFORMED`
- `DEPENDENCY_CHANGES_REQUIRED`: `NO`

The 120-row index, exact text bundle, third-party notice inventory, source
provenance, source-compliance manifest, and source plan are complete for
release packaging. The validator confirms coverage, evidence hashes, no
placeholders, no dangling files, no private absolute paths, and no stale
unresolved review IDs.

## Protected release boundary

The RC1 image was not rebuilt and the Scout result was not rerun. The RC1
first-party SBOM identity defect remains `0.1.0a1` versus `1.0.0rc1`; a future
RC2 remains `METADATA_ONLY` and is not built here. The repository remains
private. No release, tag, PyPI publication, container publication, Phase 4, or
V21 work is authorized here.
