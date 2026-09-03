# AgentGuard RC1 license owner decisions

RC1 remains sealed. The engineering license review resolved the exact package,
license-text, source-provenance, and GCC Runtime Library Exception evidence
without changing dependencies.

## Closed engineering decisions

- `NO_DEPENDENCY_CHANGE_REQUIRED`: the sealed dependency set remains unchanged.
- GCC runtime scope is factually resolved for `libgcc-s1`, `libgomp1`, and
  `libstdc++6`; `gcc-14-base` is `NOT_APPLICABLE` as a runtime-library record.
- The 120-component exact-text bundle and source-compliance artifacts are
  `READY_FOR_RELEASE_PACKAGING`.
- RC2 remains `METADATA_ONLY` for the first-party SBOM/package identity
  correction. RC2 is not built in this closure.

This record is engineering evidence and does not constitute legal
certification. `LEGAL_CERTIFICATION: NOT_PERFORMED`.
