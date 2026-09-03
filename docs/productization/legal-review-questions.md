# AgentGuard RC1 legal review questions

Only one genuine interpretation question remains in the current evidence set. This
document does not decide it and does not certify release readiness.

## GCC Runtime Library Exception 3.1 — exact file scope

- **Components:** `libgcc-s1`, `libgomp1`, `libstdc++6`, `gcc-14-base`
- **Versions:** `14.2.0-19`
- **License evidence:** `GPL-3.0-or-later WITH GCC-exception-3.1` for runtime libraries, with file-scoped GCC records in the exact Debian `gcc-14-base` copyright evidence.
- **Technical relationship:** unmodified OS/runtime packages in the sealed container; no AgentGuard source is copied into, modified, or statically linked with them.
- **Present in RC:** YES
- **Source available:** YES — exact Debian source-package mapping is recorded in `licenses/source-compliance-manifest.json` and `artifacts/license-source-bundle-plan.json`.
- **Compliance artifacts prepared:** evidence and source plan YES; complete license-text bundle BLOCKED pending final text assembly.
- **Exact unresolved question:** Does the exception cover each exact distributed file represented by these four SBOM/package records, including the `gcc-14-base` record, under the intended container redistribution model?
- **Engineering workaround:** retain the packages and obtain the owner/legal interpretation; alternatively choose a base/runtime composition without these records, accepting rebuild, regression, dependency, and new Scout impact.
- **Owner decision needed:** YES, if the release owner requires legal interpretation before completing the bundle.
