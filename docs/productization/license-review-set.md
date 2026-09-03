# AgentGuard RC1 exact license review set

This is the finite 14-record review set for the sealed image
`sha256:d67cdf9eab0bc00efe62f1535e0e954fa7b535fe69c87d0b075d12394c4acfd4`.
It is an engineering/compliance record, not legal certification. The machine-readable
version is `artifacts/dependency-license-closure.json` under `review_items`.

| Component | Version | License expression | Type / boundary | Present / relation | Modified? | Source available? | Notice / text / source requirement | Classification | Remaining legal question | Engineering action |
|---|---|---|---|---|---|---|---|---|---|---|
| base-files | 13.8+deb13u6 | GPL-2.0-or-later | OS / OS base | YES / OS runtime | NO | YES — Debian package record | YES / YES / exact source mapping | COMPLIANCE_TASK_ONLY | None identified; complete the artifact task. | Preserve exact Debian copyright and source mapping. |
| certifi | 2026.7.22 | MPL-2.0 | Python / imported library | YES / transitive runtime | NO | YES — exact dist-info | YES / YES / preserve text and attribution | COMPLIANCE_TASK_ONLY | None identified; complete the artifact task. | Ship exact MPL-2.0 text and certifi attribution. |
| psycopg-binary | 3.3.4 | LGPL-3.0-only | Python / bundled native wheel | YES / transitive runtime | NO | YES — exact wheel and native provenance | YES / YES / corresponding-source path | SOURCE_OBLIGATION_REVIEW_REQUIRED | None identified beyond source-method completion. | Preserve wheel notice, LGPL text, and exact native source mappings. |
| libgomp1 | 14.2.0-19 | GPL-3.0-or-later WITH GCC-exception-3.1 | OS / runtime library | YES / OS runtime | NO | YES — gcc-14 Debian record | YES / YES / exception and source mapping | LICENSE_EXCEPTION_INTERPRETATION_REQUIRED | Does the exception cover the exact distributed file? | Confirm file-scoped GCC exception coverage. |
| libstdc++6 | 14.2.0-19 | GPL-3.0-or-later WITH GCC-exception-3.1 | OS / runtime library | YES / OS runtime | NO | YES — gcc-14 Debian record | YES / YES / exception and source mapping | LICENSE_EXCEPTION_INTERPRETATION_REQUIRED | Does the exception cover the exact distributed file? | Confirm file-scoped GCC exception coverage. |
| readline | 8.2-6 | GPL-3.0-or-later for library; file-scoped GPL-2/GFDL | OS / runtime library | YES / transitive OS runtime | NO | YES — readline Debian record | YES / YES / exact source mapping | COMPLIANCE_TASK_ONLY | None identified; this is redistribution/source handling, not AgentGuard linkage. | Preserve exact file-scoped texts and source mapping. |
| netbase | 6.5 | GPL-2.0-only | OS / data and configuration | YES / OS runtime | NO | YES — Debian package record | YES / YES / exact source mapping | COMPLIANCE_TASK_ONLY | None identified; distributed payload is data/configuration. | Preserve copyright and map `/etc/services`, `/etc/rpc`, `/etc/protocols`, `/etc/ethertypes`. |
| libreadline8t64 | 8.2-6 | GPL-3.0-or-later for library; file-scoped GPL-2/GFDL | OS / runtime library | YES / OS runtime | NO | YES — readline Debian record | YES / YES / exact source mapping | COMPLIANCE_TASK_ONLY | None identified; complete the artifact task. | Preserve exact readline text and source mapping. |
| media-types | 13.0.0 | LicenseRef-Debian-ad-hoc-public-domain | OS / data | YES / OS runtime | NO | YES — Debian copyright record | YES / YES / source reference | COMPLIANCE_TASK_ONLY | None identified; do not replace the Debian term with guessed SPDX. | Preserve exact Debian term and source reference. |
| psycopg | 3.3.4 | LGPL-3.0-only | Python / imported library | YES / direct runtime | NO | YES — exact dist-info | YES / YES / corresponding-source path | SOURCE_OBLIGATION_REVIEW_REQUIRED | None identified beyond source-method completion. | Preserve LGPL text and document exact corresponding-source path. |
| libgcc-s1 | 14.2.0-19 | GPL-3.0-or-later WITH GCC-exception-3.1 | OS / runtime library | YES / OS runtime | NO | YES — gcc-14 Debian record | YES / YES / exception and source mapping | LICENSE_EXCEPTION_INTERPRETATION_REQUIRED | Does the exception cover the exact distributed file? | Confirm file-scoped GCC exception coverage. |
| gcc-14-base | 14.2.0-19 | GPL-3.0-or-later WITH GCC-exception-3.1; file-scoped records | OS / package metadata | YES / OS runtime | NO | YES — gcc-14 Debian record | YES / YES / exception and source mapping | LICENSE_EXCEPTION_INTERPRETATION_REQUIRED | Does the exception cover the exact distributed file? | Confirm whether the exact distributed record is covered. |
| keyutils-libs | 1.5.8-3.el7 | LGPL-2.0-or-later | Native wheel / bundled shared library | YES / transitive runtime | NO | YES — exact CentOS source RPM | YES / YES / corresponding-source path | SOURCE_OBLIGATION_REVIEW_REQUIRED | None identified beyond source-method completion. | Preserve the exact LGPL text and source RPM mapping. |
| cyrus-sasl-lib | 2.1.26-24.el7_9 | CMU BSD-with-advertising | Native wheel / bundled shared library | YES / transitive runtime | NO | YES — exact CentOS source RPM | YES / YES / source mapping | COMPLIANCE_TASK_ONLY | None identified; complete the notice/source artifact. | Preserve exact COPYING text and source reference. |

## Boundary facts

AgentGuard does not copy or modify any of these components, and no AgentGuard source
was found to import or link `readline` directly. `netbase` contributes networking
database/configuration files, not a library linked to AgentGuard. The exact image has
zero GPL-family Python runtime components; all 44 GPL-family observations are OS,
runtime, native, or file-scoped records. The six native libraries are embedded by the
unmodified `psycopg-binary` wheel and are separately mapped in the native evidence
artifact.
