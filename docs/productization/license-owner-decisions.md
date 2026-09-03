# AgentGuard RC1 license owner decisions

This matrix records choices and impacts; it does not choose a legal answer. RC1 remains
sealed and no dependency change is implemented here.

| Issue | Option A — keep and satisfy obligations | Option B — replace/remove | Option C — legal review | Engineering cost | Release impact | Security impact | New Scout scan? |
|---|---|---|---|---|---|---|---|
| GCC exception scope | Keep the exact runtime packages; preserve file-scoped GCC texts/source mapping and document the approved interpretation. | Change base/runtime composition to remove the affected records; update build, tests, SBOM, and artifacts. | Ask counsel/owner to decide whether the exact files are covered by GCC Runtime Library Exception 3.1. | A: low/medium artifact work; B: high; C: coordination delay. | A: no RC1 rebuild; B: new RC; C: release held pending decision. | A: preserves tested runtime; B risks drift/new CVEs; C no technical change. | A/C: no RC1 scan; B: yes for rebuilt image. |
| `psycopg` / `psycopg-binary` LGPL source path | Keep both unmodified packages; ship LGPL text, wheel/native notices, and exact corresponding-source/provenance artifacts. | Replace binary packaging or move database functionality outside the image. | Confirm the selected corresponding-source delivery method for this distribution model. | A: medium; B: high; C: low implementation/high coordination. | A: metadata/artifact completion; B: rebuild and retest; C: hold only the affected release path. | A preserves current tested database stack; B introduces compatibility/security review. | B: yes; A/C: no RC1 scan. |
| Full third-party text bundle | Keep dependencies and assemble authoritative exact-version texts grouped by source package, with 120-row traceability. | Reduce distributed surface only where technically unnecessary, then rebuild. | Approve whether the planned exact-source/package evidence is sufficient for the release artifact. | A: medium/large evidence curation; B: high; C: review effort. | A completes release gate without image change; B requires new RC; C holds public release. | A preserves sealed image; B changes supply chain; C no technical change. | B: yes; A/C: no RC1 scan. |

## Recommended engineering posture

Keep the sealed dependency set while completing the mechanical artifact work and asking
only the grouped GCC question. The current evidence does not prove that a dependency
replacement is necessary. Any Option B implementation would be a separate approved
change and would require a new exact SBOM, regression run, and Scout scan.
