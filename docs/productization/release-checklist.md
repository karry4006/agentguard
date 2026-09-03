# Future AgentGuard 1.0 public release checklist

This checklist is preparatory. Phase 2 does not create a 1.0 tag, GitHub
release, public repository, package publication, or container publication.

## Required gates

- Phase 1 PASS
- Phase 2 PASS
- approved Apache-2.0 license and copyright ownership
- private vulnerability reporting enabled and SECURITY.md verified
- approved public repository visibility change
- green mandatory CI, including Python 3.13, Python 3.12 SDK compatibility,
  static/security checks, migration sanity, and Docker build
- fresh clone Quick Start PASS with zero undocumented steps
- reviewed README and documentation links
- exact public-release secret and machine-path scan PASS
- reviewed source archive and public artifact classification
- release-candidate image validation and SBOM
- Docker Scout or equivalent exact-digest approval under an approved
  transmission policy

## Publication decisions

Approve the GitHub tag and release notes, package publication, container
registry target, package/image names, public visibility, and release owner.
Do not infer any of these from a local candidate build.

## Evidence

Record the exact source commit, image digest, migration head, dependency
lockfile checksums, SBOM, scanner results, Quick Start result, and owner
approvals. Keep raw internal V19/V20 acceptance evidence separate from the
public release archive.
