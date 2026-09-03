# Productization Phase 1 repository audit

Audit scope: local repository preparation only. No GitHub repository, remote,
push, release, package, image publication, or external evidence upload was
performed.

## Repository facts

- The repository currently has zero tracked files in the local Git index.
- No Git remote is configured.
- Historical baseline recorded VERSION as 0.1.0-alpha.1 and package metadata
  as 0.1.0a1; the current Phase 3 RC is 1.0.0rc1 consistently.
- No public 1.0.0 version or release tag was created; versioning should be
  changed only with an owner-approved release decision.
- The canonical Compose file is compose.yaml.
- The default Compose topology is PostgreSQL, migration, and API server.
- Optional retention, ledger, integrity, and replication services are
  profile-gated.
- The V20 acceptance topology is tests/compose.v20-live.yaml and is not the
  normal developer topology.
- Existing GitHub Actions workflows are .github/workflows/ci.yml and
  .github/workflows/security.yml; both run the repository checks with Python
  3.12. Dependabot configuration is present.
- No LICENSE file is present: LICENSE_DECISION_REQUIRED.
- No private security destination is configured:
  SECURITY_CONTACT_REQUIRED.
- No Code of Conduct was added; this remains an optional future repository
  policy decision.

## Intended surface classification

PUBLIC: server source, sdk/python source, postgres initialization, compose.yaml,
requirements and package metadata, examples/basic_agent, the OpenTelemetry
example, and the high-level documentation intended for developers.

PUBLIC BUT DOCUMENTED: .env.example, Dockerfiles, scripts/bootstrap-dev.ps1,
scripts/check.ps1, CI workflows, and security scanning configuration. These
files must not contain real credentials or machine-specific paths.

DEVELOPMENT-ONLY: .env, .dev-secrets, .agentguard, local spools, Docker
volumes, pytest caches, coverage output, and .tmp. These paths are ignored and
must not be included in a public source archive.

TEST-ONLY: tests/compose.v20-live.yaml, V20 witness and acceptance harnesses,
fixture credentials, and historical live-closure scripts. They are useful for
controlled validation but are not the normal public Quick Start.

LOCAL-ONLY: the sealed V20 image tag and digest, Docker build caches, and
disposable test configuration. A later productization candidate image must
use a distinct tag and must not inherit a V20 release claim.

RELEASE-ARTIFACT: V20 sealed evidence, SBOM, Scout outputs, release manifest,
and closure records. They remain local/internal until separately reviewed.
They were not mutated for this audit.

SECRET/NEVER COMMIT: .env values, secret files, API keys, database URLs,
pepper and integrity keys, archive encryption keys, OIDC credentials, bearer
tokens, and private keys.

## Boundary and leak review

The public template uses placeholders and local secret-file references. The
Docker build context excludes tests, artifacts, temporary paths, documentation,
and development secret directories; the image copies only the runtime server,
SDK, version, and locked runtime requirements.

Historical acceptance evidence and scripts can contain tenant identifiers,
fixture values, host paths, or operational details. They remain classified
internal/test-only rather than being silently rewritten, because V20 evidence
is sealed. The two existing ACL-protected directories
.tmp/v20-live-current and .tmp/v20-v0-v19-live are classified
UNREADABLE_NON_RELEASE_TEMP_PATH; their ACLs were not weakened.

Before any public source archive, rerun the secret scan, path scan, license
review, and artifact review over exactly the proposed archive inputs. Phase 1
does not publish any artifact.
