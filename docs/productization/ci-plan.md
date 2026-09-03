# Productization CI plan

The existing .github/workflows/ci.yml and security.yml are the starting point.
They use Python 3.12 and scripts/ci.ps1 for compile, tests, Bandit, pip-audit,
secret scanning, and Docker configuration checks.

Before a public repository is enabled, add a matrix for the supported Python
versions, pin or review action versions, cache only non-sensitive dependencies,
and keep live Docker acceptance behind an explicit protected job. Required
gates should include migrations, SDK examples, the no-paid-API demo, archive
and witness tests, image configuration, SBOM generation, and a secret scan of
the exact proposed release inputs.

Docker Scout or another external scanner must run only under an approved
policy and with explicit handling for network transmission. A local PASS on
the sealed V20 image is not a scan result for a later productization image.
