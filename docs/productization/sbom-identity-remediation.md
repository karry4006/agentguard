# RC2 SBOM identity remediation

RC1 remains immutable at
`sha256:d67cdf9eab0bc00efe62f1535e0e954fa7b535fe69c87d0b075d12394c4acfd4`.
No metadata or image from RC1 is changed by this gate.

## Defect

The product/release identity is `1.0.0rc1`, while the two first-party package records
in the sealed SBOM report `0.1.0a1`. This is an SBOM identity defect, not evidence of a
third-party dependency defect.

## Applied RC2 fix

For `1.0.0rc2`, the version sources were updated in:

- `server/pyproject.toml`
- `sdk/python/pyproject.toml`

The package `__version__` declarations read the root `VERSION` source, and the Docker
build now installs both first-party projects with `--no-deps` from their declared
`pyproject.toml` versions. This makes clean-clone image metadata and local CycloneDX
first-party components report `1.0.0rc2` without refreshing or changing third-party
dependencies. RC1 remains immutable. The recommended future tag is
`v1.0.0-rc.2`; no tag is created here.
