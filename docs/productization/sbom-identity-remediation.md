# Future RC2 SBOM identity remediation

RC1 remains immutable at
`sha256:d67cdf9eab0bc00efe62f1535e0e954fa7b535fe69c87d0b075d12394c4acfd4`.
No metadata or image is changed by this gate.

## Defect

The product/release identity is `1.0.0rc1`, while the two first-party package records
in the sealed SBOM report `0.1.0a1`. This is an SBOM identity defect, not evidence of a
third-party dependency defect.

## Exact future fix

Before building `1.0.0rc2`, update the version sources in:

- `server/pyproject.toml`
- `sdk/python/pyproject.toml`

Then inspect the package `__version__` declarations and Docker build/install metadata
that consume those project versions. Rebuild the future RC so installed wheel metadata,
CycloneDX first-party components, container labels, and release manifest all say
`1.0.0rc2`. Verify with the existing SBOM/release checks, fresh-clone validation, and a
new Scout scan. The recommended future tag is `v1.0.0-rc.2`; no tag is created here.
