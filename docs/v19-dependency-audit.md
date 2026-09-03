# V19 dependency-audit note

`pip-audit --local` completed successfully with no known vulnerabilities.
The installed environment contains two local distributions that are not
published on PyPI and therefore cannot be externally resolved by pip-audit:

- `agentguard`
- `agentguard-server`

The lock-file audit was also attempted, but its isolated installation path
cannot build the Windows-incompatible `uvloop` package. This is an audit
environment limitation, not a vulnerability finding. The Linux production
image remains the required dependency-resolution environment.
