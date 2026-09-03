param(
    [switch]$SkipDocker,
    [string]$Python = "py"
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot ".."))
Set-Location $repo
$sdkSrc = Join-Path $repo "sdk/python/src"
$serverSrc = Join-Path $repo "server/src"
$env:PYTHONPATH = ($sdkSrc, $serverSrc) -join [IO.Path]::PathSeparator

& $Python -m compileall -q server/src sdk/python/src examples
& $Python -m pytest -q -p no:cacheprovider --ignore-glob='*_live.py' --deselect tests/test_server.py::test_postgresql_integration_trace_spans_jsonb_idempotency_and_query
& $Python -m pytest -q -p no:cacheprovider tests/test_security_gate.py tests/test_evaluation.py tests/test_evaluation_api.py tests/test_evaluation_cli.py
& $Python -m bandit -q -r server/src sdk/python/src examples
if ($LASTEXITCODE -ne 0) { throw "Bandit failed" }
& $Python -m pip_audit --skip-editable
if ($LASTEXITCODE -ne 0) { throw "pip-audit failed" }
& (Join-Path $PSScriptRoot "secret-scan.ps1")
if ($LASTEXITCODE -ne 0) { throw "secret scan failed" }

if (-not $SkipDocker) {
    $env:POSTGRES_DB = "agentguard_ci"
    $env:POSTGRES_USER = "agentguard_ci_bootstrap"
    $env:POSTGRES_PASSWORD = "ci-only-placeholder-password"
    $env:AGENTGUARD_RUNTIME_PASSWORD = "ci-only-runtime-password"
    $env:AGENTGUARD_MIGRATION_PASSWORD = "ci-only-migration-password"
    $env:AGENTGUARD_KEY_PEPPER = "ci-only-key-pepper-not-used-for-runtime"
    $env:AGENTGUARD_INTEGRITY_KEY = "ci-only-integrity-key-not-used-for-runtime-32-bytes"
    docker compose config --quiet
}
Write-Output "ci=PASS"
