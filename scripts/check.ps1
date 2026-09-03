param(
    [switch]$SkipDocker
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot ".."))
Set-Location $repo

if ($SkipDocker) {
    & (Join-Path $PSScriptRoot "ci.ps1") -SkipDocker
} else {
    & (Join-Path $PSScriptRoot "ci.ps1")
}

if ($LASTEXITCODE -ne 0) {
    throw "AgentGuard checks failed"
}

Write-Output "product_checks=PASS"
