param(
    [string]$OutputPath = "artifacts\release-manifest.json",
    [string]$TestSummary = "not-recorded",
    [string]$SbomPath = "artifacts\agentguard-sbom.cyclonedx.json",
    [string]$DockerImage = "agentguard-agentguard-server:latest"
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot ".."))
$target = [IO.Path]::GetFullPath((Join-Path $repo $OutputPath))
if (-not $target.StartsWith($repo.Path, [StringComparison]::OrdinalIgnoreCase)) { throw "manifest path must stay inside the repository" }

function Get-Sha256([string]$path) {
    if (Test-Path -LiteralPath $path) { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
    return $null
}

$version = (Get-Content -LiteralPath (Join-Path $repo "VERSION") -Raw).Trim()
$gitSha = "unavailable"
try {
    $gitSha = (& git -c "safe.directory=$($repo.Path)" rev-parse HEAD 2>$null).Trim()
    if ($gitSha -notmatch '^[0-9a-f]{40}$') { $gitSha = "unavailable" }
} catch { $gitSha = "unavailable" }
$migration = "unknown"
$migrationFiles = Get-ChildItem -LiteralPath (Join-Path $repo "server\alembic\versions") -Filter "*.py" -File |
    Where-Object { $_.Name -match '^\d{4}_[A-Za-z0-9_]+\.py$' } |
    Sort-Object Name
if ($migrationFiles.Count -gt 0) { $migration = [IO.Path]::GetFileNameWithoutExtension($migrationFiles[-1].Name) }
$sbomFullPath = [IO.Path]::GetFullPath((Join-Path $repo $SbomPath))
$repoDigests = (& docker image inspect $DockerImage --format '{{json .RepoDigests}}' 2>$null | ConvertFrom-Json)
$runtimeImageDigest = if ($repoDigests.value) { [string]$repoDigests.value[0] } else { [string]$repoDigests[0] }
if (-not $runtimeImageDigest) { throw "selected runtime image has no repository digest: $DockerImage" }
$dockerfileText = Get-Content -LiteralPath (Join-Path $repo "server\Dockerfile") -Raw
$baseMatch = [regex]::Match($dockerfileText, '(?m)^FROM\s+(?<repo>[^@\s]+):(?<tag>[^@\s]+)@(?<digest>sha256:[0-9a-f]+)\s*$')
if (-not $baseMatch.Success) { throw "selected runtime base is not digest-pinned" }
$runtimePython = (& docker run --rm $DockerImage -c "import sys; print(sys.version.split()[0])" 2>$null).Trim()
if ($runtimePython -notmatch '^3\.13\.') { throw "selected runtime is not Python 3.13: $runtimePython" }
$manifest = [ordered]@{
    product = "AgentGuard"
    release_version = $version
    git_commit = $gitSha
    build_timestamp = if ($env:SOURCE_DATE_EPOCH) { $env:SOURCE_DATE_EPOCH } else { "not-recorded" }
    migration_head = $migration
    python_version = $runtimePython
    runtime_image = $DockerImage
    runtime_image_digest = $runtimeImageDigest
    runtime_base_repository = $baseMatch.Groups['repo'].Value
    runtime_base_tag = $baseMatch.Groups['tag'].Value
    runtime_base_digest = $baseMatch.Groups['digest'].Value
    runtime_base_os = "Debian 13"
    runtime_user = "65532:65532"
    runtime_shell = "absent"
    requirements_lock_sha256 = Get-Sha256 (Join-Path $repo "requirements.lock")
    requirements_dev_lock_sha256 = Get-Sha256 (Join-Path $repo "requirements-dev.lock")
    sbom_sha256 = Get-Sha256 $sbomFullPath
    sbom_status = if (Test-Path -LiteralPath $sbomFullPath) { "PASS" } else { "UNAVAILABLE" }
    test_summary = $TestSummary
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $target -Encoding utf8
$relative = $target.Substring($repo.Path.Length).TrimStart('\','/')
Write-Output "release_manifest=PASS path=$relative"
