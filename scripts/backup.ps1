param(
    [string]$OutputPath = "artifacts\agentguard-backup.dump",
    [string]$Container = "agentguard-postgres-1"
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot ".."))
$target = [IO.Path]::GetFullPath((Join-Path $repo $OutputPath))
if (-not $target.StartsWith($repo.Path, [StringComparison]::OrdinalIgnoreCase)) { throw "backup path must stay inside the repository" }
$parent = Split-Path -Parent $target
New-Item -ItemType Directory -Force -Path $parent | Out-Null
docker inspect $Container | Out-Null
# The bootstrap role is intentionally NOLOGIN after the least-privilege
# remediation. The migration role owns the schema and is sufficient for a
# logical dump without granting runtime/admin powers to the server.
$containerTarget = "/tmp/agentguard-backup-$([guid]::NewGuid().ToString('N')).dump"
try {
    $dumpCommand = 'PGPASSWORD="$AGENTGUARD_MIGRATION_PASSWORD" pg_dump --format=custom --no-owner --no-privileges --username="$AGENTGUARD_MIGRATION_USER" --dbname="$POSTGRES_DB" > ' + $containerTarget
    docker exec $Container sh -c $dumpCommand
    docker cp "$Container`:$containerTarget" $target | Out-Null
} finally {
    docker exec $Container sh -c "rm -f $containerTarget" | Out-Null
}
if (-not (Test-Path -LiteralPath $target) -or (Get-Item -LiteralPath $target).Length -lt 64) { throw "pg_dump did not create a usable backup" }
$relative = $target.Substring($repo.Path.Length).TrimStart('\','/')
Write-Output "backup=PASS path=$relative bytes=$((Get-Item -LiteralPath $target).Length)"
