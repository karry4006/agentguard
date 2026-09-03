param(
    [Parameter(Mandatory=$true)][string]$BackupPath,
    [string]$Container = "agentguard-postgres-1",
    [string]$DatabasePrefix = "agentguard_restore_check"
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot ".."))
$backup = [IO.Path]::GetFullPath((Join-Path $repo $BackupPath))
if (-not $backup.StartsWith($repo.Path, [StringComparison]::OrdinalIgnoreCase)) { throw "restore path must stay inside the repository" }
if (-not (Test-Path -LiteralPath $backup)) { throw "backup file does not exist" }
docker inspect $Container | Out-Null
$migrationUser = $env:AGENTGUARD_MIGRATION_USER
$migrationPassword = $env:AGENTGUARD_MIGRATION_PASSWORD
$database = $env:POSTGRES_DB
if (-not $migrationUser -or -not $migrationPassword -or -not $database) { throw "migration restore environment is incomplete" }
$schema = "$DatabasePrefix`_$([guid]::NewGuid().ToString('N').Substring(0,12))"
$containerBackup = "/tmp/$schema.dump"
$containerSql = "/tmp/$schema.sql"
try {
    docker cp $backup "$Container`:$containerBackup" | Out-Null
    # Runtime and migration roles are deliberately not CREATEDB. Restore into
    # a temporary schema in the existing database, which is an isolated target
    # that exercises recovery without weakening the production role model.
    # The application roles are not database CREATE-capable. The disposable schema is created by the container bootstrap process, then the migration role receives only temporary schema-local rights.
    docker exec $Container psql "--username=postgres" "--dbname=$database" "--command=CREATE SCHEMA $schema" | Out-Null
    docker exec $Container psql "--username=postgres" "--dbname=$database" "--command=GRANT USAGE, CREATE ON SCHEMA $schema TO $migrationUser" | Out-Null
    docker exec $Container sh -c "pg_restore --no-owner --no-privileges --schema=public --file=$containerSql $containerBackup" | Out-Null
    docker exec $Container sh -c ("sed -i -e 's/public\./$schema./g' -e 's/search_path = public/search_path = $schema/g' $containerSql") | Out-Null
    docker exec -e "PGPASSWORD=$migrationPassword" $Container psql "--username=$migrationUser" "--dbname=$database" --set=ON_ERROR_STOP=1 "--file=$containerSql" | Out-Null
    $head = (docker exec -e "PGPASSWORD=$migrationPassword" $Container psql "--username=$migrationUser" "--dbname=$database" --tuples-only --no-align "--command=SELECT version_num FROM $schema.alembic_version" | Select-Object -Last 1).Trim()
    if ($head -ne "0014_ledger_segment_archival") { throw "restored migration head was not 0014_ledger_segment_archival" }
    Write-Output "backup_restore=PASS isolated_target=schema migration_head=$head"
} finally {
    docker exec $Container psql "--username=postgres" "--dbname=$database" "--command=DROP SCHEMA IF EXISTS $schema CASCADE" | Out-Null
    docker exec $Container sh -c "rm -f $containerBackup $containerSql" | Out-Null
}
