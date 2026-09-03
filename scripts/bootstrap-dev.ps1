param(
    [string]$OutputDirectory = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
$root = [IO.Path]::GetFullPath($OutputDirectory)
$envPath = Join-Path $root ".env"
$secretDir = Join-Path $root ".dev-secrets"

if ((Test-Path -LiteralPath $envPath) -or (Test-Path -LiteralPath $secretDir)) {
    throw "Refusing to overwrite existing local configuration. Remove or move .env and .dev-secrets only after verifying they are disposable."
}

New-Item -ItemType Directory -Force -Path $secretDir | Out-Null

function New-RandomHex([int]$Bytes = 32) {
    $buffer = New-Object byte[] $Bytes
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($buffer)
    } finally {
        $rng.Dispose()
    }
    return (($buffer | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Write-Secret([string]$Name, [string]$Value) {
    $path = Join-Path $secretDir $Name
    [IO.File]::WriteAllText($path, $Value, [Text.UTF8Encoding]::new($false))
    return $path
}

$database = "agentguard_dev"
$bootstrapUser = "agentguard_bootstrap"
$runtimeUser = "agentguard_runtime"
$migrationUser = "agentguard_migration"
$retentionUser = "agentguard_retention"
$ledgerUser = "agentguard_ledger_compactor"
$integrityUser = "agentguard_integrity_compactor"
$replicationUser = "agentguard_replication_worker"
$bootstrapPassword = New-RandomHex
$runtimePassword = New-RandomHex
$migrationPassword = New-RandomHex
$retentionPassword = New-RandomHex
$ledgerPassword = New-RandomHex
$integrityPassword = New-RandomHex
$replicationPassword = New-RandomHex

Write-Secret "key_pepper" (New-RandomHex) | Out-Null
Write-Secret "integrity_key" (New-RandomHex) | Out-Null
Write-Secret "archive_encryption_keys.json" (@{ "archive-key-v1" = (New-RandomHex) } | ConvertTo-Json -Compress) | Out-Null

$urls = @{
    database_url = "postgresql+psycopg://${runtimeUser}:${runtimePassword}@postgres:5432/${database}"
    migration_database_url = "postgresql+psycopg://${migrationUser}:${migrationPassword}@postgres:5432/${database}"
    retention_database_url = "postgresql+psycopg://${retentionUser}:${retentionPassword}@postgres:5432/${database}"
    ledger_compactor_database_url = "postgresql+psycopg://${ledgerUser}:${ledgerPassword}@postgres:5432/${database}"
    integrity_compactor_database_url = "postgresql+psycopg://${integrityUser}:${integrityPassword}@postgres:5432/${database}"
    replication_database_url = "postgresql+psycopg://${replicationUser}:${replicationPassword}@postgres:5432/${database}"
}
foreach ($name in $urls.Keys) { Write-Secret $name $urls[$name] | Out-Null }

$secretPath = { param([string]$Name) (Join-Path $secretDir $Name).Replace('\','/') }
$lines = @(
    "# Generated for local development by scripts/bootstrap-dev.ps1. Do not commit.",
    "AGENTGUARD_ENVIRONMENT=development",
    "POSTGRES_DB=$database",
    "POSTGRES_USER=$bootstrapUser",
    "POSTGRES_PASSWORD=$bootstrapPassword",
    "AGENTGUARD_RUNTIME_USER=$runtimeUser",
    "AGENTGUARD_RUNTIME_PASSWORD=$runtimePassword",
    "AGENTGUARD_MIGRATION_USER=$migrationUser",
    "AGENTGUARD_MIGRATION_PASSWORD=$migrationPassword",
    "AGENTGUARD_RETENTION_USER=$retentionUser",
    "AGENTGUARD_RETENTION_PASSWORD=$retentionPassword",
    "AGENTGUARD_LEDGER_COMPACTOR_USER=$ledgerUser",
    "AGENTGUARD_LEDGER_COMPACTOR_PASSWORD=$ledgerPassword",
    "AGENTGUARD_INTEGRITY_COMPACTOR_USER=$integrityUser",
    "AGENTGUARD_INTEGRITY_COMPACTOR_PASSWORD=$integrityPassword",
    "AGENTGUARD_ARCHIVE_REPLICATION_USER=$replicationUser",
    "AGENTGUARD_ARCHIVE_REPLICATION_PASSWORD=$replicationPassword",
    "AGENTGUARD_KEY_PEPPER_HOST_FILE=$(& $secretPath 'key_pepper')",
    "AGENTGUARD_INTEGRITY_KEY_HOST_FILE=$(& $secretPath 'integrity_key')",
    "AGENTGUARD_DATABASE_URL_HOST_FILE=$(& $secretPath 'database_url')",
    "AGENTGUARD_MIGRATION_DATABASE_URL_HOST_FILE=$(& $secretPath 'migration_database_url')",
    "AGENTGUARD_RETENTION_DATABASE_URL_HOST_FILE=$(& $secretPath 'retention_database_url')",
    "AGENTGUARD_ARCHIVE_ENCRYPTION_KEYS_HOST_FILE=$(& $secretPath 'archive_encryption_keys.json')",
    "AGENTGUARD_ARCHIVE_REPLICATION_DATABASE_URL_HOST_FILE=$(& $secretPath 'replication_database_url')",
    "AGENTGUARD_LEDGER_COMPACTOR_DATABASE_URL_HOST_FILE=$(& $secretPath 'ledger_compactor_database_url')",
    "AGENTGUARD_INTEGRITY_COMPACTOR_DATABASE_URL_HOST_FILE=$(& $secretPath 'integrity_compactor_database_url')",
    "AGENTGUARD_CAPTURE_CONTENT=false",
    "AGENTGUARD_DASHBOARD_API_KEY_LOGIN_ENABLED=true",
    "AGENTGUARD_OIDC_ENABLED=false",
    "AGENTGUARD_ANCHOR_ENABLED=false",
    "AGENTGUARD_ARCHIVE_ENABLED=false",
    "AGENTGUARD_RETENTION_PURGE_ENABLED=false",
    "AGENTGUARD_ARCHIVE_REPLICATION_ENABLED=false",
    "AGENTGUARD_LEDGER_ARCHIVE_ENABLED=false",
    "AGENTGUARD_LEDGER_COMPACTION_ENABLED=false",
    "AGENTGUARD_INTEGRITY_SEGMENT_COMPACTION_ENABLED=false",
    "AGENTGUARD_ALLOW_INSECURE_HTTP=false",
    "AGENTGUARD_INGEST_URL=http://127.0.0.1:8000/v1/ingest",
    "OPENAI_API_KEY="
)
[IO.File]::WriteAllLines($envPath, $lines, [Text.UTF8Encoding]::new($false))
Write-Output "DEV_BOOTSTRAP=PASS"
Write-Output "ENV_FILE=$envPath"
Write-Output "SECRET_DIRECTORY=$secretDir"
Write-Output "WARNING=local development only; generated secret values were not printed"
