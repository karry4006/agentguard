$ErrorActionPreference = "Stop"
$patterns = @(
    '(?i)sk-[A-Za-z0-9_-]{20,}',
    '\bagk_[A-Za-z0-9_-]{40,}\b',
    '-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----',
    '(?i)postgres(?:ql)?://[^\s"''`]+:[^\s"''`]+@'
)
$files = @()
foreach ($pattern in $patterns) {
    $files += @(rg -l --hidden --glob '!.env' --glob '!.env.*' --glob '!**/__pycache__/**' --glob '!.tmp/**' --glob '!.pytest-tmp-*/**' --glob '!.pip-audit-cache*/**' -- $pattern . 2>$null)
}
$unique = @($files | Sort-Object -Unique)
$allowlisted = @(
    'tests\test_otlp_gateway.py',
    'tests\test_opentelemetry.py',
    'tests\test_sdk.py'
)
$unexpected = @($unique | Where-Object {
    $relative = $_.TrimStart('.','\','/').Replace('/','\')
    $allowlisted -notcontains $relative
})
if ($unexpected.Count -gt 0) {
    Write-Error "secret-pattern scan found $($unexpected.Count) unexpected file(s); inspect without printing values"
}
Write-Output "secret_scan=PASS unexpected_files=0 allowlisted_test_files=$($unique.Count - $unexpected.Count)"
exit 0
