param(
    [ValidateSet("V16", "V17", "V18", "V19", "V20")]
    [string]$ReleaseLine = "V16",
    [switch]$SkipDockerLive,
    [switch]$SkipBackupRestore,
    [string]$Python = "py",
    [string]$ScoutImage = "local://agentguard-agentguard-server:latest",
    [string]$ScoutTriagePath = "security\v9-scout-triage.json",
    [string]$V16EvidencePath = "artifacts\v16-final-live-evidence.json",
    [string]$SbomPath = "artifacts\agentguard-v16-sbom.cyclonedx.json",
    [string]$ExpectedImageDigest = "sha256:b845044e02af02f1052a1cd657221f12c950eafea502fe92165688f98716fb2c",
    [string]$V17EvidencePath = "artifacts\v17-final-live-evidence.json",
    [string]$V17SbomPath = "artifacts\agentguard-v17-sbom.cyclonedx.json",
    [string]$ExpectedV17ImageDigest = "",
    [string]$V19EvidencePath = "artifacts\v19-final-live-evidence.json",
    [string]$V19FailClosedPath = "artifacts\v19-fail-closed-matrix.json",
    [string]$V19PerformancePath = "artifacts\v19-performance-evidence.json",
    [string]$V19DrPath = "artifacts\v19-dr-evidence.json",
    [string]$V19ManifestPath = "artifacts\v19-release-manifest.json",
    [switch]$RequireV19ScoutEvidence,
    [string]$V20EvidencePath = "artifacts\v20-final-live-evidence.json",
    [string]$V20FailClosedPath = "artifacts\v20-fail-closed-matrix.json",
    [string]$V20ToctouPath = "artifacts\v20-quorum-toctou.json",
    [string]$V20SecurityPath = "artifacts\v20-security-evidence.json",
    [string]$V20ManifestPath = "artifacts\v20-release-manifest.json",
    [switch]$RequireV20ScoutEvidence,
    [switch]$OperatorApprovedRiskException,
    [string]$RiskExceptionReference = ""
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot ".."))
if ($ReleaseLine -eq "V18") {
    & (Join-Path $PSScriptRoot "release-check-v18.ps1") -SkipDockerLive:$SkipDockerLive -SkipBackupRestore:$SkipBackupRestore -Python $Python -ExpectedImageDigest $ExpectedV17ImageDigest
    exit $LASTEXITCODE
}
if ($ReleaseLine -eq "V19") {
    & (Join-Path $PSScriptRoot "release-check-v19.ps1") -Python $Python -EvidencePath $V19EvidencePath -FailClosedPath $V19FailClosedPath -PerformancePath $V19PerformancePath -DrPath $V19DrPath -ManifestPath $V19ManifestPath -ExpectedImageDigest $ExpectedV17ImageDigest -RequireScoutEvidence:$RequireV19ScoutEvidence
    exit $LASTEXITCODE
}
if ($ReleaseLine -eq "V20") {
    & (Join-Path $PSScriptRoot "release-check-v20.ps1") -Python $Python -EvidencePath $V20EvidencePath -FailClosedPath $V20FailClosedPath -ToctouPath $V20ToctouPath -SecurityPath $V20SecurityPath -ManifestPath $V20ManifestPath -RequireScoutEvidence:$RequireV20ScoutEvidence
    exit $LASTEXITCODE
}
Set-Location $repo
if ($ReleaseLine -eq "V17") {
    & (Join-Path $PSScriptRoot "release-check-v17.ps1") -SkipDockerLive:$SkipDockerLive -SkipBackupRestore:$SkipBackupRestore -Python $Python -ScoutImage $ScoutImage -ScoutTriagePath $ScoutTriagePath -EvidencePath $V17EvidencePath -SbomPath $V17SbomPath -ExpectedImageDigest $ExpectedV17ImageDigest
    exit $LASTEXITCODE
}
$env:PYTHONPATH = "$repo\sdk\python\src;$repo\server\src"
Write-Output "release_check=START"

function Require-ReleaseValue {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if (-not $Condition) { throw "V16 release evidence failed: $Message" }
}

git -c safe.directory=$repo status --short | Out-Null
if (-not (Test-Path VERSION)) { throw "VERSION is missing" }
if (-not (Test-Path requirements.lock)) { throw "requirements.lock is missing" }
$testTemp = Join-Path $repo ".pytest-tmp-release-check"
if (Test-Path -LiteralPath $testTemp) { Remove-Item -LiteralPath $testTemp -Recurse -Force }
try {
    & $Python -m compileall -q server/src sdk/python/src examples
    if ($LASTEXITCODE -ne 0) { throw "compile failed" }
    & $Python -m pytest -q -p no:cacheprovider --basetemp $testTemp --ignore-glob='*_live.py'
    if ($LASTEXITCODE -ne 0) { throw "regression tests failed" }
    & $Python -m pytest -q -p no:cacheprovider --basetemp $testTemp tests/test_security_gate.py tests/test_evaluation.py tests/test_evaluation_api.py tests/test_evaluation_cli.py
    if ($LASTEXITCODE -ne 0) { throw "security regression tests failed" }
    & $Python -m bandit -q -r server/src sdk/python/src examples
    if ($LASTEXITCODE -ne 0) { throw "Bandit failed" }
    & $Python -m pip_audit --local
    if ($LASTEXITCODE -ne 0) { throw "pip-audit failed" }
    & (Join-Path $PSScriptRoot "secret-scan.ps1")
    if ($LASTEXITCODE -ne 0) { throw "secret scan failed" }
} finally {
    if (Test-Path -LiteralPath $testTemp) { Remove-Item -LiteralPath $testTemp -Recurse -Force }
}

Write-Output "v16_evidence=START"
$v16EvidenceFile = Join-Path $repo $V16EvidencePath
Require-ReleaseValue (Test-Path -LiteralPath $v16EvidenceFile) "structured evidence is missing: $V16EvidencePath"
try {
    $v16Evidence = Get-Content -LiteralPath $v16EvidenceFile -Raw | ConvertFrom-Json
} catch {
    throw "V16 release evidence is not valid JSON: $V16EvidencePath"
}
Require-ReleaseValue ([string]$v16Evidence.schema_version -eq "agentguard-v16-release-evidence-v1") "unexpected evidence schema"
Require-ReleaseValue (-not [string]::IsNullOrWhiteSpace([string]$v16Evidence.timestamp)) "evidence timestamp is missing"
Require-ReleaseValue (-not [string]::IsNullOrWhiteSpace([string]$v16Evidence.harness)) "evidence harness is missing"
Require-ReleaseValue ([string]$v16Evidence.image_digest -eq $ExpectedImageDigest) "evidence image digest does not match expected V16 image"
Require-ReleaseValue ([string]$v16Evidence.migration_head -eq "0013_evidence_retention_archival") "migration head is not 0013_evidence_retention_archival"

Require-ReleaseValue ([string]$v16Evidence.python_3_13.status -eq "PASS") "Python 3.13 status is not PASS"
Require-ReleaseValue ([int]$v16Evidence.python_3_13.collected -eq 152 -and [int]$v16Evidence.python_3_13.passed -eq 152 -and [int]$v16Evidence.python_3_13.skipped -eq 0 -and [int]$v16Evidence.python_3_13.failed -eq 0 -and [int]$v16Evidence.python_3_13.errors -eq 0) "Python 3.13 counts are not 152 passed, 0 skipped, 0 failed, 0 errors"
Require-ReleaseValue ([string]$v16Evidence.python_3_12.status -eq "PASS") "Python 3.12 compatibility status is not PASS"
Require-ReleaseValue ([int]$v16Evidence.python_3_12.passed -eq 134 -and [int]$v16Evidence.python_3_12.skipped -eq 0 -and [int]$v16Evidence.python_3_12.failed -eq 0 -and [int]$v16Evidence.python_3_12.errors -eq 0 -and [int]$v16Evidence.python_3_12.deselected -eq 1) "Python 3.12 counts are not 134 passed, 0 skipped, 1 deselected"
Require-ReleaseValue ([string]$v16Evidence.security.status -eq "PASS" -and [int]$v16Evidence.security.passed -eq 9 -and [int]$v16Evidence.security.skipped -eq 0 -and [int]$v16Evidence.security.failed -eq 0 -and [int]$v16Evidence.security.errors -eq 0 -and [string]$v16Evidence.security.bandit -eq "PASS" -and [string]$v16Evidence.security.secret_scan -eq "PASS") "security evidence is not a complete PASS"
Require-ReleaseValue ([string]$v16Evidence.backup_restore.status -eq "PASS" -and [string]$v16Evidence.backup_restore.migration_head -eq "0013_evidence_retention_archival" -and [string]$v16Evidence.backup_restore.cold_retrieval -eq "PASS" -and [string]$v16Evidence.backup_restore.restored_archive_catalog -eq "PASS" -and [string]$v16Evidence.backup_restore.image_digest -eq $ExpectedImageDigest) "backup/restore evidence is not a complete PASS"
Require-ReleaseValue ([string]$v16Evidence.scout.status -eq "PASS" -and [int]$v16Evidence.scout.critical -eq 0 -and [int]$v16Evidence.scout.high -eq 0 -and [int]$v16Evidence.scout.kev -eq 0) "Scout vulnerability/KEV evidence is not 0C/0H/0KEV PASS"
Require-ReleaseValue ([string]$v16Evidence.sbom.status -eq "PASS" -and [string]$v16Evidence.sbom.format -eq "CycloneDX" -and [int]$v16Evidence.sbom.components -eq 120 -and [string]$v16Evidence.sbom.image_digest -eq $ExpectedImageDigest) "SBOM evidence is not the verified 120-component V16 PASS"
Require-ReleaseValue (@($v16Evidence.scout.residuals) -contains "SUPPLY_CHAIN_LICENSE_REVIEW") "SUPPLY_CHAIN_LICENSE_REVIEW residual is not recorded"
Require-ReleaseValue (@($v16Evidence.scout.residuals) -contains "MISSING_SUPPLY_CHAIN_ATTESTATIONS") "MISSING_SUPPLY_CHAIN_ATTESTATIONS residual is not recorded"

$requiredV16Gates = @(
    "live_minio_outage",
    "live_minio_recovery",
    "durable_retry_to_succeeded",
    "live_multi_worker_race",
    "single_logical_archive",
    "double_purge_prevented",
    "crash_lease_reclaim",
    "stale_archive_purge_block",
    "v15_witness_unavailable_purge_block",
    "remote_ahead_purge_block",
    "backup_restore_cold_retrieval",
    "v3_source_of_truth_preservation",
    "runtime_db_least_privilege",
    "retention_db_least_privilege"
)
foreach ($gateName in $requiredV16Gates) {
    $gateProperty = @($v16Evidence.gates.PSObject.Properties | Where-Object { $_.Name -eq $gateName }) | Select-Object -First 1
    Require-ReleaseValue ($null -ne $gateProperty) "required gate is missing: $gateName"
    $gate = $gateProperty.Value
    Require-ReleaseValue ([string]$gate.result -eq "PASS") "required gate is not PASS: $gateName"
    Require-ReleaseValue (-not [string]::IsNullOrWhiteSpace([string]$gate.timestamp)) "gate timestamp is missing: $gateName"
    Require-ReleaseValue (-not [string]::IsNullOrWhiteSpace([string]$gate.harness_version)) "gate harness version is missing: $gateName"
    Require-ReleaseValue ([string]$gate.image_digest -eq $ExpectedImageDigest) "gate image digest does not match V16 image: $gateName"
}

$sbomFile = Join-Path $repo $SbomPath
Require-ReleaseValue (Test-Path -LiteralPath $sbomFile) "SBOM file is missing: $SbomPath"
try {
    $sbom = Get-Content -LiteralPath $sbomFile -Raw | ConvertFrom-Json
} catch {
    throw "SBOM is not valid JSON: $SbomPath"
}
$sbomPurl = [string]$sbom.metadata.component.purl
Require-ReleaseValue ($sbomPurl -match [regex]::Escape($ExpectedImageDigest)) "SBOM image component does not match expected V16 image digest"
Require-ReleaseValue (@($sbom.components).Count -eq 120) "SBOM component count is not 120"
Write-Output "v16_evidence=PASS"

if ($SkipDockerLive) { Write-Output "docker_live=UNAVAILABLE" } else { docker compose config --quiet; Write-Output "docker_config=PASS" }
if ($SkipBackupRestore) { Write-Output "backup_restore=UNAVAILABLE" }

$triagePath = Join-Path $repo $ScoutTriagePath
if (-not (Test-Path -LiteralPath $triagePath)) { throw "Scout triage policy is missing: $ScoutTriagePath" }
$scoutReport = Join-Path $repo "artifacts\v9-scout-critical-high.sarif"
$scoutFixedReport = Join-Path $repo "artifacts\v9-scout-fixable-critical-high.sarif"
$scoutKevReport = Join-Path $repo "artifacts\v9-scout-cisa-kev.sarif"
$scoutPolicyReport = Join-Path $repo "artifacts\v9-scout-policy.json"
if (-not (Test-Path (Split-Path -Parent $scoutReport))) { New-Item -ItemType Directory -Path (Split-Path -Parent $scoutReport) | Out-Null }

Write-Output "docker_scout=START"
& docker scout quickview $ScoutImage
if ($LASTEXITCODE -ne 0) { throw "Docker Scout quickview failed" }
& docker scout cves $ScoutImage --only-severity critical,high --format sarif --output $scoutReport
if ($LASTEXITCODE -ne 0) { throw "Docker Scout CVE scan failed" }
& docker scout cves $ScoutImage --only-fixed --only-severity critical,high --format sarif --output $scoutFixedReport
if ($LASTEXITCODE -ne 0) { throw "Docker Scout fixable CVE scan failed" }
& docker scout cves $ScoutImage --only-cisa-kev --format sarif --output $scoutKevReport
if ($LASTEXITCODE -ne 0) { throw "Docker Scout CISA KEV scan failed" }

$triage = Get-Content -LiteralPath $triagePath -Raw | ConvertFrom-Json
$triageByCve = @{}
foreach ($finding in $triage.findings) { $triageByCve[$finding.cve] = $finding }
$sarif = Get-Content -LiteralPath $scoutReport -Raw | ConvertFrom-Json
$results = @($sarif.runs | ForEach-Object { $_.results })
$fixedSarif = Get-Content -LiteralPath $scoutFixedReport -Raw | ConvertFrom-Json
$fixedResults = @($fixedSarif.runs | ForEach-Object { $_.results })
$fixedCves = @($fixedResults | ForEach-Object { [string]$_.ruleId } | Where-Object { $_ })
$kevSarif = Get-Content -LiteralPath $scoutKevReport -Raw | ConvertFrom-Json
$kevResults = @($kevSarif.runs | ForEach-Object { $_.results })
$rawCritical = 0
$rawHigh = 0
$untriaged = @()
$fixable = @()
$affectedNoFix = @()
foreach ($result in $results) {
    $cve = [string]$result.ruleId
    $finding = $triageByCve[$cve]
    $severity = if ($finding) { [string]$finding.severity } else {
        $match = [regex]::Match([string]$result.message.text, "Severity\s*:\s*(CRITICAL|HIGH)")
        if ($match.Success) { $match.Groups[1].Value } else { "UNKNOWN" }
    }
    if ($severity -eq "CRITICAL") { $rawCritical++ }
    if ($severity -eq "HIGH") { $rawHigh++ }
    if (-not $finding) { $untriaged += $cve; continue }
    if ($fixedCves -contains $cve) { $fixable += $finding }
    if ([string]$finding.disposition -eq "AFFECTED_NO_FIX") { $affectedNoFix += $finding }
}
$cisaKev = @($kevResults | ForEach-Object { [string]$_.ruleId } | Where-Object { $_ })
$unfixedTriaged = @($results | ForEach-Object {
    $candidate = $triageByCve[[string]$_.ruleId]
    if ($candidate -and [string]$candidate.disposition -in @("NOT_AFFECTED", "AFFECTED_NO_FIX")) { $candidate }
})
$policy = [ordered]@{
    schema_version = "agentguard-scout-policy-result-v1"
    image = $ScoutImage
    raw_findings = $results.Count
    raw_critical = $rawCritical
    raw_high = $rawHigh
    fixable_findings = $fixable.Count
    fixable_critical = @($fixable | Where-Object { $_.severity -eq "CRITICAL" }).Count
    fixable_high = @($fixable | Where-Object { $_.severity -eq "HIGH" }).Count
    unfixed_triaged_findings = $unfixedTriaged.Count
    untriaged_findings = $untriaged.Count
    untriaged_cves = @($untriaged)
    cisa_kev_findings = $cisaKev.Count
    cisa_kev_cves = @($cisaKev)
    affected_no_fix_findings = $affectedNoFix.Count
    affected_no_fix_cves = @($affectedNoFix | ForEach-Object { $_.cve })
    operator_approved_risk_exception = [bool]$OperatorApprovedRiskException
    risk_exception_reference = if ($OperatorApprovedRiskException) { $RiskExceptionReference } else { "" }
}
$policy | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $scoutPolicyReport -Encoding utf8
Write-Output "RAW_FINDINGS=$($policy.raw_findings)"
Write-Output "RAW_CRITICAL=$($policy.raw_critical)"
Write-Output "RAW_HIGH=$($policy.raw_high)"
Write-Output "FIXABLE_FINDINGS=$($policy.fixable_findings)"
Write-Output "FIXABLE_CRITICAL=$($policy.fixable_critical)"
Write-Output "FIXABLE_HIGH=$($policy.fixable_high)"
Write-Output "UNFIXED_TRIAGED_FINDINGS=$($policy.unfixed_triaged_findings)"
Write-Output "UNTRIAGED_FINDINGS=$($policy.untriaged_findings)"
Write-Output "CISA_KEV_FINDINGS=$($policy.cisa_kev_findings)"
Write-Output "AFFECTED_NO_FIX_FINDINGS=$($policy.affected_no_fix_findings)"

$policyBlockers = @()
if ($policy.fixable_critical -gt 0 -or $policy.fixable_high -gt 0) { $policyBlockers += "fixable Critical/High findings" }
if ($policy.untriaged_findings -gt 0) { $policyBlockers += "untriaged Critical/High findings" }
if ($policy.cisa_kev_findings -gt 0) { $policyBlockers += "CISA KEV findings" }
if ($policy.affected_no_fix_findings -gt 0) {
    if (-not $OperatorApprovedRiskException) { $policyBlockers += "AFFECTED_NO_FIX findings require operator-approved risk exception" }
    elseif ([string]::IsNullOrWhiteSpace($RiskExceptionReference)) { $policyBlockers += "risk exception reference is missing" }
}
if ($policyBlockers.Count -gt 0) {
    Write-Output "release_check=BLOCKED"
    throw ("V9 vulnerability policy blocked release: " + ($policyBlockers -join "; "))
}
Write-Output "release_check=PASS"
