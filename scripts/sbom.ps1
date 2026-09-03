param([string]$Image = "agentguard-agentguard-server", [string]$OutputPath = "artifacts\agentguard-sbom.cyclonedx.json")
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot ".."))
$target = [IO.Path]::GetFullPath((Join-Path $repo $OutputPath))
if (-not $target.StartsWith($repo.Path, [StringComparison]::OrdinalIgnoreCase)) { throw "SBOM path must stay inside the repository" }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
docker scout sbom --format cyclonedx --output $target "local://$Image"
if (-not (Test-Path -LiteralPath $target)) { throw "Docker Scout did not create an SBOM" }
$relative = $target.Substring($repo.Path.Length).TrimStart('\','/')
Write-Output "sbom=PASS path=$relative"
