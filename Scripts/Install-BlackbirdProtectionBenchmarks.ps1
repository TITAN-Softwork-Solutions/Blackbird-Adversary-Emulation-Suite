param(
    [string]$BkaesRoot = "",
    [switch]$Force,
    [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$sourceManifest = Join-Path $repoRoot "manifests\blackbird.protection.json"

if (-not (Test-Path -LiteralPath $sourceManifest)) {
    throw "Blackbird protection manifest was not found: $sourceManifest"
}

try {
    $null = Get-Content -LiteralPath $sourceManifest -Raw | ConvertFrom-Json
}
catch {
    throw "Blackbird protection manifest is not valid JSON: $sourceManifest. $($_.Exception.Message)"
}

function Copy-ManifestIfNeeded {
    param(
        [string]$Source,
        [string]$Destination,
        [switch]$ForceCopy
    )

    $destinationDirectory = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $destinationDirectory)) {
        New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    }

    if (Test-Path -LiteralPath $Destination) {
        $sourceHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash
        if ($sourceHash -eq $destinationHash) {
            return $false
        }
        if (-not $ForceCopy) {
            throw "Target manifest already exists and differs: $Destination. Re-run with -Force to replace it."
        }
    }

    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    return $true
}

function Write-RunHint {
    param([string]$SuiteRoot)

    Write-Host "Run the protection audit with:"
    Write-Host "  BlackbirdRunner.exe --detection-audit --suite-root `"$SuiteRoot`" --manifest `"manifests\blackbird.protection.json`""
}

if ($ValidateOnly -or [string]::IsNullOrWhiteSpace($BkaesRoot)) {
    Write-Host "Blackbird protection manifest is valid: $sourceManifest"
    Write-Host "No native benchmark sample build is required; the anti-VM probe uses BlackbirdRunner.exe directly."
    Write-RunHint -SuiteRoot $repoRoot
    return
}

if (-not (Test-Path -LiteralPath $BkaesRoot)) {
    if (-not $Force) {
        throw "BKAES root does not exist: $BkaesRoot. Create it or re-run with -Force."
    }
    New-Item -ItemType Directory -Path $BkaesRoot -Force | Out-Null
}

$targetRoot = (Resolve-Path -LiteralPath $BkaesRoot).Path
$targetManifest = Join-Path $targetRoot "manifests\blackbird.protection.json"
$legacyManifest = Join-Path $targetRoot "benchmarks\manifest.json"

$copiedPrimary = Copy-ManifestIfNeeded -Source $sourceManifest -Destination $targetManifest -ForceCopy:$Force
$copiedLegacy = Copy-ManifestIfNeeded -Source $sourceManifest -Destination $legacyManifest -ForceCopy:$Force

Write-Host "Blackbird protection benchmarks are installed under $targetRoot"
Write-Host "Source manifest: $sourceManifest"
Write-Host "Protection manifest: $targetManifest"
Write-Host "Legacy benchmark shim: $legacyManifest"
if (-not $copiedPrimary -and -not $copiedLegacy) {
    Write-Host "Existing manifests already matched the AES source."
}
Write-Host "No native benchmark sample build is required; the anti-VM probe uses BlackbirdRunner.exe directly."
Write-RunHint -SuiteRoot $targetRoot
