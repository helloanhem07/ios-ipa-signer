<#
.SYNOPSIS
    Generates offline test fixtures (mock.p12, embedded.mobileprovision, mock_unsigned.ipa).

.DESCRIPTION
    Creates zero-external-dependency mock certificate assets and application bundles
    required for local verification, signing pipeline integration tests, and E2E suites.
    Target files:
      - mock.p12: Self-signed PKCS#12 certificate with private key
      - embedded.mobileprovision: Apple ASN.1 CMS SignedData provisioning profile
      - mock_unsigned.ipa: Unsigned iOS application package with ARM64 Mach-O binary

.PARAMETER OutputDir
    Destination folder for generated fixtures. Defaults to tests/fixtures.

.PARAMETER Password
    Password for the mock.p12 certificate. Defaults to 'test1234'.

.PARAMETER Force
    Regenerate fixtures even if they already exist.

.EXAMPLE
    .\scripts\generate_fixtures.ps1
    .\scripts\generate_fixtures.ps1 -OutputDir "tests/fixtures" -Password "test1234" -Force
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$OutputDir = "",

    [Parameter(Position = 1)]
    [string]$Password = "test1234",

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $OutputDir) {
    $OutputDir = Join-Path $PSScriptRoot "..\tests\fixtures"
}

$ResolvedOutputDir = [System.IO.Path]::GetFullPath($OutputDir)
if (-not (Test-Path -Path $ResolvedOutputDir)) {
    New-Item -ItemType Directory -Path $ResolvedOutputDir -Force | Out-Null
}

Write-Host "==> Generating offline test fixtures in: $ResolvedOutputDir" -ForegroundColor Cyan

$P12Target = Join-Path $ResolvedOutputDir "mock.p12"
$ProvTarget = Join-Path $ResolvedOutputDir "embedded.mobileprovision"
$IpaTarget = Join-Path $ResolvedOutputDir "mock_unsigned.ipa"

$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) {
    $PythonExe = "python"
}

$PyScript = "import sys; from pathlib import Path; repo_root = Path(r'$RepoRoot'); sys.path.insert(0, str(repo_root)); from tests.e2e.harness.fixture_manager import FixtureManager; mgr = FixtureManager(output_dir=Path(r'$ResolvedOutputDir')); fixtures = mgr.ensure_fixtures(); print('Fixtures ready:', fixtures)"
& $PythonExe -c $PyScript
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to generate fixtures via Python harness (exit code $LASTEXITCODE)"
    exit $LASTEXITCODE
}

Write-Host "==> Verifying fixture presence:" -ForegroundColor Green
$Files = @("mock.p12", "embedded.mobileprovision", "mock_unsigned.ipa")
foreach ($File in $Files) {
    $FilePath = Join-Path $ResolvedOutputDir $File
    if (Test-Path -Path $FilePath) {
        $Size = (Get-Item -Path $FilePath).Length
        Write-Host "  [OK] $File ($Size bytes)" -ForegroundColor Green
    } else {
        Write-Error "Missing expected fixture file: $FilePath"
        exit 1
    }
}

Write-Host "==> Fixture generation successfully completed." -ForegroundColor Green
