<#
.SYNOPSIS
    Automated Standalone Verification Harness for iOS IPA Signing Pipeline.

.DESCRIPTION
    Validates end-to-end signing workflow against a live FastAPI backend:
      1. Health check (GET /api/v1/health)
      2. Job submission with fixtures (POST /api/v1/jobs)
      3. Polling job status (GET /api/v1/jobs/{job_id})
      4. Downloading signed IPA artifact (GET /api/v1/downloads/{job_id}/signed.ipa)
      5. OTA manifest Apple DTD compliance (GET /api/v1/ota/{job_id}/manifest.plist)
      6. OTA Safari 1-tap install landing page (GET /api/v1/ota/{job_id}/install)

.PARAMETER ServerUrl
    Target URL of the running backend server. Defaults to http://127.0.0.1:8000.

.PARAMETER FixturesDir
    Optional custom directory containing mock test assets.

.PARAMETER AutoStart
    Automatically spawn the backend server subprocess if it is not currently running.

.PARAMETER Timeout
    Timeout in seconds for server readiness polling and signing operations.

.PARAMETER JsonOutput
    Destination path for machine-readable JSON verification results.

.EXAMPLE
    .\tests\verify_signing_pipeline.ps1
    .\tests\verify_signing_pipeline.ps1 -ServerUrl "http://127.0.0.1:8000" -AutoStart
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$ServerUrl = "http://127.0.0.1:8000",

    [Parameter(Position = 1)]
    [string]$FixturesDir = "",

    [switch]$AutoStart,

    [int]$Timeout = 30,

    [string]$JsonOutput = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$PyScript = Join-Path $PSScriptRoot "verify_signing_pipeline.py"

if (-not (Test-Path -Path $PyScript)) {
    Write-Error "Verification harness Python script not found at: $PyScript"
    exit 1
}

$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) {
    $PythonExe = "python"
}

$ArgsList = @(
    $PyScript,
    "--server-url", $ServerUrl,
    "--timeout", $Timeout.ToString()
)

if ($AutoStart.IsPresent) {
    $ArgsList += "--auto-start"
}

if ($FixturesDir) {
    $ArgsList += @("--fixtures-dir", $FixturesDir)
}

if ($JsonOutput) {
    $ArgsList += @("--json", $JsonOutput)
}

Write-Host "==> Executing verification harness: $ServerUrl (Endpoint: /api/v1/health)" -ForegroundColor Cyan
& $PythonExe @ArgsList
$ExitCode = $LASTEXITCODE

if ($ExitCode -eq 0) {
    Write-Host "==> Signing pipeline verification SUCCEEDED." -ForegroundColor Green
} else {
    Write-Host "==> Signing pipeline verification FAILED (Exit code: $ExitCode)." -ForegroundColor Red
}

exit $ExitCode
