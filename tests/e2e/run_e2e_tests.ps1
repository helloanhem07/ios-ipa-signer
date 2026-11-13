<#
.SYNOPSIS
    Master E2E Test Suite PowerShell Runner for iOS IPA Signing System.

.DESCRIPTION
    Runs Tier 1 (Feature Coverage) and Tier 2 (Boundary & Corner Cases) E2E tests,
    manages the backend server lifecycle, records metrics, and produces execution reports.

.PARAMETER Tier
    Test tier to run ('1', '2', or 'all'). Default is 'all'.

.PARAMETER Verbose
    Enables verbose output displaying individual test names, execution times, and tracebacks.

.PARAMETER JsonOutput
    Destination file path for machine-readable JSON results. Defaults to tests/e2e/reports/results.json.

.PARAMETER ReportFile
    Destination file path for Markdown test summary. Defaults to tests/e2e/reports/summary.md.

.PARAMETER ServerUrl
    Target URL for backend REST API endpoints. Defaults to http://127.0.0.1:8000.

.PARAMETER SkipServerSpawn
    Assume backend server is already running; bypass auto-spawning.

.PARAMETER Filter
    Filter test cases matching regex or substring in class or method name.

.PARAMETER Timeout
    Timeout in seconds for server readiness polling and job completion. Defaults to 30.

.EXAMPLE
    .\tests\e2e\run_e2e_tests.ps1
    .\tests\e2e\run_e2e_tests.ps1 -Tier 1 -Verbose
    .\tests\e2e\run_e2e_tests.ps1 -SkipServerSpawn -ServerUrl "http://127.0.0.1:8000"
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("1", "2", "all")]
    [string]$Tier = "all",

    [switch]$VerboseOutput,

    [string]$JsonOutput = "tests/e2e/reports/results.json",

    [string]$ReportFile = "tests/e2e/reports/summary.md",

    [string]$ServerUrl = "http://127.0.0.1:8000",

    [switch]$SkipServerSpawn,

    [string]$Filter = "",

    [int]$Timeout = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$RunnerScript = Join-Path $PSScriptRoot "run_e2e_tests.py"

if (-not (Test-Path -Path $RunnerScript)) {
    Write-Error "E2E runner script not found at: $RunnerScript"
    exit 1
}

$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) {
    $PythonExe = "python"
}

$ArgsList = @(
    $RunnerScript,
    "--tier", $Tier,
    "--json-output", $JsonOutput,
    "--report-file", $ReportFile,
    "--server-url", $ServerUrl,
    "--timeout", $Timeout.ToString()
)

if ($VerboseOutput.IsPresent -or $PSBoundParameters.ContainsKey('Verbose')) {
    $ArgsList += "--verbose"
}

if ($SkipServerSpawn.IsPresent) {
    $ArgsList += "--skip-server-spawn"
}

if ($Filter) {
    $ArgsList += @("--filter", $Filter)
}

& $PythonExe @ArgsList
$ExitCode = $LASTEXITCODE

exit $ExitCode
