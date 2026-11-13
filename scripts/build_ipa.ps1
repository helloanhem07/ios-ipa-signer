<#
================================================================================
scripts/build_ipa.ps1
Cross-Platform iOS IPA Build, Validation, Packaging & CI Automation Script
Compatible with Windows PowerShell 5.1 and PowerShell Core 7+ (Windows, macOS, Linux)
================================================================================

.SYNOPSIS
    Cross-platform iOS IPA packaging, cryptographic asset validation, and GitHub
    Actions CI/CD remote build dispatch automation.

.DESCRIPTION
    This script provides three operational modes:
    1. Cryptographic Pre-Flight Validation:
       Validates PKCS#12 (.p12/.pfx) code signing certificates and Apple Provisioning
       Profiles (.mobileprovision), checking passwords, private key presence,
       code-signing EKUs, UUIDs, team IDs, and expiration dates.
    2. Local Application Packaging:
       Packages a pre-compiled iOS application bundle (.app) into a standard iOS .ipa
       zip archive (Payload/<AppName>.app/) with forward-slash normalized zip entry paths
       for 100% Apple platform compliance.
    3. Remote CI/CD Automation Dispatch:
       Triggers the GitHub Actions remote build workflow (.github/workflows/build-ipa.yml)
       via the GitHub CLI (gh workflow run), passing build configuration and export options,
       with detailed fallback diagnostics when 'gh' or authentication is missing.

.PARAMETER P12Path
    Path to Apple PKCS#12 code-signing certificate (.p12 / .pfx).
.PARAMETER P12Password
    Password for the PKCS#12 certificate.
.PARAMETER ProfilePath
    Path to Apple provisioning profile (.mobileprovision).
.PARAMETER AppBundlePath
    Path to pre-compiled .app directory for local packaging into an .ipa archive.
.PARAMETER Configuration
    Build configuration: Release (default) or Debug.
.PARAMETER ExportMethod
    IPA export method: development (default), ad-hoc, enterprise, app-store.
.PARAMETER OutputDir
    Destination folder for output .ipa (default: build/export).
.PARAMETER TriggerRemote
    Switch to dispatch remote GitHub Actions build workflow (.github/workflows/build-ipa.yml).
.PARAMETER Branch
    Target Git branch for remote workflow dispatch (default: main).
.PARAMETER Help
    Displays interactive usage guide, CI secrets reference, and remote setup instructions.

.EXAMPLE
    # Validate signing certificate and provisioning profile
    .\scripts\build_ipa.ps1 -P12Path certs\dev.p12 -P12Password "Secret123" -ProfilePath certs\dev.mobileprovision

.EXAMPLE
    # Package local .app bundle into .ipa
    .\scripts\build_ipa.ps1 -AppBundlePath build\iOSApp.app -OutputDir dist\ipa

.EXAMPLE
    # Trigger remote GitHub Actions build
    .\scripts\build_ipa.ps1 -TriggerRemote -Branch main -Configuration Release -ExportMethod development
#>

[CmdletBinding(DefaultParameterSetName = "Default")]
param(
    [Parameter(ParameterSetName = "LocalPackage")]
    [Parameter(ParameterSetName = "ValidateOnly")]
    [Parameter(ParameterSetName = "RemoteTrigger")]
    [Parameter(ParameterSetName = "Default")]
    [Alias("p", "p12")]
    [string]$P12Path,

    [Parameter(ParameterSetName = "LocalPackage")]
    [Parameter(ParameterSetName = "ValidateOnly")]
    [Parameter(ParameterSetName = "RemoteTrigger")]
    [Parameter(ParameterSetName = "Default")]
    [Alias("w", "password")]
    [string]$P12Password,

    [Parameter(ParameterSetName = "LocalPackage")]
    [Parameter(ParameterSetName = "ValidateOnly")]
    [Parameter(ParameterSetName = "RemoteTrigger")]
    [Parameter(ParameterSetName = "Default")]
    [Alias("m", "profile")]
    [string]$ProfilePath,

    [Parameter(ParameterSetName = "LocalPackage")]
    [Parameter(ParameterSetName = "Default")]
    [Alias("app")]
    [string]$AppBundlePath,

    [Parameter()]
    [Alias("c", "config")]
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",

    [Parameter()]
    [Alias("e", "method")]
    [ValidateSet("development", "ad-hoc", "enterprise", "app-store")]
    [string]$ExportMethod = "development",

    [Parameter()]
    [Alias("o", "output")]
    [string]$OutputDir = "build/export",

    [Parameter(ParameterSetName = "RemoteTrigger")]
    [Alias("remote")]
    [switch]$TriggerRemote,

    [Parameter()]
    [Alias("b")]
    [string]$Branch = "main",

    [Parameter()]
    [Alias("h")]
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# ==============================================================================
# Help & Secrets Reference Documentation
# ==============================================================================
function Show-HelpManual {
    Write-Host @"
================================================================================
  scripts/build_ipa.ps1 - Cross-Platform iOS IPA Packaging & CI Automation
================================================================================

USAGE:
  1. Cryptographic Asset Validation:
     .\scripts\build_ipa.ps1 -P12Path <path> -P12Password <pwd> -ProfilePath <path>

  2. Local .app Bundle to .ipa Packaging:
     .\scripts\build_ipa.ps1 -AppBundlePath <path.app> [-ProfilePath <path>] [-OutputDir <dir>]

  3. Remote GitHub Actions CI/CD Build Dispatch:
     .\scripts\build_ipa.ps1 -TriggerRemote [-Branch <branch>] [-Configuration Release|Debug] [-ExportMethod <method>]

PARAMETERS:
  -P12Path, -p          Path to PKCS#12 signing certificate (.p12 / .pfx)
  -P12Password, -w      Password for the .p12 certificate
  -ProfilePath, -m      Path to Apple provisioning profile (.mobileprovision)
  -AppBundlePath, -app  Path to pre-compiled .app directory
  -Configuration, -c    Build configuration: Release | Debug (default: Release)
  -ExportMethod, -e     Export method: development | ad-hoc | enterprise | app-store (default: development)
  -OutputDir, -o        Output directory for exported .ipa (default: build/export)
  -TriggerRemote        Switch to dispatch GitHub Actions remote build workflow
  -Branch, -b           Target branch for remote dispatch (default: main)
  -Help, -h             Show this help menu and CI secrets configuration guide

--------------------------------------------------------------------------------
GITHUB ACTIONS REQUIRED SECRETS:
--------------------------------------------------------------------------------
The remote workflow (.github/workflows/build-ipa.yml) requires these repository secrets:
(Configure in GitHub: Repository Settings -> Secrets and variables -> Actions)

  1. P12_BASE64:
     Base64-encoded PKCS#12 certificate (.p12 / .pfx) with private key.
     Encode on Windows PowerShell:
       [Convert]::ToBase64String([IO.File]::ReadAllBytes("path\to\cert.p12")) | Set-Clipboard
     Encode on macOS / Linux:
       base64 -i cert.p12 | tr -d '\n'

  2. P12_PASSWORD:
     Password protecting the .p12 certificate.

  3. PROVISIONING_PROFILE_BASE64:
     Base64-encoded Apple Provisioning Profile (.mobileprovision).
     Encode on Windows PowerShell:
       [Convert]::ToBase64String([IO.File]::ReadAllBytes("path\to\app.mobileprovision")) | Set-Clipboard
     Encode on macOS / Linux:
       base64 -i app.mobileprovision | tr -d '\n'

  4. DEVELOPMENT_TEAM (Optional):
     10-character Apple Developer Team ID (e.g. ABCDE12345).

--------------------------------------------------------------------------------
PROVISION SECRETS AUTOMATICALLY VIA GITHUB CLI:
--------------------------------------------------------------------------------
  `$p12 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("certs\developer.p12"))
  gh secret set P12_BASE64 -b "`$p12"
  gh secret set P12_PASSWORD -b "YourPasswordHere"
  `$prof = [Convert]::ToBase64String([IO.File]::ReadAllBytes("certs\embedded.mobileprovision"))
  gh secret set PROVISIONING_PROFILE_BASE64 -b "`$prof"

--------------------------------------------------------------------------------
INITIAL GIT REPOSITORY SETUP & REMOTE PUSH:
--------------------------------------------------------------------------------
  git init
  git branch -M main
  git remote add origin https://github.com/<owner>/<repo>.git
  git add .
  git commit -m "feat(ci): configure iOS IPA remote build pipeline and packaging automation"
  git push -u origin main
================================================================================
"@
}

# ==============================================================================
# Assembly Loading Helper
# ==============================================================================
function Initialize-RequiredAssemblies {
    try {
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
    } catch { }
    try {
        Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    } catch { }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    } catch { }
}

# ==============================================================================
# PKCS#12 (.p12) Certificate Cryptographic Validation
# ==============================================================================
function Test-P12Certificate {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][string]$Password = ""
    )

    Write-Host "==> Validating PKCS#12 Certificate: $Path" -ForegroundColor Cyan

    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        Write-Error "Certificate file not found: $Path"
        return $false
    }

    $fileInfo = Get-Item -Path $Path
    if ($fileInfo.Length -eq 0) {
        Write-Error "Certificate file is empty (0 bytes): $Path"
        return $false
    }

    Initialize-RequiredAssemblies

    try {
        $keyStorageFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Path, $Password, $keyStorageFlags)
    }
    catch [System.Security.Cryptography.CryptographicException] {
        $msg = $_.Exception.Message
        if ($msg -match "password" -or $_.Exception.HResult -eq -2147024810) {
            Write-Error "Failed to unlock .p12 certificate: Incorrect password."
        } else {
            Write-Error "Failed to decode .p12 certificate: Invalid format or corrupted archive ($msg)."
        }
        return $false
    }
    catch {
        Write-Error "Unexpected error reading .p12 certificate: $($_.Exception.Message)"
        return $false
    }

    # Extract Certificate Details
    $subject = $cert.Subject
    $thumbprint = $cert.Thumbprint
    $notAfter = $cert.NotAfter
    $hasPrivateKey = $cert.HasPrivateKey

    Write-Host "    Subject:        $subject"
    Write-Host "    Thumbprint:     $thumbprint"
    Write-Host "    Expiration:     $notAfter"
    Write-Host "    Has PrivateKey: $hasPrivateKey"

    # Validate Private Key Presence
    if (-not $hasPrivateKey) {
        Write-Warning "Certificate does NOT contain a private key! It cannot be used for iOS code signing."
    }

    # Validate Expiration
    if ($notAfter -lt [DateTime]::UtcNow) {
        Write-Warning "Certificate EXPIRED on $notAfter (UTC: $([DateTime]::UtcNow))!"
    } else {
        Write-Host "    Status:         Active / Valid" -ForegroundColor Green
    }

    # Check for Code Signing EKU (1.3.6.1.5.5.7.3.3 or Apple-specific EKUs)
    $hasCodeSigningEku = $false
    foreach ($ext in $cert.Extensions) {
        if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($oid in $ext.EnhancedKeyUsages) {
                if ($oid.Value -eq "1.3.6.1.5.5.7.3.3" -or $oid.Value -like "1.2.840.113635.*") {
                    $hasCodeSigningEku = $true
                    break
                }
            }
        }
    }
    if ($hasCodeSigningEku) {
        Write-Host "    Key Usage:      Code Signing Verified" -ForegroundColor Green
    } else {
        Write-Host "    Key Usage:      Standard Certificate"
    }

    return $true
}

# ==============================================================================
# Provisioning Profile (.mobileprovision) Decoding & Metadata Extraction
# ==============================================================================
function Test-ProvisioningProfile {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    Write-Host "==> Validating Provisioning Profile: $Path" -ForegroundColor Cyan

    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        Write-Error "Provisioning profile file not found: $Path"
        return $null
    }

    $rawBytes = [System.IO.File]::ReadAllBytes($Path)
    if ($rawBytes.Length -eq 0) {
        Write-Error "Provisioning profile file is empty (0 bytes): $Path"
        return $null
    }

    Initialize-RequiredAssemblies

    $xmlString = $null

    # Method 1: CMS SignedData Decapsulation via .NET SignedCms
    try {
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $cms.Decode($rawBytes)
        $xmlString = [System.Text.Encoding]::UTF8.GetString($cms.ContentInfo.Content)
    }
    catch {
        # Method 2: Resilient Fallback - Scan binary byte stream for XML plist boundary
        $rawAscii = [System.Text.Encoding]::ASCII.GetString($rawBytes)
        $startIdx = $rawAscii.IndexOf("<?xml")
        if ($startIdx -ge 0) {
            $endTag = "</plist>"
            $endIdx = $rawAscii.IndexOf($endTag, $startIdx)
            if ($endIdx -ge 0) {
                $xmlString = $rawAscii.Substring($startIdx, ($endIdx - $startIdx) + $endTag.Length)
            }
        }
    }

    if ([string]::IsNullOrEmpty($xmlString)) {
        Write-Error "Failed to extract XML property list from provisioning profile ($Path)."
        return $null
    }

    # Extract metadata properties via regex patterns
    $metadata = @{
        UUID = ""
        TeamID = ""
        AppID = ""
        BundleID = ""
        Name = ""
        ExpirationDate = ""
        RawXml = $xmlString
    }

    if ($xmlString -match "<key>UUID</key>\s*<string>([^<]+)</string>") {
        $metadata.UUID = $matches[1].Trim()
    }
    if ($xmlString -match "<key>TeamIdentifier</key>\s*<array>\s*<string>([^<]+)</string>") {
        $metadata.TeamID = $matches[1].Trim()
    }
    if ($xmlString -match "<key>application-identifier</key>\s*<string>([^<]+)</string>") {
        $metadata.AppID = $matches[1].Trim()
        $parts = $metadata.AppID.Split(".", 2)
        if ($parts.Length -eq 2) {
            $metadata.BundleID = $parts[1]
            if ([string]::IsNullOrEmpty($metadata.TeamID)) {
                $metadata.TeamID = $parts[0]
            }
        }
    }
    if ($xmlString -match "<key>Name</key>\s*<string>([^<]+)</string>") {
        $metadata.Name = $matches[1].Trim()
    }
    if ($xmlString -match "<key>ExpirationDate</key>\s*<(?:date|string)>([^<]+)</(?:date|string)>") {
        $metadata.ExpirationDate = $matches[1].Trim()
    }

    Write-Host "    Profile Name:   $($metadata.Name)"
    Write-Host "    Profile UUID:   $($metadata.UUID)"
    Write-Host "    Team ID:        $($metadata.TeamID)"
    Write-Host "    App Identifier: $($metadata.AppID)"
    Write-Host "    Bundle ID:      $($metadata.BundleID)"
    Write-Host "    Expiration:     $($metadata.ExpirationDate)"

    if (-not [string]::IsNullOrEmpty($metadata.ExpirationDate)) {
        try {
            $expDate = [DateTime]::Parse($metadata.ExpirationDate)
            if ($expDate -lt [DateTime]::UtcNow) {
                Write-Warning "Provisioning profile EXPIRED on $expDate!"
            } else {
                Write-Host "    Status:         Active / Valid" -ForegroundColor Green
            }
        } catch { }
    }

    return $metadata
}

# ==============================================================================
# Cross-Platform Forward-Slash Normalized ZIP Archive Creator
# ==============================================================================
function New-NormalizedIpaArchive {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDirectory,
        [Parameter(Mandatory = $true)][string]$DestinationZipPath
    )

    Initialize-RequiredAssemblies

    $destDir = [System.IO.Path]::GetDirectoryName($DestinationZipPath)
    if (-not [string]::IsNullOrEmpty($destDir) -and -not (Test-Path -Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    if (Test-Path -Path $DestinationZipPath) {
        Remove-Item -Path $DestinationZipPath -Force
    }

    Write-Host "--> Creating normalized ZIP archive: $DestinationZipPath"

    $zip = [System.IO.Compression.ZipFile]::Open($DestinationZipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $sourceDirInfo = New-Object System.IO.DirectoryInfo($SourceDirectory)
        $rootLen = $sourceDirInfo.FullName.TrimEnd('\', '/').Length + 1
        $files = [System.IO.Directory]::GetFiles($sourceDirInfo.FullName, "*", [System.IO.SearchOption]::AllDirectories)

        foreach ($file in $files) {
            # Convert Windows backslashes to standard forward slashes in ZIP entries
            $entryPath = $file.Substring($rootLen).Replace('\', '/')
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip,
                $file,
                $entryPath,
                [System.IO.Compression.CompressionLevel]::Optimal
            ) | Out-Null
        }
    }
    finally {
        $zip.Dispose()
    }
}

# ==============================================================================
# Local Packaging Engine (.app to .ipa)
# ==============================================================================
function Package-LocalAppBundle {
    param(
        [Parameter(Mandatory = $true)][string]$AppPath,
        [Parameter(Mandatory = $false)][string]$Profile,
        [Parameter(Mandatory = $true)][string]$OutDir
    )

    Write-Host "==> Initiating Local Application Packaging (.app -> .ipa)..." -ForegroundColor Cyan

    if (-not (Test-Path -Path $AppPath)) {
        Write-Error "App bundle directory not found: $AppPath"
        return $false
    }

    $appItem = Get-Item -Path $AppPath
    $appName = $appItem.Name
    if ($appName.EndsWith(".app", [System.StringComparison]::OrdinalIgnoreCase)) {
        $appNameClean = $appName.Substring(0, $appName.Length - 4)
    } else {
        $appNameClean = $appName
        $appName = "$appNameClean.app"
    }

    # Prepare temporary staging directory
    $stagingGuid = [System.Guid]::NewGuid().ToString("N")
    $tempBase = [System.IO.Path]::GetTempPath()
    $stagingDir = Join-Path -Path $tempBase -ChildPath "ipa_stage_$stagingGuid"
    $payloadDir = Join-Path -Path $stagingDir -ChildPath "Payload"
    $targetAppDir = Join-Path -Path $payloadDir -ChildPath $appName

    Write-Host "    Staging Directory: $stagingDir"

    try {
        New-Item -ItemType Directory -Path $targetAppDir -Force | Out-Null

        # Copy .app bundle contents
        Write-Host "--> Copying app bundle payload..."
        Copy-Item -Path (Join-Path -Path $AppPath -ChildPath "*") -Destination $targetAppDir -Recurse -Force

        # Optional Profile Injection
        if (-not [string]::IsNullOrEmpty($Profile) -and (Test-Path -Path $Profile -PathType Leaf)) {
            Write-Host "--> Injecting provisioning profile into app bundle: embedded.mobileprovision"
            $destProfile = Join-Path -Path $targetAppDir -ChildPath "embedded.mobileprovision"
            Copy-Item -Path $Profile -Destination $destProfile -Force
        }

        # Create output destination directory
        if (-not (Test-Path -Path $OutDir)) {
            New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
        }

        $ipaPath = Join-Path -Path $OutDir -ChildPath "$appNameClean.ipa"

        # Compress into normalized zip
        New-NormalizedIpaArchive -SourceDirectory $stagingDir -DestinationZipPath $ipaPath

        # Verify output
        if (Test-Path -Path $ipaPath -PathType Leaf) {
            $ipaItem = Get-Item -Path $ipaPath
            $sizeMb = [Math]::Round(($ipaItem.Length / 1MB), 2)

            # Compute SHA-256
            $sha256 = (Get-FileHash -Path $ipaPath -Algorithm SHA256).Hash

            Write-Host ""
            Write-Host "==================================================================" -ForegroundColor Green
            Write-Host "  LOCAL PACKAGING SUCCESSFUL" -ForegroundColor Green
            Write-Host "==================================================================" -ForegroundColor Green
            Write-Host "  IPA Output Path: $ipaPath"
            Write-Host "  Package Size:    $sizeMb MB ($($ipaItem.Length) bytes)"
            Write-Host "  SHA-256 Hash:    $sha256"
            Write-Host "=================================================================="
            return $true
        } else {
            Write-Error "Packaging completed but output .ipa was not created at $ipaPath."
            return $false
        }
    }
    finally {
        if (Test-Path -Path $stagingDir) {
            Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# ==============================================================================
# Remote CI/CD Trigger Subsystem (GitHub CLI Dispatch)
# ==============================================================================
function Invoke-RemoteBuildDispatch {
    param(
        [string]$TargetBranch,
        [string]$Config,
        [string]$Method
    )

    Write-Host "==================================================================" -ForegroundColor Cyan
    Write-Host "  GitHub Actions Remote Build Dispatch Subsystem" -ForegroundColor Cyan
    Write-Host "==================================================================" -ForegroundColor Cyan

    # 1. Check if 'gh' (GitHub CLI) is available
    $ghCommand = Get-Command -Name "gh" -ErrorAction SilentlyContinue

    if ($null -eq $ghCommand) {
        Write-Host ""
        Write-Host "======================================================================" -ForegroundColor Red
        Write-Host "[ERROR] GitHub CLI ('gh') is not installed or not found in system PATH." -ForegroundColor Red
        Write-Host "======================================================================" -ForegroundColor Red
        Write-Host "To dispatch remote iOS IPA builds automatically, install the GitHub CLI:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  • Windows:" -ForegroundColor Gray
        Write-Host "      winget install --id GitHub.cli" -ForegroundColor White
        Write-Host "      choco install gh" -ForegroundColor White
        Write-Host ""
        Write-Host "  • macOS:" -ForegroundColor Gray
        Write-Host "      brew install gh" -ForegroundColor White
        Write-Host ""
        Write-Host "  • Linux (Debian/Ubuntu):" -ForegroundColor Gray
        Write-Host "      sudo apt install gh" -ForegroundColor White
        Write-Host ""
        Write-Host "After installing, authenticate with your GitHub account:" -ForegroundColor Yellow
        Write-Host "  gh auth login" -ForegroundColor White
        Write-Host ""
        Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "ALTERNATIVE 1: Manual Trigger via GitHub Web UI" -ForegroundColor Yellow
        Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "1. Navigate to your repository in a web browser." -ForegroundColor Gray
        Write-Host "2. Click on the 'Actions' tab." -ForegroundColor Gray
        Write-Host "3. Select 'Build and Package iOS IPA' in the left workflow list." -ForegroundColor Gray
        Write-Host "4. Click 'Run workflow' on the right:" -ForegroundColor Gray
        Write-Host "   - Branch:              $TargetBranch" -ForegroundColor White
        Write-Host "   - Xcode Configuration: $Config" -ForegroundColor White
        Write-Host "   - IPA Export Method:   $Method" -ForegroundColor White
        Write-Host ""
        Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "ALTERNATIVE 2: Trigger via GitHub REST API (cURL)" -ForegroundColor Yellow
        Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "curl -X POST \" -ForegroundColor Gray
        Write-Host "  -H `"Authorization: Bearer <YOUR_GITHUB_TOKEN>`" \" -ForegroundColor Gray
        Write-Host "  -H `"Accept: application/vnd.github+json`" \" -ForegroundColor Gray
        Write-Host "  https://api.github.com/repos/<OWNER>/<REPO>/actions/workflows/build-ipa.yml/dispatches \" -ForegroundColor Gray
        Write-Host "  -d '{`"ref`":`"$TargetBranch`",`"inputs`":{`"build_configuration`":`"$Config`",`"export_method`":`"$Method`"}}'" -ForegroundColor Gray
        Write-Host "======================================================================" -ForegroundColor Red
        exit 1
    }

    # 2. Check GitHub CLI Authentication Status
    Write-Host "--> Verifying GitHub CLI authentication..." -ForegroundColor Gray
    $authCheck = & gh auth status 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "[WARNING] GitHub CLI is not authenticated." -ForegroundColor Yellow
        Write-Host "Please run the following command to authenticate:" -ForegroundColor Yellow
        Write-Host "  gh auth login" -ForegroundColor White
        exit 1
    }

    # 3. Trigger Remote Workflow Dispatch
    Write-Host "--> Dispatching build-ipa.yml on branch '$TargetBranch' (Config: $Config, Method: $Method)..." -ForegroundColor Green

    $dispatchArgs = @(
        "workflow", "run", "build-ipa.yml",
        "--ref", $TargetBranch,
        "-f", "build_configuration=$Config",
        "-f", "export_method=$Method"
    )

    & gh @dispatchArgs
    $dispatchExit = $LASTEXITCODE

    if ($dispatchExit -ne 0) {
        Write-Error "Failed to dispatch remote workflow. Verify that .github/workflows/build-ipa.yml is committed on '$TargetBranch'."
        exit $dispatchExit
    }

    Write-Host ""
    Write-Host "==================================================================" -ForegroundColor Green
    Write-Host "  REMOTE WORKFLOW DISPATCHED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "==================================================================" -ForegroundColor Green
    Write-Host "  Workflow: build-ipa.yml"
    Write-Host "  Branch:   $TargetBranch"
    Write-Host "  Config:   $Config"
    Write-Host "  Method:   $Method"
    Write-Host ""
    Write-Host "  Next steps to monitor the remote build:" -ForegroundColor Cyan
    Write-Host "    View recent runs: gh run list --workflow=build-ipa.yml" -ForegroundColor White
    Write-Host "    Watch live logs:  gh run watch" -ForegroundColor White
    Write-Host "    Open Web UI:      gh run view --web" -ForegroundColor White
    Write-Host "=================================================================="
}

# ==============================================================================
# Main Execution Router
# ==============================================================================
function Main {
    if ($Help) {
        Show-HelpManual
        exit 0
    }

    Write-Host "==================================================================" -ForegroundColor Cyan
    Write-Host "  iOS IPA Build & CI Automation (scripts/build_ipa.ps1)" -ForegroundColor Cyan
    Write-Host "==================================================================" -ForegroundColor Cyan

    $performedAction = $false

    # 1. Optional Pre-Flight Asset Validation
    if (-not [string]::IsNullOrEmpty($P12Path)) {
        $p12Valid = Test-P12Certificate -Path $P12Path -Password $P12Password
        if (-not $p12Valid -and -not $TriggerRemote) {
            exit 1
        }
        $performedAction = $true
    }

    if (-not [string]::IsNullOrEmpty($ProfilePath)) {
        $profileMeta = Test-ProvisioningProfile -Path $ProfilePath
        if ($null -eq $profileMeta -and -not $TriggerRemote) {
            exit 1
        }
        $performedAction = $true
    }

    # 2. Local Packaging Mode
    if (-not [string]::IsNullOrEmpty($AppBundlePath)) {
        $packageSuccess = Package-LocalAppBundle -AppPath $AppBundlePath -Profile $ProfilePath -OutDir $OutputDir
        if (-not $packageSuccess) {
            exit 1
        }
        $performedAction = $true
    }

    # 3. Remote Trigger Mode
    if ($TriggerRemote) {
        Invoke-RemoteBuildDispatch -TargetBranch $Branch -Config $Configuration -Method $ExportMethod
        $performedAction = $true
    }

    # 4. Default Fallback when no operational parameters were specified
    if (-not $performedAction) {
        Write-Host ""
        Write-Host "No operational parameters provided. Displaying help guide..." -ForegroundColor Yellow
        Write-Host ""
        Show-HelpManual
    }

    exit 0
}

Main
