#!/usr/bin/env bash
# ==============================================================================
# scripts/build_ipa.sh
# Standalone macOS iOS IPA Build & Codesigning Automation Script
# Compatible with macOS 12+ and default /bin/bash 3.2+
# ==============================================================================

set -o errexit
set -o nounset
set -o pipefail

# ------------------------------------------------------------------------------
# Default Configuration
# ------------------------------------------------------------------------------
P12_PATH=""
P12_PASSWORD=""
PROFILE_PATH=""
CONFIG="Release"
EXPORT_METHOD="development"
OUTPUT_DIR="build/export"
PROJECT_PATH="iOSApp/iOSApp.xcodeproj"
SCHEME="iOSApp"
BUNDLE_ID_OVERRIDE=""
TEAM_ID_OVERRIDE=""
KEEP_ARCHIVE=false
VERBOSE=false

# Internal State Tracking
TEMP_DIR=""
KEYCHAIN_PATH=""
KEYCHAIN_PASSWORD=""
ORIGINAL_KEYCHAINS=()
PROFILE_UUID=""
INSTALLED_PROFILE_PATH=""
PROFILE_INSTALLED_BY_SCRIPT=false
SIGNING_IDENTITY=""
TEAM_ID=""
BUNDLE_ID=""

# ------------------------------------------------------------------------------
# Help Menu
# ------------------------------------------------------------------------------
show_help() {
    cat <<'EOF'
build_ipa.sh - Standalone iOS IPA Build and Export Automation

Usage:
  ./scripts/build_ipa.sh -p <p12_path> -w <password> -m <profile_path> [options]

Required Options:
  -p, --p12 <file>          Path to PKCS#12 signing certificate (.p12 / .pfx)
  -w, --password <pwd>      Password for the .p12 certificate
  -m, --profile <file>      Path to Apple provisioning profile (.mobileprovision)

Build & Export Options:
  -c, --config <cfg>        Build configuration: Release | Debug (default: Release)
  -e, --method <method>     Export method: development | ad-hoc | enterprise | app-store
                            (default: development)
  -o, --output <dir>        Output directory for exported .ipa (default: build/export)
      --project <path>      Path to Xcode project (default: iOSApp/iOSApp.xcodeproj)
  -s, --scheme <name>       Xcode scheme to archive (default: iOSApp)
  -b, --bundle-id <id>      Override Bundle ID (default: extracted from profile/project)
  -t, --team-id <id>        Override Apple Team ID (default: extracted from profile)
      --keep-archive        Retain intermediate .xcarchive in output directory
  -v, --verbose             Display verbose xcodebuild output (default: quiet)
  -h, --help                Show this help message and exit

Exit Codes:
  0  Success (IPA generated)
  1  File not found or filesystem error
  2  Invalid or missing command-line arguments
  3  Missing required system tools (xcodebuild, security, plutil, openssl)
  4  Certificate import or ephemeral keychain setup failure
  5  Provisioning profile parsing or UUID extraction failure
  6  xcodebuild archive compilation failure
  7  xcodebuild -exportArchive failure

Examples:
  # Basic Development build using default project and scheme
  ./scripts/build_ipa.sh -p certs/dev.p12 -w "Secret123" -m certs/dev.mobileprovision

  # Release Ad-Hoc distribution build to custom output folder
  ./scripts/build_ipa.sh -p certs/dist.p12 -w "Secret123" -m certs/adhoc.mobileprovision \
      -c Release -e ad-hoc -o dist/ipa

  # Enterprise build with custom scheme and bundle ID override
  ./scripts/build_ipa.sh -p certs/inhouse.p12 -w "P12Pass" -m certs/inhouse.mobileprovision \
      -e enterprise -s iOSApp -b com.company.inhouse.app
EOF
}

# ------------------------------------------------------------------------------
# Cleanup Trap Handler
# ------------------------------------------------------------------------------
cleanup() {
    local exit_code=$?
    set +e

    echo ""
    echo "==> Cleaning up build resources..."

    # 1. Restore original keychain search domain
    if [ ${#ORIGINAL_KEYCHAINS[@]} -gt 0 ]; then
        echo "--> Restoring original user keychain search list..."
        security list-keychains -d user -s "${ORIGINAL_KEYCHAINS[@]}" 2>/dev/null || true
    fi

    # 2. Delete the ephemeral keychain
    if [ -n "$KEYCHAIN_PATH" ] && [ -f "$KEYCHAIN_PATH" ]; then
        echo "--> Deleting ephemeral keychain: $KEYCHAIN_PATH..."
        security delete-keychain "$KEYCHAIN_PATH" 2>/dev/null || true
        security delete-keychain "${KEYCHAIN_PATH%-db}" 2>/dev/null || true
    fi

    # 3. Clean up installed provisioning profile (if created by this script)
    if [ "$PROFILE_INSTALLED_BY_SCRIPT" = "true" ] && [ -n "$INSTALLED_PROFILE_PATH" ]; then
        if [ -f "$INSTALLED_PROFILE_PATH" ]; then
            echo "--> Removing installed provisioning profile: $INSTALLED_PROFILE_PATH..."
            rm -f "$INSTALLED_PROFILE_PATH" 2>/dev/null || true
        fi
    fi

    # 4. Remove temporary scratchpad directory
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        echo "--> Removing temporary directory: $TEMP_DIR..."
        rm -rf "$TEMP_DIR" 2>/dev/null || true
    fi

    exit "$exit_code"
}
trap cleanup EXIT INT TERM HUP

# ------------------------------------------------------------------------------
# CLI Argument Parsing (Bash 3.2 Compatible)
# ------------------------------------------------------------------------------
parse_arguments() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -p|--p12)
                [ $# -lt 2 ] && { echo "Error: $1 requires an argument." >&2; exit 2; }
                P12_PATH="$2"; shift 2 ;;
            --p12=*)
                P12_PATH="${1#*=}"; shift ;;
            -w|--password)
                [ $# -lt 2 ] && { echo "Error: $1 requires an argument." >&2; exit 2; }
                P12_PASSWORD="$2"; shift 2 ;;
            --password=*)
                P12_PASSWORD="${1#*=}"; shift ;;
            -m|--profile)
                [ $# -lt 2 ] && { echo "Error: $1 requires an argument." >&2; exit 2; }
                PROFILE_PATH="$2"; shift 2 ;;
            --profile=*)
                PROFILE_PATH="${1#*=}"; shift ;;
            -c|--config)
                [ $# -lt 2 ] && { echo "Error: $1 requires an argument." >&2; exit 2; }
                CONFIG="$2"; shift 2 ;;
            --config=*)
                CONFIG="${1#*=}"; shift ;;
            -e|--method)
                [ $# -lt 2 ] && { echo "Error: $1 requires an argument." >&2; exit 2; }
                EXPORT_METHOD="$2"; shift 2 ;;
            --method=*)
                EXPORT_METHOD="${1#*=}"; shift ;;
            -o|--output)
                [ $# -lt 2 ] && { echo "Error: $1 requires an argument." >&2; exit 2; }
                OUTPUT_DIR="$2"; shift 2 ;;
            --output=*)
                OUTPUT_DIR="${1#*=}"; shift ;;
            --project)
                [ $# -lt 2 ] && { echo "Error: $1 requires an argument." >&2; exit 2; }
                PROJECT_PATH="$2"; shift 2 ;;
            --project=*)
                PROJECT_PATH="${1#*=}"; shift ;;
            -s|--scheme)
                [ $# -lt 2 ] && { echo "Error: $1 requires an argument." >&2; exit 2; }
                SCHEME="$2"; shift 2 ;;
            --scheme=*)
                SCHEME="${1#*=}"; shift ;;
            -b|--bundle-id)
                [ $# -lt 2 ] && { echo "Error: $1 requires an argument." >&2; exit 2; }
                BUNDLE_ID_OVERRIDE="$2"; shift 2 ;;
            --bundle-id=*)
                BUNDLE_ID_OVERRIDE="${1#*=}"; shift ;;
            -t|--team-id)
                [ $# -lt 2 ] && { echo "Error: $1 requires an argument." >&2; exit 2; }
                TEAM_ID_OVERRIDE="$2"; shift 2 ;;
            --team-id=*)
                TEAM_ID_OVERRIDE="${1#*=}"; shift ;;
            --keep-archive)
                KEEP_ARCHIVE=true; shift ;;
            -v|--verbose)
                VERBOSE=true; shift ;;
            -h|--help)
                show_help; exit 0 ;;
            *)
                echo "Error: Unknown argument: $1" >&2
                show_help >&2
                exit 2 ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# Validation Routines
# ------------------------------------------------------------------------------
validate_environment() {
    local missing=()
    for tool in xcodebuild security plutil openssl; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo "Error: Missing required system utilities: ${missing[*]}" >&2
        echo "Please install Xcode Command Line Tools and macOS security utilities." >&2
        exit 3
    fi

    if ! xcode-select -p >/dev/null 2>&1; then
        echo "Error: Active Xcode developer directory not configured." >&2
        exit 3
    fi
}

validate_inputs() {
    # Check required options
    if [ -z "$P12_PATH" ]; then
        echo "Error: Missing required certificate option (-p, --p12)." >&2
        exit 2
    fi
    if [ -z "$P12_PASSWORD" ]; then
        echo "Error: Missing required certificate password option (-w, --password)." >&2
        exit 2
    fi
    if [ -z "$PROFILE_PATH" ]; then
        echo "Error: Missing required provisioning profile option (-m, --profile)." >&2
        exit 2
    fi

    # Check file existence
    if [ ! -f "$P12_PATH" ]; then
        echo "Error: PKCS#12 certificate file does not exist: $P12_PATH" >&2
        exit 1
    fi
    if [ ! -f "$PROFILE_PATH" ]; then
        echo "Error: Provisioning profile file does not exist: $PROFILE_PATH" >&2
        exit 1
    fi
    if [ ! -d "$PROJECT_PATH" ]; then
        echo "Error: Xcode project directory does not exist: $PROJECT_PATH" >&2
        exit 1
    fi

    # Check configuration
    if [ "$CONFIG" != "Release" ] && [ "$CONFIG" != "Debug" ]; then
        echo "Error: Invalid configuration: '$CONFIG'. Must be 'Release' or 'Debug'." >&2
        exit 2
    fi

    # Check export method
    case "$EXPORT_METHOD" in
        development|ad-hoc|enterprise|app-store) ;;
        *)
            echo "Error: Invalid export method: '$EXPORT_METHOD'." >&2
            echo "Must be one of: development, ad-hoc, enterprise, app-store." >&2
            exit 2 ;;
    esac
}

# ------------------------------------------------------------------------------
# Plist Value Extraction Helper (plutil + PlistBuddy fallback)
# ------------------------------------------------------------------------------
get_plist_value() {
    local file="$1"
    local plutil_key="$2"
    local plistbuddy_key="$3"
    local val=""

    if command -v plutil >/dev/null 2>&1; then
        val=$(plutil -extract "$plutil_key" raw -o - "$file" 2>/dev/null || true)
        if [ -z "$val" ]; then
            val=$(plutil -extract "$plutil_key" raw "$file" 2>/dev/null || true)
        fi
    fi

    if [ -z "$val" ] && [ -x /usr/libexec/PlistBuddy ]; then
        val=$(/usr/libexec/PlistBuddy -c "Print :$plistbuddy_key" "$file" 2>/dev/null || true)
    fi

    echo "$val"
}

# ------------------------------------------------------------------------------
# Ephemeral Keychain Setup
# ------------------------------------------------------------------------------
setup_keychain() {
    echo "==> Setting up isolated ephemeral keychain..."
    KEYCHAIN_NAME="build-$(date +%s)-$$.keychain-db"
    KEYCHAIN_PATH="$TEMP_DIR/$KEYCHAIN_NAME"
    KEYCHAIN_PASSWORD=$(openssl rand -base64 16 | tr -d '\r\n')

    # Create temporary keychain
    security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH" || {
        echo "Error: Failed to create ephemeral keychain." >&2
        exit 4
    }

    # Set timeout to 6 hours (21600 seconds) and unlock
    security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
    security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

    # Import .p12 certificate
    echo "--> Importing .p12 certificate into ephemeral keychain..."
    if ! security import "$P12_PATH" \
        -k "$KEYCHAIN_PATH" \
        -P "$P12_PASSWORD" \
        -T /usr/bin/codesign \
        -T /usr/bin/security >/dev/null 2>&1; then
        echo "Error: Failed to import .p12 certificate into keychain. Invalid password or corrupted archive." >&2
        exit 4
    fi

    # Set partition list to eliminate GUI authorization popups
    echo "--> Configuring partition access list for codesign..."
    security set-key-partition-list \
        -S apple-tool:,apple: \
        -s \
        -k "$KEYCHAIN_PASSWORD" \
        "$KEYCHAIN_PATH" >/dev/null 2>&1 || true

    # Backup original keychain search list
    echo "--> Prepending ephemeral keychain to user search domain..."
    ORIGINAL_KEYCHAINS=()
    while IFS= read -r line; do
        cleaned=$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/^"//' -e 's/"$//')
        if [ -n "$cleaned" ] && [ -f "$cleaned" ]; then
            ORIGINAL_KEYCHAINS+=("$cleaned")
        fi
    done < <(security list-keychains -d user 2>/dev/null || true)

    if [ ${#ORIGINAL_KEYCHAINS[@]} -gt 0 ]; then
        security list-keychains -d user -s "$KEYCHAIN_PATH" "${ORIGINAL_KEYCHAINS[@]}"
    else
        security list-keychains -d user -s "$KEYCHAIN_PATH"
    fi

    # Verify signing identity in imported keychain
    echo "--> Verifying code-signing identities..."
    IDENTITY_LINE=$(security find-identity -v -p codesigning "$KEYCHAIN_PATH" | grep -E '^[[:space:]]*1\)' | head -n1 || true)
    if [ -z "$IDENTITY_LINE" ]; then
        echo "Error: No valid code-signing identities found in the imported .p12." >&2
        exit 4
    fi

    SIGNING_IDENTITY=$(echo "$IDENTITY_LINE" | sed -E 's/^[[:space:]]*1\)[[:space:]]+[A-Fa-f0-9]+[[:space:]]+"([^"]+)".*$/\1/')
    echo "    Identified Signing Certificate: $SIGNING_IDENTITY"
}

# ------------------------------------------------------------------------------
# Provisioning Profile Parsing & Installation
# ------------------------------------------------------------------------------
process_provisioning_profile() {
    echo "==> Decoding and parsing provisioning profile..."
    local plist_file="$TEMP_DIR/profile.plist"

    # Decode ASN.1 CMS container
    if ! security cms -D -i "$PROFILE_PATH" > "$plist_file" 2>/dev/null; then
        echo "Error: Failed to decode provisioning profile ($PROFILE_PATH). Not a valid CMS SignedData file." >&2
        exit 5
    fi

    # Extract Profile UUID
    PROFILE_UUID=$(get_plist_value "$plist_file" "UUID" "UUID")
    if [ -z "$PROFILE_UUID" ]; then
        echo "Error: Failed to extract UUID from provisioning profile." >&2
        exit 5
    fi
    echo "    Profile UUID: $PROFILE_UUID"

    # Extract Team ID
    if [ -n "$TEAM_ID_OVERRIDE" ]; then
        TEAM_ID="$TEAM_ID_OVERRIDE"
    else
        TEAM_ID=$(get_plist_value "$plist_file" "TeamIdentifier.0" "TeamIdentifier:0")
        if [ -z "$TEAM_ID" ]; then
            local app_id
            app_id=$(get_plist_value "$plist_file" "Entitlements.application-identifier" "Entitlements:application-identifier")
            TEAM_ID="${app_id%%.*}"
        fi
    fi

    if [ -z "$TEAM_ID" ]; then
        echo "Error: Failed to determine Apple Developer Team ID." >&2
        exit 5
    fi
    echo "    Developer Team ID: $TEAM_ID"

    # Extract Bundle ID
    if [ -n "$BUNDLE_ID_OVERRIDE" ]; then
        BUNDLE_ID="$BUNDLE_ID_OVERRIDE"
    else
        local app_id
        app_id=$(get_plist_value "$plist_file" "Entitlements.application-identifier" "Entitlements:application-identifier")
        local raw_bundle="${app_id#*.}"
        if [ "$raw_bundle" != "*" ] && [ -n "$raw_bundle" ]; then
            BUNDLE_ID="$raw_bundle"
        else
            # Wildcard profile fallback: check project build settings
            local proj_bundle
            proj_bundle=$(xcodebuild -project "$PROJECT_PATH" -scheme "$SCHEME" -configuration "$CONFIG" -showBuildSettings 2>/dev/null | grep -E '^[[:space:]]*PRODUCT_BUNDLE_IDENTIFIER =' | head -n1 | awk '{print $3}' || true)
            if [ -n "$proj_bundle" ]; then
                BUNDLE_ID="$proj_bundle"
            else
                BUNDLE_ID="com.example.iOSApp"
            fi
        fi
    fi
    echo "    Target Bundle Identifier: $BUNDLE_ID"

    # Install profile into standard macOS cache location
    local profiles_dir="$HOME/Library/MobileDevice/Provisioning Profiles"
    mkdir -p "$profiles_dir"
    INSTALLED_PROFILE_PATH="$profiles_dir/${PROFILE_UUID}.mobileprovision"

    if [ -f "$INSTALLED_PROFILE_PATH" ]; then
        PROFILE_INSTALLED_BY_SCRIPT=false
        echo "    Profile already installed at $INSTALLED_PROFILE_PATH"
    else
        cp "$PROFILE_PATH" "$INSTALLED_PROFILE_PATH"
        PROFILE_INSTALLED_BY_SCRIPT=true
        echo "    Installed profile to $INSTALLED_PROFILE_PATH"
    fi
}

# ------------------------------------------------------------------------------
# Xcode Archive & Export
# ------------------------------------------------------------------------------
build_and_export() {
    local archive_path="$TEMP_DIR/${SCHEME}.xcarchive"
    local export_plist="$TEMP_DIR/ExportOptions.plist"

    # 1. Resolve Swift Package Dependencies
    echo "==> Resolving Swift package dependencies..."
    xcodebuild -resolvePackageDependencies \
        -project "$PROJECT_PATH" \
        -scheme "$SCHEME" >/dev/null 2>&1 || true

    # 2. Archive Application
    echo "==> Archiving Xcode project: $SCHEME (Configuration: $CONFIG)..."
    local archive_args=(
        -project "$PROJECT_PATH"
        -scheme "$SCHEME"
        -configuration "$CONFIG"
        -destination "generic/platform=iOS"
        -archivePath "$archive_path"
        CODE_SIGN_STYLE=Manual
        DEVELOPMENT_TEAM="$TEAM_ID"
        PROVISIONING_PROFILE="$PROFILE_UUID"
        PROVISIONING_PROFILE_SPECIFIER="$PROFILE_UUID"
    )

    if [ -n "$SIGNING_IDENTITY" ]; then
        archive_args+=(CODE_SIGN_IDENTITY="$SIGNING_IDENTITY")
    fi

    if [ "$VERBOSE" = "true" ]; then
        xcodebuild archive "${archive_args[@]}" || {
            echo "Error: xcodebuild archive failed." >&2
            exit 6
        }
    else
        xcodebuild archive "${archive_args[@]}" -quiet || {
            echo "Error: xcodebuild archive failed." >&2
            exit 6
        }
    fi

    # 3. Generate dynamic ExportOptions.plist
    echo "==> Generating dynamic ExportOptions.plist..."
    cat <<EOF > "$export_plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>${EXPORT_METHOD}</string>
    <key>teamID</key>
    <string>${TEAM_ID}</string>
    <key>signingStyle</key>
    <string>manual</string>
    <key>provisioningProfiles</key>
    <dict>
        <key>${BUNDLE_ID}</key>
        <string>${PROFILE_UUID}</string>
    </dict>
    <key>compileBitcode</key>
    <false/>
    <key>thinning</key>
    <string>&lt;none&gt;</string>
</dict>
</plist>
EOF

    # 4. Export IPA from Archive
    echo "==> Exporting IPA (Method: $EXPORT_METHOD)..."
    mkdir -p "$OUTPUT_DIR"

    local export_args=(
        -exportArchive
        -archivePath "$archive_path"
        -exportOptionsPlist "$export_plist"
        -exportPath "$OUTPUT_DIR"
        -allowProvisioningUpdates
    )

    if [ "$VERBOSE" = "true" ]; then
        xcodebuild "${export_args[@]}" || {
            echo "Error: xcodebuild -exportArchive failed." >&2
            exit 7
        }
    else
        xcodebuild "${export_args[@]}" -quiet || {
            echo "Error: xcodebuild -exportArchive failed." >&2
            exit 7
        }
    fi

    # 5. Confirm output .ipa exists
    local exported_ipa
    exported_ipa=$(find "$OUTPUT_DIR" -maxdepth 1 -name "*.ipa" | head -n1 || true)
    if [ -z "$exported_ipa" ] || [ ! -f "$exported_ipa" ]; then
        echo "Error: Export succeeded but no .ipa file was found in $OUTPUT_DIR" >&2
        exit 7
    fi

    # Retain archive if requested
    if [ "$KEEP_ARCHIVE" = "true" ]; then
        echo "--> Retaining intermediate archive in $OUTPUT_DIR..."
        cp -R "$archive_path" "$OUTPUT_DIR/"
    fi

    # 6. Success Summary
    local ipa_size
    ipa_size=$(ls -lh "$exported_ipa" | awk '{print $5}')
    local ipa_filename
    ipa_filename=$(basename "$exported_ipa")

    echo ""
    echo "=================================================================="
    echo "  BUILD & EXPORT SUCCESSFUL"
    echo "=================================================================="
    echo "  IPA Package:    $OUTPUT_DIR/$ipa_filename"
    echo "  Package Size:   $ipa_size"
    echo "  Target Scheme:  $SCHEME"
    echo "  Configuration:  $CONFIG"
    echo "  Export Method:  $EXPORT_METHOD"
    echo "  Bundle ID:      $BUNDLE_ID"
    echo "  Team ID:        $TEAM_ID"
    echo "  Profile UUID:   $PROFILE_UUID"
    echo "=================================================================="
}

# ------------------------------------------------------------------------------
# Main Execution Entry Point
# ------------------------------------------------------------------------------
main() {
    echo "=================================================================="
    echo "  iOS IPA Standalone Build Automation (scripts/build_ipa.sh)"
    echo "=================================================================="

    parse_arguments "$@"
    validate_environment
    validate_inputs

    # Allocate temporary working scratchpad
    if [ -n "${RUNNER_TEMP:-}" ] && [ -d "${RUNNER_TEMP:-}" ]; then
        TEMP_DIR=$(mktemp -d "$RUNNER_TEMP/build_ipa_XXXXXX" 2>/dev/null || mktemp -d -t "build_ipa_XXXXXX")
    else
        TEMP_DIR=$(mktemp -d -t "build_ipa_XXXXXX" 2>/dev/null || mktemp -d "/tmp/build_ipa_XXXXXX")
    fi

    echo "Using Developer Directory: $(xcode-select -p)"
    echo "Using Temporary Scratchpad: $TEMP_DIR"

    setup_keychain
    process_provisioning_profile
    build_and_export

    exit 0
}

main "$@"
