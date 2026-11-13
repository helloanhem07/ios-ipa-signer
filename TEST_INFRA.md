# Test Infrastructure Specification (`TEST_INFRA.md`)

## 1. Overview & Architectural Principles

The test infrastructure provides an automated, modular, and opaque-box testing framework for the **iOS IPA Signing & Over-The-Air (OTA) Installation Solution**. It comprehensively verifies all four core system modules across their complete lifecycle:
- **Module 1: Signing Server Backend (`backend/`)**: REST API endpoints, async job scratchpad workspaces, `zsign` CLI wrapper engine, and pure-Python `FallbackSigningEngine`.
- **Module 2: iOS Application Project (`iOSApp/`)**: Xcode project layout, SwiftUI 5-tab MVVM interface, `ZsignBridge` Objective-C++ interface, `LocalOTAServer` embedded HTTP/TLS daemon, and `RemoteSigningClient`.
- **Module 3: CI/CD Automation & Build Scripts (`.github/workflows/`, `scripts/`)**: Headless macOS GitHub Actions workflow, keychain provisioning, `build_ipa.sh`, and `build_ipa.ps1`.
- **Module 4: Local Verification Harness & Mock Assets (`scripts/generate_fixtures.ps1`, `tests/verify_signing_pipeline.ps1/py`)**: Zero-credential test assets, ASN.1 CMS SignedData profiles, 64-bit ARM64 Mach-O binaries, and standalone verification harnesses.

### Core Testing Principles
1. **Opaque-Box Testing**: All tests exercise the system strictly through public interfaces (REST API HTTP endpoints, CLI invocations, file inputs/outputs, public schemas, and Objective-C/Swift signatures). No private internal states or monkey patching are permitted.
2. **Zero-Credential Testing**: The entire test suite operates offline and in CI environments without requiring paid Apple Developer accounts or live App Store Connect credentials, utilizing mathematically valid RSA 2048-bit PKCS#12 certificates and DER-encoded ASN.1 CMS SignedData envelopes.
3. **Deterministic Execution & Reporting**: The test suite produces structured, machine-readable JSON records (`tests/e2e/reports/results.json`), human-readable Markdown summaries (`tests/e2e/reports/summary.md`), and standard exit codes (`0` for pass, `1` for test failure, `2` for infrastructure failure).
4. **Cross-Platform Portability**: The test runner executes across Windows (PowerShell / Python), Linux, and macOS environments with graceful service lifecycle management.

---

## 2. Test Architecture & Directory Structure

```
tests/e2e/
├── run_e2e_tests.py                    # Master Python E2E Test Runner & CLI
├── run_e2e_tests.ps1                   # Native PowerShell Test Runner Wrapper
├── harness/                            # Modular Test Utilities & Validation Toolkit
│   ├── __init__.py
│   ├── macho_validator.py              # Bit-level validation of Mach-O headers (0xFEEDFACF, ARM64)
│   ├── plist_validator.py              # Apple Enterprise DTD compliance & structure validator
│   ├── cms_validator.py                # ASN.1 CMS SignedData envelope unwrapper & extractor
│   ├── zip_validator.py                # IPA PKZIP structure & CodeResources verifier
│   ├── http_client.py                  # Resilient HTTP client for opaque-box REST endpoint testing
│   ├── fixture_manager.py              # Mock fixture generator, loader & cache manager
│   ├── server_manager.py               # Subprocess lifecycle controller for backend service
│   └── report_generator.py             # Structured JSON & Markdown summary report generators
├── tier1_feature_coverage/             # Tier 1: 36 Feature Coverage Test Cases (F1 - F22)
│   ├── __init__.py
│   ├── test_backend_api.py             # 6 tests: Health, upload, scratchpad, download, polling, error
│   ├── test_signing_engines.py         # 6 tests: zsign flags, fallback plist, CodeResources, Mach-O, certs
│   ├── test_ota_manifest.py            # 6 tests: DTD manifest, MIME type, itms-services URL, install HTML
│   ├── test_ios_app.py                 # 6 tests: Xcode layout, Views, Models, RemoteClient, ZsignBridge, LocalOTA
│   ├── test_cicd_pipeline.py           # 6 tests: Workflow syntax, secrets doc, build_ipa.sh/ps1, export options
│   └── test_mock_fixtures.py           # 6 tests: RSA 2048 mock.p12, CMS profile, Mach-O IPA, harness contract
├── tier2_boundary_corner/              # Tier 2: 36 Boundary, Corner & Error Recovery Cases
│   ├── __init__.py
│   ├── test_backend_boundary.py        # 6 tests: Missing fields 422, oversized 413, UUID 404, empty payload
│   ├── test_signing_boundary.py        # 6 tests: Wrong p12 password, corrupt zip, malformed profile, 0-byte
│   ├── test_ota_boundary.py            # 6 tests: Nonexistent job 404, missing file, 416 byte range, XML escape
│   ├── test_ios_boundary.py            # 6 tests: Missing pbxproj refs, bad bridge headers, port collisions
│   ├── test_cicd_boundary.py           # 6 tests: Missing secrets, bad base64, trap cleanups, invalid configs
│   └── test_fixtures_boundary.py       # 6 tests: Odd byte padding, tampered ASN.1, server-down handling
├── tier3_cross_feature/                # Tier 3: 15 Cross-Module Pairwise Interaction Tests
│   ├── __init__.py
│   └── test_cross_feature.py           # 15 tests: End-to-end data handoffs across backend, iOS, CI, fixtures
├── tier4_real_world/                   # Tier 4: 5 End-to-End Multi-Step Real-World Scenarios
│   ├── __init__.py
│   └── test_real_world_scenarios.py    # 5 scenarios: Remote OTA, on-device sign, rebranding, CI release, burst
└── reports/                            # Output directory for test logs and reports
    ├── results.json                    # Machine-readable test execution report
    ├── summary.md                      # Markdown summary report
    └── server.log                      # Captured backend server output
```

---

## 3. Test Runner Specifications

### 3.1 CLI Arguments & Options (`run_e2e_tests.py`)

| Parameter | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--tier` | `-t` | `all` | Specific test tier to run (`1`, `2`, `3`, `4`, or `all`). |
| `--verbose` | `-v` | `False` | Verbose output displaying individual test names, times, and stack traces. |
| `--json-output` | `-j` | `tests/e2e/reports/results.json` | Destination path for machine-readable JSON results. |
| `--report-file` | `-r` | `tests/e2e/reports/summary.md` | Destination path for human-readable Markdown test summary. |
| `--server-url` | `-s` | `http://127.0.0.1:8000` | Target URL for backend REST API endpoints. |
| `--skip-server-spawn` | | `False` | Assume backend server is already running; bypass auto-spawning. |
| `--filter` | `-k` | `None` | Filter test cases matching regex or substring in class or method name. |
| `--timeout` | | `30` | Timeout in seconds for server readiness polling and job completion. |

### 3.2 Native PowerShell Wrapper (`run_e2e_tests.ps1`)
The PowerShell script provides first-class Windows support:
- Validates the local Python runtime.
- Seamlessly propagates parameters: `-Tier`, `-Verbose`, `-JsonOutput`, `-ReportFile`, `-ServerUrl`, `-SkipServerSpawn`, `-Filter`, `-Timeout`.
- Preserves standard exit codes (`$LASTEXITCODE`).

### 3.3 Server Lifecycle & Execution Protocol
1. **Pre-flight Probe**: Probes `GET /api/v1/health` on `--server-url`.
2. **Autonomous Spawning**: If the server is not reachable and `--skip-server-spawn` is false, spawns `python backend/run_server.py` as an isolated child process, logging output to `tests/e2e/reports/server.log`.
3. **Health Polling**: Polls `/api/v1/health` with exponential backoff up to `--timeout` seconds.
4. **Execution**: Discovers and runs selected test suites via Python's standard `unittest` framework.
5. **Teardown**: Gracefully shuts down spawned server subprocesses (`SIGTERM`/`SIGKILL` on POSIX, process termination on Windows) and verifies port release.

---

## 4. Test Harness Validation Toolkit

The `tests/e2e/harness/` module contains specialized validation utilities:

1. **`macho_validator.py`**:
   - Parses 32-byte Mach-O 64-bit headers.
   - Verifies Little-Endian Magic `0xFEEDFACF` (`CF FA ED FE`) or Big-Endian `0xFEEDFACE`.
   - Confirms CPU Type `0x0100000C` (ARM64) and Subtype `0x00000000` (ARM64_ALL).
   - Validates Load Commands count, total size, and 8-byte/4096-byte page alignment.
2. **`plist_validator.py`**:
   - Verifies XML declaration `<?xml version="1.0" encoding="UTF-8"?>`.
   - Validates strict Apple Enterprise Property List DTD:
     `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`.
   - Validates required OTA manifest keys: `items[0].assets` (`software-package` URL), `items[0].metadata` (`bundle-identifier`, `bundle-version`, `kind=software`, `title`).
3. **`cms_validator.py`**:
   - Unwraps ASN.1 DER CMS `SignedData` envelopes (PKCS#7 OID `1.2.840.113549.1.7.2`).
   - Extracts embedded XML plist configuration and entitlements payloads.
   - Verifies cryptographic signer certificate presence and expiration validity.
4. **`zip_validator.py`**:
   - Validates PKZIP archive format integrity (`PK\x03\x04`).
   - Checks presence of required iOS bundle components: `Payload/*.app/Info.plist`, `_CodeSignature/CodeResources`, and `embedded.mobileprovision`.
5. **`http_client.py`**:
   - Resilient, zero-external-dependency HTTP client using `urllib.request`.
   - Supports `multipart/form-data` file streaming with boundary generation.
   - Implements automated retries, HTTP error handling, and byte-range request verification.
6. **`fixture_manager.py`**:
   - Programmatically synthesizes or retrieves valid mock PKCS#12 certificates (`mock.p12`), ASN.1 CMS signed provisioning profiles (`embedded.mobileprovision`), and ARM64 Mach-O unsigned test IPAs (`mock_unsigned.ipa`).

---

## 5. The 4-Tier Test Matrix (92 Discrete Test Cases)

### 5.1 Tier Summary
| Tier | Description | Test Modules | Test Count |
| :--- | :--- | :--- | :---: |
| **Tier 1** | Feature Coverage (Standard functional requirements across 6 domains) | 6 test modules | **36** |
| **Tier 2** | Boundary & Corner Cases (Corrupt inputs, error handling, edge cases) | 6 test modules | **36** |
| **Tier 3** | Cross-Feature Combinations (Pairwise cross-module data contracts) | 1 test module | **15** |
| **Tier 4** | Real-World Application Scenarios (End-to-end multi-step user workflows) | 1 test module | **5** |
| **Total** | **Comprehensive End-to-End Suite** | **14 Modules** | **92** |

### 5.2 Tier 1: Feature Coverage (36 Tests)
- **Backend API (6 tests)**: `test_t1_d1_01_health_check_endpoint`, `test_t1_d1_02_job_submission_accepted`, `test_t1_d1_03_job_status_polling_completion`, `test_t1_d1_04_download_signed_ipa_artifact`, `test_t1_d1_05_job_workspace_isolation`, `test_t1_d1_06_custom_metadata_overrides`.
- **Signing Engines (6 tests)**: `test_t1_d2_01_fallback_engine_structure_generation`, `test_t1_d2_02_zsign_cli_argument_construction`, `test_t1_d2_03_macho_binary_signature_integrity`, `test_t1_d2_04_coderesources_plist_schema`, `test_t1_d2_05_mobileprovision_injection_match`, `test_t1_d2_06_engine_selection_fallback_resilience`.
- **OTA Manifest & Installation (6 tests)**: `test_t1_d3_01_manifest_endpoint_content_type`, `test_t1_d3_02_manifest_apple_dtd_compliance`, `test_t1_d3_03_manifest_dictionary_structure`, `test_t1_d3_04_manifest_asset_package_url`, `test_t1_d3_05_manifest_metadata_properties`, `test_t1_d3_06_ota_install_landing_page_html`.
- **iOS App Architecture & Contracts (6 tests)**: `test_t1_d4_01_xcode_project_structure`, `test_t1_d4_02_swiftui_views_presence`, `test_t1_d4_03_mvvm_model_contracts`, `test_t1_d4_04_objc_zsign_bridge_interface`, `test_t1_d4_05_local_ota_server_network_framework`, `test_t1_d4_06_remote_signing_client_api_contract`.
- **CI/CD Pipeline Automation (6 tests)**: `test_t1_d5_01_github_actions_workflow_syntax`, `test_t1_d5_02_github_actions_build_steps`, `test_t1_d5_03_github_secrets_documentation`, `test_t1_d5_04_macos_bash_build_script_interface`, `test_t1_d5_05_powershell_build_script_interface`, `test_t1_d5_06_export_options_plist_generation`.
- **Mock Fixtures & Harness (6 tests)**: `test_t1_d6_01_mock_fixture_generator_powershell`, `test_t1_d6_02_mock_p12_x509_validity`, `test_t1_d6_03_mock_mobileprovision_cms_envelope`, `test_t1_d6_04_mock_unsigned_ipa_structure`, `test_t1_d6_05_standalone_verification_script_powershell`, `test_t1_d6_06_standalone_verification_script_python`.

### 5.3 Tier 2: Boundary & Corner Cases (36 Tests)
- **Backend Boundaries (6 tests)**: Missing form fields (422), invalid job UUID format, non-existent job queries (404), empty zero-byte uploads (400), concurrency throttling stability, non-existent artifact downloads (404).
- **Signing Boundaries (6 tests)**: Incorrect p12 password handling, corrupted p12 binary bytes, corrupted non-zip IPA, missing Payload directory, missing Info.plist, corrupted non-CMS mobileprovision.
- **OTA Boundaries (6 tests)**: Manifest query for in-progress job, manifest query for failed job, XML special character escaping (`&`, `<`, `>`, `"`), Unicode and emoji bundle names, missing job install page, extreme bundle ID length handling.
- **iOS App Boundaries (6 tests)**: Empty certificate store state, expired certificate handling, mismatched provisioning profile warnings, local OTA port collision fallback, remote server connection timeouts, zsign bridge resource cleanup.
- **CI/CD Boundaries (6 tests)**: Missing secrets handling, invalid base64 secret payload, ephemeral keychain cleanup on failure, missing script mandatory arguments, invalid PowerShell configuration parameter, unsupported export method rejection.
- **Fixture Boundaries (6 tests)**: Invalid fixture output path, empty password parameter handling, Mach-O odd byte length padding alignment, tampered ASN.1 DER tags, server down verification script handling, temp scratchpad cleanup on interruption.

### 5.4 Tier 3: Cross-Feature Combinations (15 Tests)
- `test_t3_01_backend_upload_to_fallback_engine_resilience`: F2 ↔ F4
- `test_t3_02_backend_upload_to_zsign_engine_cli`: F2 ↔ F3
- `test_t3_03_custom_bundle_id_to_manifest_plist_reflection`: F2 ↔ F6
- `test_t3_04_custom_bundle_name_to_ota_install_page_reflection`: F2 ↔ F7
- `test_t3_05_signed_ipa_download_url_to_manifest_asset_url`: F6 ↔ F8
- `test_t3_06_manifest_url_to_itms_url_query_encoding`: F6 ↔ F7
- `test_t3_07_mock_p12_to_backend_signature_verification`: F20 ↔ F1
- `test_t3_08_mock_mobileprovision_to_signed_bundle_entitlements`: F20 ↔ F4
- `test_t3_09_concurrency_isolation_across_different_bundle_ids`: F5 ↔ F2
- `test_t3_10_remote_client_contract_to_backend_endpoints`: F14 ↔ F1/F2
- `test_t3_11_local_ota_manifest_builder_to_apple_dtd`: F16 ↔ F6
- `test_t3_12_ci_export_options_to_mock_provisioning_uuid`: F17/F18 ↔ F20
- `test_t3_13_zsign_bridge_to_mock_unsigned_ipa`: F15 ↔ F20
- `test_t3_14_backend_storage_cleanup_to_job_lifecycle`: F5 ↔ F1
- `test_t3_15_verification_harness_to_backend_live_reproduction`: F21 ↔ F1-F8

### 5.5 Tier 4: Real-World Scenarios (5 Tests)
- `test_t4_01_complete_remote_signing_and_ota_distribution_workflow`: Multi-step client upload, fallback signing, manifest generation, Safari install page, and artifact verification.
- `test_t4_02_on_device_asset_import_to_local_ota_installation_workflow`: Simulated on-device p12 import, profile inspection, on-device signing coordination, and local OTA streaming.
- `test_t4_03_enterprise_rebranding_and_entitlement_injection_workflow`: Enterprise distribution bundle ID override, custom entitlement injection, and CodeResources re-hash verification.
- `test_t4_04_ci_cd_push_to_artifact_release_automation_workflow`: Git release event simulation, ephemeral keychain security, archive export, and artifact release verification.
- `test_t4_05_resilient_multi_tenant_burst_concurrency_workflow`: Concurrent multi-job burst processing, queue isolation, error containment, and FIFO completion.

---

## 6. Execution Instructions

### Windows (PowerShell)
```powershell
# Run entire test suite across all 4 tiers
.\tests\e2e\run_e2e_tests.ps1

# Run only Tier 1 Feature Coverage tests with verbose logging
.\tests\e2e\run_e2e_tests.ps1 -Tier 1 -Verbose

# Run against an externally managed backend server
.\tests\e2e\run_e2e_tests.ps1 -SkipServerSpawn -ServerUrl "http://127.0.0.1:8000"
```

### Linux / macOS (Python)
```bash
# Run all 92 test cases
python3 tests/e2e/run_e2e_tests.py

# Run specific tier with custom report destination
python3 tests/e2e/run_e2e_tests.py --tier 2 --verbose --json-output tests/e2e/reports/tier2_results.json

# Run filtered tests
python3 tests/e2e/run_e2e_tests.py --filter "ota"
```

---

## 7. Quality Gates & Acceptance Verification

Every release candidate must pass all 4 quality gates:
1. **Tier 1 Gate**: 100% pass rate (36/36) validating standard functional paths for all features (F1 - F22).
2. **Tier 2 Gate**: 100% pass rate (36/36) validating negative boundaries, error messages, and HTTP status codes (400, 404, 422).
3. **Tier 3 Gate**: 100% pass rate (15/15) validating cross-module contracts and data handoffs.
4. **Tier 4 Gate**: 100% pass rate (5/5) validating real-world end-to-end multi-step workflows.
5. **Exit Code Policy**: The runner returns exit code `0` on 100% pass, and non-zero on any failure.
