# Project: iOS IPA Signing & Over-The-Air Installation Solution

## Architecture Overview
The solution provides an end-to-end iOS IPA re-signing and wireless Over-The-Air (OTA) installation platform across four interconnected modules:
1. **Signing Server Backend (`backend/`)**:
   - High-concurrency RESTful service (Python FastAPI / async job engine).
   - Pluggable Signing Engine architecture:
     - `ZsignBinaryEngine`: Executes native `zsign` CLI subprocess with flags (`-k`, `-p`, `-m`, `-o`, `-b`, `-n`, `-r`, `-e`, `-z`, `-t`, `-f`).
     - `FallbackSigningEngine`: In-process pure-Python engine for offline/portable environments that unzips the IPA, updates `Info.plist`, injects `embedded.mobileprovision`, synthesizes `_CodeSignature/CodeResources`, and repacks.
   - Isolated UUID job scratchpads (`backend/storage/jobs/{job_id}/`).
   - Dynamic Apple Enterprise OTA manifest generator (`/api/v1/ota/{job_id}/manifest.plist`) and mobile Safari web landing page (`/api/v1/ota/{job_id}/install`).
2. **iOS Signing Application (`iOSApp/`)**:
   - Native Swift/SwiftUI iOS 16.0+ application structured for Xcode (`iOSApp.xcodeproj`).
   - MVVM architecture with 5 dedicated functional tabs:
     - `CertificatesView`: Import and inspect `.p12` files, password entry, Keychain storage.
     - `ProfilesView`: Import and parse `.mobileprovision` CMS envelopes and entitlements.
     - `IPASettingsView` (IPA Library): Manage unsigned IPAs, extract app metadata and icons.
     - `SigningSettingsView`: Override bundle IDs, display names, inject entitlements, configure compression.
     - `ServerConnectionView`: Configure remote signing server URL, test health, submit remote jobs.
   - Embedded Signing Engine: Objective-C++ bridge (`ZsignBridge.h/.mm`) linking zsign C++ core with `OpenSSL.xcframework` and `libz`.
   - Embedded Local OTA Server: Native `Network.framework` HTTP/TLS server serving `manifest.plist` and signed IPAs for on-device installation.
3. **CI/CD Pipeline Automation (`.github/workflows/`, `scripts/`)**:
   - GitHub Actions workflow (`.github/workflows/build-ipa.yml`) for headless macOS runner builds.
   - Ephemeral keychain management, certificate and provisioning profile installation from GitHub secrets (`P12_BASE64`, `P12_PASSWORD`, `PROVISIONING_PROFILE_BASE64`, `DEVELOPMENT_TEAM`).
   - Automated `xcodebuild archive` and `xcodebuild -exportArchive` with dynamic `ExportOptions.plist`.
   - Standalone shell (`scripts/build_ipa.sh`) and PowerShell (`scripts/build_ipa.ps1`) build automations.
4. **Local Verification Harness & Mock Assets (`scripts/`, `tests/`)**:
   - Zero-external-dependency mock asset generator (`scripts/generate_fixtures.ps1`) producing RSA 2048-bit code-signing `.p12` certificates, DER-encoded ASN.1 CMS signed `.mobileprovision` profiles, and valid Mach-O unsigned test IPAs.
   - Automated end-to-end verification harness (`tests/verify_signing_pipeline.ps1` and `tests/verify_signing_pipeline.py`) validating health, job submission, signing execution, signature structures, and OTA manifest XML.

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Backend Service Core & REST API | FastAPI server with health check, CORS, and async job management | M1 | ORIGINAL_REQUEST §R1 |
| 2 | Multipart Asset Upload | Upload endpoint accepting unsigned IPA, p12, password, mobileprovision, bundleId/name overrides | M1 | ORIGINAL_REQUEST §R1 |
| 3 | zsign Engine CLI Wrapper | Binary engine wrapping zsign CLI invocations with full flag support and parameter sanitization | M1 | ORIGINAL_REQUEST §R1 |
| 4 | Fallback Signing Engine | Zero-dependency pure-Python signing engine for portable offline environments and verification | M1 | Survey Explorer 1 |
| 5 | Job Concurrency & Workspace Isolation | UUID-based scratchpad directories with concurrency limiting and automatic cleanup | M1 | Survey Explorer 1 |
| 6 | OTA Manifest Plist Generator | Endpoint generating Apple Enterprise DTD compliant manifest.plist for itms-services:// | M1 | ORIGINAL_REQUEST §R1 |
| 7 | OTA Web Installation Page | Mobile Safari landing page with 1-tap itms-services:// launch link | M1 | Survey Explorer 1 |
| 8 | IPA Artifact Download Endpoint | Streaming download endpoint for signed IPA packages | M1 | ORIGINAL_REQUEST §R1 |
| 9 | iOS App Structure & Navigation | Xcode project with SwiftUI iOS 16+ TabView (5 tabs) and MVVM architecture | M2 | ORIGINAL_REQUEST §R2 |
| 10 | Certificate Manager View & Store | Import .p12 certificates, validate passwords, inspect X.509 metadata, store securely | M2 | ORIGINAL_REQUEST §R2 |
| 11 | Provisioning Profile Manager | Import .mobileprovision, extract CMS payload, parse entitlements, inspect expiration/team | M2 | ORIGINAL_REQUEST §R2 |
| 12 | IPA Library View | Import, store, inspect unsigned IPAs (app name, bundle ID, version, minimum OS) | M2 | ORIGINAL_REQUEST §R2 |
| 13 | Signing Settings & Customization | UI controls to override bundle identifier, display name, inject entitlements, and set compression | M2 | ORIGINAL_REQUEST §R2 |
| 14 | Remote Server Connection Client | Client configuration view and REST API client to connect to backend for remote signing | M2 | ORIGINAL_REQUEST §R2 |
| 15 | Embedded zsign Objective-C++ Bridge | ZsignBridge wrapping zsign C++ logic with OpenSSL/zlib for on-device signing | M2 | ORIGINAL_REQUEST §R2 |
| 16 | Embedded Local OTA Server | In-process Network.framework HTTP/TLS server hosting manifest.plist and signed IPA for on-device OTA | M2 | ORIGINAL_REQUEST §R2 |
| 17 | GitHub Actions Remote Build Workflow | .github/workflows/build-ipa.yml defining macOS build runner, keychain, signing, and artifact archiving | M3 | ORIGINAL_REQUEST §R3 |
| 18 | Standalone Remote Build Scripts | Shell (build_ipa.sh) and PowerShell (build_ipa.ps1) automated build and packaging scripts | M3 | ORIGINAL_REQUEST §R3 |
| 19 | CI/CD Secret & Environment Documentation | Comprehensive setup guide for GitHub secrets and environment variables | M3 | ORIGINAL_REQUEST §R3 |
| 20 | Zero-Credential Mock Asset Generator | PowerShell script generating valid mock .p12, ASN.1 CMS signed .mobileprovision, and dummy Mach-O IPA | M4 | ORIGINAL_REQUEST §R4 |
| 21 | Automated Local Verification Harness | Multi-stage verification script validating backend endpoints, zsign execution, signatures, and manifest | M4 | ORIGINAL_REQUEST §R4 |
| 22 | Comprehensive Project Documentation | README.md documenting architecture, backend execution, iOS app build, and CI/CD workflow | M4 | ORIGINAL_REQUEST §R4 |
| 23 | E2E Testing Suite (Tiers 1-4) | Comprehensive opaque-box test suite verifying all requirements against specifications | E2E | Project Pattern |
| 24 | Adversarial Hardening (Tier 5) | White-box adversarial testing and edge-case hardening | Final | Project Pattern |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Signing Server Backend | Features 1, 2, 3, 4, 5, 6, 7, 8: FastAPI server, zsign binary & fallback engines, OTA manifest generator, download service | None | PLANNED |
| M2 | iOS Signing Application | Features 9, 10, 11, 12, 13, 14, 15, 16: Xcode project structure, SwiftUI 5-tab UI, ZsignBridge C++, local OTA server, remote client | None | PLANNED |
| M3 | CI/CD Pipeline & Build Scripts | Features 17, 18, 19: .github/workflows/build-ipa.yml, build_ipa.sh, build_ipa.ps1, CI documentation | None | PLANNED |
| M4 | Mock Fixtures & Verification Harness | Features 20, 21, 22: generate_fixtures.ps1, mock assets, verify_signing_pipeline.ps1/py, README.md | M1 | PLANNED |
| E2E | E2E Testing Track | Feature 23: Test infrastructure, runner, Tiers 1-4 test cases, TEST_READY.md | None | IN_PROGRESS |
| Final | Final Verification & Hardening | Feature 24: Pass 100% E2E test suite + Tier 5 adversarial hardening | M1, M2, M3, M4, E2E | PLANNED |

---

## Interface Contracts

### Backend Signing Server REST API (M1 ↔ M2, M4, Clients)
- **Base URL**: `http://localhost:8000/api/v1` (or configured `BASE_URL`)
- **Endpoints**:
  - `GET /health`:
    - Response: `{"status": "ok", "version": "1.0.0", "engines": {"zsign": bool, "fallback": bool}}`
  - `POST /jobs`:
    - Request: `multipart/form-data`:
      - `ipa`: File (required, `.ipa` archive)
      - `p12`: File (required, `.p12` / `.pfx` certificate)
      - `password`: String (required, PKCS#12 password)
      - `mobileprovision`: File (required, `.mobileprovision` file)
      - `bundle_id`: String (optional, bundle identifier override)
      - `bundle_name`: String (optional, app display name override)
      - `bundle_version`: String (optional, short version override)
      - `entitlements`: File (optional, custom entitlements plist)
    - Response (HTTP 202 Accepted):
      ```json
      {
        "job_id": "uuid-string",
        "status": "queued",
        "created_at": "ISO-8601"
      }
      ```
  - `GET /jobs/{job_id}`:
    - Response:
      ```json
      {
        "job_id": "uuid-string",
        "status": "completed | processing | queued | failed",
        "download_url": "/api/v1/downloads/{job_id}/signed.ipa",
        "manifest_url": "/api/v1/ota/{job_id}/manifest.plist",
        "install_url": "/api/v1/ota/{job_id}/install",
        "itms_url": "itms-services://?action=download-manifest&url=...",
        "error": null,
        "bundle_id": "com.example.app",
        "bundle_version": "1.0.0",
        "app_name": "SignedApp"
      }
      ```
  - `GET /downloads/{job_id}/{filename}`:
    - Response: Binary stream (`application/octet-stream` or `application/x-itunes-ipa`)
  - `GET /ota/{job_id}/manifest.plist`:
    - Response: XML property list (`text/xml` or `application/xml`) conforming to Apple Enterprise DTD.
  - `GET /ota/{job_id}/install`:
    - Response: HTML page (`text/html`) with one-tap `itms-services://` button.

### Embedded zsign Bridge (M2 Internal Contract)
- **Objective-C++ Interface (`ZsignBridge.h`)**:
  ```objc
  @interface ZsignResult : NSObject
  @property (nonatomic, assign) BOOL success;
  @property (nonatomic, copy) NSString *outputIpaPath;
  @property (nonatomic, copy) NSString *bundleId;
  @property (nonatomic, copy) NSString *appVersion;
  @property (nonatomic, copy) NSString *appName;
  @property (nonatomic, copy) NSString *errorMessage;
  @end

  @interface ZsignBridge : NSObject
  + (ZsignResult *)signAppBundleWithIpaPath:(NSString *)ipaPath
                                   p12Path:(NSString *)p12Path
                               p12Password:(NSString *)p12Password
                         provisioningPath:(NSString *)provisioningPath
                                 bundleId:(nullable NSString *)bundleId
                              displayName:(nullable NSString *)displayName
                         entitlementsPath:(nullable NSString *)entitlementsPath
                              compression:(NSInteger)compression
                                 progress:(void (^)(float progress, NSString *status))progressBlock;
  @end
  ```

### Local Verification Harness Contract (M4 ↔ M1)
- Input: `fixtures/mock.p12`, `fixtures/embedded.mobileprovision`, `fixtures/mock_unsigned.ipa`
- Invocation: `powershell -ExecutionPolicy Bypass -File tests/verify_signing_pipeline.ps1` or `python tests/verify_signing_pipeline.py`
- Output: Exit code 0 on all tests passing, structured JSON or console summary report.

---

## Code Layout
```
c:\Users\Administrator\Desktop\TuanAnh\
├── .github/
│   └── workflows/
│       └── build-ipa.yml             # GitHub Actions remote IPA build workflow
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                   # FastAPI application entry point & routing
│   │   ├── config.py                 # Application configuration & env vars
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   └── v1/
│   │   │       ├── __init__.py
│   │   │       ├── endpoints.py      # REST API endpoints (jobs, health, downloads, ota)
│   │   │       └── schemas.py        # Pydantic schemas for requests and responses
│   │   └── services/
│   │       ├── __init__.py
│   │       ├── signing_manager.py    # Job queue, workspace isolation, engine dispatch
│   │       ├── zsign_engine.py       # Native zsign CLI wrapper
│   │       ├── fallback_engine.py    # Pure-Python portable signing engine
│   │       ├── manifest_service.py   # Apple manifest.plist generator & HTML landing page
│   │       └── plist_utils.py        # Plist parsing and metadata extraction
│   ├── storage/                      # Scratchpads and output storage (gitignored contents)
│   ├── requirements.txt              # Backend dependencies (fastapi, uvicorn, python-multipart, pydantic)
│   └── run_server.py                 # Standalone script to launch backend server
├── iOSApp/
│   ├── iOSApp.xcodeproj/             # Xcode project directory
│   │   └── project.pbxproj           # Project configuration
│   ├── Sources/
│   │   ├── App/
│   │   │   └── iOSApp.swift          # SwiftUI App entry point
│   │   ├── Views/
│   │   │   ├── MainTabView.swift     # 5-tab root view
│   │   │   ├── CertificatesView.swift# P12 certificate management UI
│   │   │   ├── ProfilesView.swift    # Provisioning profile management UI
│   │   │   ├── IPALibraryView.swift  # IPA import and library UI
│   │   │   ├── SigningSettingsView.swift # On-device signing options UI
│   │   │   └── ServerConnectionView.swift# Remote backend connection UI
│   │   ├── Models/
│   │   │   ├── CertificateItem.swift
│   │   │   ├── ProfileItem.swift
│   │   │   ├── IPAItem.swift
│   │   │   └── SigningJob.swift
│   │   ├── Services/
│   │   │   ├── LocalOTAServer.swift  # Embedded Network.framework HTTP/TLS server
│   │   │   ├── RemoteSigningClient.swift # REST client connecting to backend
│   │   │   ├── CertificateStore.swift# Keychain and local file persistence
│   │   │   └── SigningCoordinator.swift # Directs on-device vs remote signing
│   │   ├── Bridge/
│   │   │   ├── ZsignBridge.h         # Objective-C++ bridging header
│   │   │   └── ZsignBridge.mm        # Implementation wrapping C++ zsign logic
│   │   └── zsign/                    # Embedded zsign C++ source code & headers
│   │       ├── zsign.cpp
│   │       ├── bundle.cpp
│   │       ├── macho.cpp
│   │       ├── openssl.cpp
│   │       └── ...
│   └── Resources/
│       └── Info.plist
├── scripts/
│   ├── build_ipa.sh                  # Standalone bash build script for macOS
│   ├── build_ipa.ps1                 # Standalone PowerShell build script
│   └── generate_fixtures.ps1         # Offline mock p12, mobileprovision, IPA generator
├── tests/
│   ├── verify_signing_pipeline.ps1   # PowerShell automated local verification test harness
│   ├── verify_signing_pipeline.py    # Python automated local verification test harness
│   └── fixtures/                     # Test fixtures (generated by generate_fixtures)
│       ├── mock.p12
│       ├── embedded.mobileprovision
│       └── mock_unsigned.ipa
├── README.md                         # Comprehensive documentation
├── PROJECT.md                        # Master project architecture and tracking
└── .agents/teamwork/                 # Orchestrator & agent metadata
```
