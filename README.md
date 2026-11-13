# 📱 iOS IPA Signing Solution

Hệ thống ký lại IPA hoàn chỉnh gồm **Backend Signing Server** (tương tự LCSign) và **iOS On-Device Signer App** (tương tự ESign/Feather), kèm theo CI/CD pipeline tự động build IPA qua GitHub Actions.

## 📁 Cấu trúc dự án

```
├── backend/                    # Backend Signing Server (Python/FastAPI)
│   ├── app/
│   │   ├── main.py             # FastAPI entry point
│   │   ├── config.py           # Cấu hình server (env vars)
│   │   ├── api/v1/
│   │   │   ├── endpoints.py    # REST API endpoints
│   │   │   └── schemas.py      # Pydantic request/response schemas
│   │   └── services/
│   │       ├── zsign_engine.py      # Native zsign subprocess wrapper
│   │       ├── fallback_engine.py   # Fallback signing engine (Python-based)
│   │       ├── signing_manager.py   # Job queue & concurrency manager
│   │       ├── manifest_service.py  # OTA manifest.plist & install page generator
│   │       ├── signing_engine.py    # Abstract signing engine interface
│   │       └── plist_utils.py       # IPA metadata extraction utilities
│   ├── storage/jobs/           # Job scratchpad directories (auto-created)
│   ├── run_server.py           # CLI server launcher
│   ├── requirements.txt        # Python dependencies
│   └── tests/                  # Backend unit & adversarial tests
│
├── iOSApp/                     # iOS Signing Application (Swift/SwiftUI)
│   ├── iOSApp.xcodeproj/      # Xcode project file
│   ├── Resources/
│   │   ├── Info.plist
│   │   └── iOSApp.entitlements
│   └── Sources/
│       ├── App/                # App entry point & state management
│       ├── Bridge/             # Objective-C++ bridging header for zsign
│       ├── Models/             # Data models (CertificateItem, IPAItem, etc.)
│       ├── Services/           # Business logic services
│       │   ├── LocalOTAServer.swift        # Embedded HTTP server for on-device OTA
│       │   ├── LocalZsignEngine.swift      # On-device zsign wrapper
│       │   ├── SigningCoordinator.swift     # Pipeline coordinator (local/remote)
│       │   ├── RemoteSigningClient.swift    # HTTP client for backend server
│       │   ├── KeychainManager.swift        # iOS Keychain integration
│       │   ├── PKCS12Parser.swift           # Certificate parsing
│       │   ├── MobileProvisionParser.swift  # Provisioning profile parser
│       │   └── ManifestBuilder.swift        # OTA manifest XML builder
│       ├── Views/              # SwiftUI interface (5-tab navigation)
│       └── zsign/              # Embedded C++ zsign engine source
│
├── scripts/                    # Build automation scripts
│   ├── build_ipa.sh            # macOS/Linux build script
│   └── build_ipa.ps1           # Windows PowerShell build script
│
├── .github/workflows/
│   └── build-ipa.yml           # GitHub Actions CI/CD workflow
│
├── tests/                      # E2E test suites & verification harness
│   └── e2e/
│       ├── fixtures/           # Mock certificates, profiles & test IPA
│       ├── harness/            # Test infrastructure (validators, HTTP client)
│       ├── tier1_feature_coverage/   # Feature coverage tests
│       └── tier2_boundary_corner/    # Boundary & corner case tests
│
├── PROJECT.md                  # Architecture specification
└── TEST_INFRA.md               # Test infrastructure documentation
```

---

## 🚀 Hướng dẫn chạy Backend Server

### Yêu cầu
- Python 3.11+
- `zsign` binary (tùy chọn, có fallback engine)

### Cài đặt & Khởi động

```bash
# 1. Di chuyển vào thư mục backend
cd backend

# 2. Cài đặt dependencies
pip install -r requirements.txt

# 3. Khởi động server
python run_server.py --host 0.0.0.0 --port 8000
```

Server sẽ chạy tại `http://localhost:8000`. Truy cập `http://localhost:8000/docs` để xem Swagger API documentation.

### Cấu hình (Environment Variables)

| Biến môi trường | Mặc định | Mô tả |
|---|---|---|
| `SIGNING_SERVER_HOST` | `0.0.0.0` | Host interface |
| `SIGNING_SERVER_PORT` | `8000` | Port |
| `SIGNING_BASE_URL` | `http://localhost:8000` | Public URL (dùng cho link OTA HTTPS) |
| `ZSIGN_BIN_PATH` | Auto-detect | Đường dẫn tới zsign binary |
| `SIGNING_MAX_CONCURRENT_JOBS` | `3` | Số job ký song song tối đa |
| `SIGNING_TIMEOUT_SECONDS` | `300` | Timeout cho mỗi job (giây) |
| `SIGNING_MAX_UPLOAD_SIZE_BYTES` | `4294967296` | Giới hạn upload (4GB) |
| `SIGNING_ENGINE` | `auto` | Engine ưu tiên: `zsign`, `fallback`, `auto` |

### API Endpoints

| Method | Endpoint | Mô tả |
|---|---|---|
| `GET` | `/api/v1/health` | Kiểm tra trạng thái server & engines |
| `POST` | `/api/v1/jobs` | Tạo job ký IPA mới (upload IPA + P12 + mobileprovision) |
| `GET` | `/api/v1/jobs/{job_id}` | Kiểm tra trạng thái job & lấy link download |
| `GET` | `/api/v1/downloads/{job_id}/{filename}` | Tải file IPA đã ký |
| `GET` | `/api/v1/ota/{job_id}/manifest.plist` | Lấy file manifest OTA |
| `GET` | `/api/v1/ota/{job_id}/install` | Trang web cài đặt 1-tap cho Safari |

### Quy trình ký IPA qua API

```bash
# Upload & ký IPA
curl -X POST http://localhost:8000/api/v1/jobs \
  -F "ipa=@app.ipa" \
  -F "p12=@cert.p12" \
  -F "password=your_cert_password" \
  -F "mobileprovision=@profile.mobileprovision" \
  -F "bundle_id=com.custom.bundleid"

# Response: {"job_id": "xxx-xxx", "status": "queued", "poll_url": "..."}

# Kiểm tra trạng thái
curl http://localhost:8000/api/v1/jobs/{job_id}

# Response (khi hoàn thành):
# {
#   "status": "completed",
#   "download_url": "http://localhost:8000/api/v1/downloads/{job_id}/signed.ipa",
#   "install_url": "http://localhost:8000/api/v1/ota/{job_id}/install",
#   "itms_url": "itms-services://..."
# }
```

Mở link `install_url` trên Safari iPhone để cài đặt OTA trực tiếp.

---

## 📱 Hướng dẫn build iOS App

### Yêu cầu
- macOS với Xcode 15+
- Apple Developer Certificate (P12) & Provisioning Profile
- OpenSSL framework (cho zsign C++ engine)

### Build từ Xcode

```bash
# Mở project trong Xcode
open iOSApp/iOSApp.xcodeproj

# Hoặc build bằng command line
xcodebuild -project iOSApp/iOSApp.xcodeproj \
  -scheme iOSApp \
  -configuration Release \
  -destination "generic/platform=iOS" \
  archive -archivePath build/iOSApp.xcarchive
```

### Tính năng App iOS

| Tab | Chức năng |
|---|---|
| **Certificates** | Import & quản lý chứng chỉ P12 (lưu password trong Keychain) |
| **Profiles** | Import & quản lý file .mobileprovision |
| **IPA Library** | Import file IPA, xem metadata (Bundle ID, version, icon) |
| **Sign** | Chọn cert + profile + IPA → Ký trực tiếp on-device hoặc gửi lên server |
| **Server** | Cấu hình kết nối Backend Signing Server từ xa |

### Hai chế độ ký

1. **On-Device (Offline):** Sử dụng engine zsign C++ nhúng trực tiếp, ký ngay trên iPhone/iPad mà không cần kết nối server. Sau khi ký xong, app tự khởi động local HTTP server để cài qua OTA.

2. **Remote Server:** Upload file IPA/P12/Profile lên Backend Server, server ký xong trả về link OTA cài đặt. Phù hợp cho file IPA nặng hoặc thiết bị yếu.

---

## ⚙️ CI/CD - GitHub Actions

### Cấu hình

File workflow: `.github/workflows/build-ipa.yml`

#### Secrets cần thiết lập trên GitHub Repository

| Secret | Mô tả | Cách tạo |
|---|---|---|
| `P12_BASE64` | Certificate P12 encoded base64 | `base64 -i cert.p12 \| tr -d '\n'` |
| `P12_PASSWORD` | Password của file P12 | Nhập trực tiếp |
| `PROVISIONING_PROFILE_BASE64` | Profile encoded base64 | `base64 -i app.mobileprovision \| tr -d '\n'` |
| `DEVELOPMENT_TEAM` (tùy chọn) | Apple Team ID 10 ký tự | Ví dụ: `ABCDE12345` |

#### Trigger tự động

Workflow tự động chạy khi:
- Push code vào nhánh `main` hoặc `master` (khi thay đổi files trong `iOSApp/`, `scripts/`, hoặc workflow)
- Tạo tag version mới (`v*`)
- Pull Request vào `main` / `master`
- Kích hoạt thủ công (workflow_dispatch)

#### Các bước thực hiện

1. Checkout repository
2. Validate signing secrets
3. Select Xcode version (mặc định Xcode 15.4 trên macOS 14 Apple Silicon)
4. Provision ephemeral keychain & import P12 certificate
5. Install provisioning profile & parse metadata
6. Resolve Swift Package dependencies
7. Build `.xcarchive`
8. Export `.ipa` (hỗ trợ: development, ad-hoc, enterprise, app-store)
9. Upload artifact (lưu trữ 14 ngày)
10. Cleanup bảo mật (xóa keychain, profiles, temp files)

---

## 🧪 Chạy kiểm thử & Verification (Test Suite)

### 1. Automated Verification Harness (Standalone Pipeline Verification)

The standalone verification harness executes a 6-stage end-to-end verification against the backend signing server (probing health, submitting signing jobs with mock assets, polling to completion, downloading signed IPAs, verifying Apple Enterprise DTD manifests, and validating Safari 1-tap installation HTML landing pages).

**PowerShell (Windows native):**
```powershell
# Auto-spawns backend server, executes all 6 verification stages, and tears down cleanly
powershell -ExecutionPolicy Bypass -File tests/verify_signing_pipeline.ps1 -AutoStart

# Verify against an externally running server:
powershell -ExecutionPolicy Bypass -File tests/verify_signing_pipeline.ps1 -ServerUrl http://127.0.0.1:8000
```

**Python (Cross-platform):**
```bash
python tests/verify_signing_pipeline.py --auto-start
```

---

### 2. Comprehensive E2E Test Suite Runner

The master E2E runner orchestrates automated server lifecycle management, discovers and executes all test tiers, records metrics, and produces both machine-readable `results.json` and human-readable `summary.md`.

**PowerShell:**
```powershell
# Run full E2E suite (Tier 1 & Tier 2) with verbose logging
.\tests\e2e\run_e2e_tests.ps1 -Tier all -Verbose

# Run specific tier
.\tests\e2e\run_e2e_tests.ps1 -Tier 1
.\tests\e2e\run_e2e_tests.ps1 -Tier 2
```

**Python:**
```bash
python tests/e2e/run_e2e_tests.py --tier all --verbose
python tests/e2e/run_e2e_tests.py --tier 1
python tests/e2e/run_e2e_tests.py --tier 2
```

---

### 3. Backend Unit & Adversarial Tests

```bash
python -m pytest backend/tests/ -v
```

---

### 4. Root Architecture & Challenger Test Suites

```bash
python -m pytest tests/test_m2_challenger.py tests/test_m2_engine_security.py tests/test_m3_challenger.py -v
```

---

### 5. Offline Fixture Generation

Generate genuine mock test assets (`mock.p12`, `embedded.mobileprovision`, `mock_unsigned.ipa`):
```powershell
powershell -ExecutionPolicy Bypass -File scripts/generate_fixtures.ps1
```

Các file giả lập được lưu tại `tests/fixtures/` và `tests/e2e/fixtures/`:
- `mock_unsigned.ipa` — File IPA mẫu chứa ARM64 Mach-O executable
- `mock.p12` — Chứng chỉ RSA 2048-bit PKCS#12
- `embedded.mobileprovision` — Profile ASN.1 CMS SignedData Apple DTD

---

## 🔧 Cài đặt zsign Binary

### Linux (Ubuntu/Debian)

```bash
sudo apt update && sudo apt install -y g++ clang make libssl-dev git
git clone https://github.com/zhlynn/zsign.git
cd zsign
g++ *.cpp -lcrypto -O3 -o zsign
sudo mv zsign /usr/local/bin/
```

### macOS

```bash
brew install openssl
git clone https://github.com/zhlynn/zsign.git
cd zsign
g++ *.cpp -I$(brew --prefix openssl)/include -L$(brew --prefix openssl)/lib -lcrypto -O3 -o zsign
sudo mv zsign /usr/local/bin/
```

### Windows

Compile zsign bằng MinGW hoặc MSYS2 với OpenSSL, hoặc đặt `zsign.exe` vào `backend/bin/zsign.exe`.

---

## 📋 Triển khai Production

### Yêu cầu bắt buộc cho OTA qua Safari

- **HTTPS (SSL/TLS):** Apple bắt buộc link `itms-services://` phải trỏ tới URL HTTPS hợp lệ. Sử dụng Let's Encrypt, Cloudflare hoặc reverse proxy (Nginx/Caddy) với SSL.

### Ví dụ cấu hình Nginx reverse proxy

```nginx
server {
    listen 443 ssl;
    server_name sign.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/sign.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sign.yourdomain.com/privkey.pem;

    client_max_body_size 4G;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Đặt biến môi trường:
```bash
export SIGNING_BASE_URL="https://sign.yourdomain.com"
```

---

## 📜 License

MIT License
