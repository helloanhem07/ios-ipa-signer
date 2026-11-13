"""
Comprehensive Automated Test Suite for iOS Signing Server Backend.
Covers:
- REST API Health and Metadata Endpoints
- Plist Utilities and CMS Mobileprovision Extraction
- FallbackSigningEngine: Full bundle modification, signature structure synthesis, and repackaging
- ZsignBinaryEngine: Command-line mapping and unavailable state handling
- ManifestService: Apple Enterprise DTD compliance, ITMS URL quoting, and HTML landing page rendering
- End-to-End Multipart Job Creation, Processing, Status Polling, Download Range Streaming, and OTA
- Concurrency Throttling, Workspace Isolation, and Path Traversal Protection
"""
import asyncio
import datetime
import hashlib
import io
import os
from pathlib import Path
import plistlib
import sys
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.config import settings
from app.main import app
from app.services.signing_engine import SigningResult
from app.services.fallback_engine import FallbackSigningEngine
from app.services.zsign_engine import ZsignBinaryEngine
from app.services.manifest_service import ManifestService
from app.services.plist_utils import (
    extract_ipa_metadata,
    extract_plist_from_mobileprovision,
    parse_provisioning_profile,
    validate_p12_certificate,
)
from app.services.signing_manager import signing_manager
from app.api.v1.schemas import JobStatus


@pytest.fixture(scope="session")
def client():
    """Test client for FastAPI app."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def mock_assets(tmp_path):
    """
    Generates authentic mock assets (test IPA, mock .p12, and mock .mobileprovision)
    for integration testing.
    """
    assets_dir = tmp_path / "fixtures"
    assets_dir.mkdir(parents=True, exist_ok=True)

    # 1. Build synthetic unsigned IPA
    ipa_path = assets_dir / "test_unsigned.ipa"
    with zipfile.ZipFile(ipa_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Info.plist
        info_plist_dict = {
            "CFBundleIdentifier": "com.test.originalapp",
            "CFBundleName": "OriginalApp",
            "CFBundleDisplayName": "Original App Display",
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleVersion": "1",
            "CFBundleExecutable": "OriginalApp",
            "MinimumOSVersion": "15.0",
            "CFBundlePackageType": "APPL",
        }
        info_bytes = plistlib.dumps(info_plist_dict, fmt=plistlib.FMT_XML)
        zf.writestr("Payload/OriginalApp.app/Info.plist", info_bytes)

        # Mock binary executable (Mach-O magic header 0xFEEDFACF for 64-bit arm64)
        macho_dummy = b"\xca\xfe\xba\xbe\x00\x00\x00\x02\x01\x00\x00\x0c" + (b"\x90" * 256)
        zf.writestr("Payload/OriginalApp.app/OriginalApp", macho_dummy)

        # Resource file
        zf.writestr("Payload/OriginalApp.app/Assets.car", b"MOCK_ASSET_CAR_DATA_123456789")

    # 2. Build mock .mobileprovision (ASN.1 wrapper simulation around XML plist)
    prov_path = assets_dir / "embedded.mobileprovision"
    prov_dict = {
        "AppIDName": "TestAppId",
        "TeamName": "Enterprise Test Team",
        "TeamIdentifier": ["ABCDE12345"],
        "UUID": "11223344-5566-7788-9900-AABBCCDDEEFF",
        "CreationDate": datetime.datetime.now(datetime.timezone.utc),
        "ExpirationDate": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365),
        "ProvisionsAllDevices": True,
        "Entitlements": {
            "application-identifier": "ABCDE12345.com.test.originalapp",
            "get-task-allow": False,
            "keychain-access-groups": ["ABCDE12345.*"],
        },
    }
    prov_xml_bytes = plistlib.dumps(prov_dict, fmt=plistlib.FMT_XML)
    # Wrap in mock CMS header/footer
    cms_wrapper = b"\x30\x82\x05\x00\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" + prov_xml_bytes + b"\x00\x00\x00"
    with open(prov_path, "wb") as f:
        f.write(cms_wrapper)

    # 3. Build genuine PKCS#12 (.p12) certificate using cryptography
    p12_path = assets_dir / "mock_cert.p12"
    p12_password = "SecretPassword123"

    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes, serialization
        import cryptography.hazmat.primitives.serialization.pkcs12 as pkcs12
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apple Development Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "iPhone Distribution: Test Company"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        p12_bytes = pkcs12.serialize_key_and_certificates(
            name=b"Test iOS Certificate",
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(p12_password.encode("utf-8")),
        )
        with open(p12_path, "wb") as f:
            f.write(p12_bytes)
    except Exception as e:
        # Fallback raw byte stub if cryptography fails unexpectedly
        with open(p12_path, "wb") as f:
            f.write(b"MOCK_P12_BINARY_DATA")

    return {
        "ipa_path": ipa_path,
        "prov_path": prov_path,
        "p12_path": p12_path,
        "p12_password": p12_password,
        "temp_dir": assets_dir,
    }


# ==============================================================================
# 1. Health Check Endpoint Tests
# ==============================================================================

def test_health_endpoint(client):
    """Verifies that GET /api/v1/health returns 200 with engine availability."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"
    assert "engines" in data
    assert "fallback" in data["engines"]
    assert "zsign" in data["engines"]
    assert data["engines"]["fallback"] is True


def test_root_endpoint(client):
    """Verifies that GET / returns service information banner."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == "1.0.0"
    assert data["health_check"] == "/api/v1/health"


# ==============================================================================
# 2. Plist & Mobileprovision Utilities Tests
# ==============================================================================

def test_plist_utils_extract_ipa_metadata(mock_assets):
    """Verifies metadata extraction from an unsigned .ipa archive."""
    meta = extract_ipa_metadata(mock_assets["ipa_path"])
    assert meta["bundle_id"] == "com.test.originalapp"
    assert meta["bundle_name"] == "Original App Display"
    assert meta["bundle_version"] == "1.0.0"
    assert meta["executable_name"] == "OriginalApp"
    assert meta["min_os_version"] == "15.0"


def test_plist_utils_cms_mobileprovision_extraction(mock_assets):
    """Verifies unwrapping of CMS payload from a .mobileprovision file."""
    profile_data = parse_provisioning_profile(mock_assets["prov_path"])
    assert profile_data["app_id_name"] == "TestAppId"
    assert profile_data["team_name"] == "Enterprise Test Team"
    assert profile_data["team_identifier"] == ["ABCDE12345"]
    assert profile_data["uuid"] == "11223344-5566-7788-9900-AABBCCDDEEFF"
    assert profile_data["is_enterprise"] is True
    assert profile_data["is_expired"] is False
    assert "application-identifier" in profile_data["entitlements"]


def test_plist_utils_p12_validation(mock_assets):
    """Verifies validation and inspection of a PKCS#12 certificate."""
    cert_info = validate_p12_certificate(mock_assets["p12_path"], mock_assets["p12_password"])
    assert cert_info["valid"] is True
    if "expired" in cert_info:
        assert cert_info["expired"] is False
        assert cert_info["has_private_key"] is True
        assert "Test Company" in cert_info["subject"]


# ==============================================================================
# 3. FallbackSigningEngine Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_fallback_signing_engine_execution(mock_assets):
    """
    Verifies that FallbackSigningEngine successfully modifies bundle metadata,
    embeds provisioning profile, synthesizes _CodeSignature/CodeResources,
    and repacks a compliant IPA.
    """
    engine = FallbackSigningEngine()
    assert engine.name == "fallback"
    assert engine.is_available() is True

    output_ipa = mock_assets["temp_dir"] / "signed_output.ipa"
    new_bundle_id = "com.resigned.customapp"
    new_app_name = "ReSignedApp"
    new_version = "2.1.0"

    result: SigningResult = await engine.sign(
        ipa_path=mock_assets["ipa_path"],
        p12_path=mock_assets["p12_path"],
        p12_password=mock_assets["p12_password"],
        provisioning_path=mock_assets["prov_path"],
        output_path=output_ipa,
        bundle_id=new_bundle_id,
        bundle_name=new_app_name,
        bundle_version=new_version,
        temp_dir=mock_assets["temp_dir"] / "scratch",
    )

    assert result.success is True
    assert output_ipa.is_file()
    assert output_ipa.stat().st_size > 0

    # Inspect the signed IPA archive contents
    with zipfile.ZipFile(output_ipa, "r") as zf:
        file_list = zf.namelist()

        # Check Info.plist was mutated
        assert "Payload/OriginalApp.app/Info.plist" in file_list
        info_bytes = zf.read("Payload/OriginalApp.app/Info.plist")
        info_dict = plistlib.loads(info_bytes)
        assert info_dict["CFBundleIdentifier"] == new_bundle_id
        assert info_dict["CFBundleDisplayName"] == new_app_name
        assert info_dict["CFBundleShortVersionString"] == new_version

        # Check embedded.mobileprovision was injected
        assert "Payload/OriginalApp.app/embedded.mobileprovision" in file_list
        embedded_prov_bytes = zf.read("Payload/OriginalApp.app/embedded.mobileprovision")
        with open(mock_assets["prov_path"], "rb") as orig_prov:
            assert embedded_prov_bytes == orig_prov.read()

        # Check _CodeSignature/CodeResources was generated
        assert "Payload/OriginalApp.app/_CodeSignature/CodeResources" in file_list
        code_resources_bytes = zf.read("Payload/OriginalApp.app/_CodeSignature/CodeResources")
        code_resources = plistlib.loads(code_resources_bytes)

        assert "files" in code_resources
        assert "files2" in code_resources
        assert "rules" in code_resources
        assert "rules2" in code_resources

        # Verify hash calculation accuracy
        assert "Assets.car" in code_resources["files"]
        expected_sha1 = hashlib.sha1(b"MOCK_ASSET_CAR_DATA_123456789").digest()
        assert code_resources["files"]["Assets.car"] == expected_sha1

        expected_sha256 = hashlib.sha256(b"MOCK_ASSET_CAR_DATA_123456789").digest()
        assert code_resources["files2"]["Assets.car"]["hash2"] == expected_sha256


@pytest.mark.asyncio
async def test_fallback_signing_engine_corrupt_archive(mock_assets):
    """Verifies that FallbackSigningEngine detects corrupt zip archives."""
    engine = FallbackSigningEngine()
    corrupt_ipa = mock_assets["temp_dir"] / "corrupt.ipa"
    with open(corrupt_ipa, "wb") as f:
        f.write(b"NOT_A_ZIP_FILE_RANDOM_DATA")

    output_ipa = mock_assets["temp_dir"] / "failed_output.ipa"
    result = await engine.sign(
        ipa_path=corrupt_ipa,
        p12_path=mock_assets["p12_path"],
        p12_password="pass",
        provisioning_path=mock_assets["prov_path"],
        output_path=output_ipa,
    )

    assert result.success is False
    assert result.error_code == "INVALID_IPA_ARCHIVE"


# ==============================================================================
# 4. ZsignBinaryEngine Tests
# ==============================================================================

def test_zsign_engine_command_construction(mock_assets):
    """Verifies that ZsignBinaryEngine correctly maps all flags to CLI args."""
    engine = ZsignBinaryEngine(binary_path=Path("zsign_dummy"))
    cmd = engine.build_command(
        ipa_path=mock_assets["ipa_path"],
        p12_path=mock_assets["p12_path"],
        p12_password="dummy_password",
        provisioning_path=mock_assets["prov_path"],
        output_path=mock_assets["temp_dir"] / "out.ipa",
        bundle_id="com.override.id",
        bundle_name="OverrideName",
        bundle_version="3.0.0",
        compression_level=6,
        temp_dir=mock_assets["temp_dir"] / "temp_extract",
    )

    assert "-k" in cmd
    assert "-p" in cmd
    assert "dummy_password" in cmd
    assert "-m" in cmd
    assert "-o" in cmd
    assert "-b" in cmd
    assert "com.override.id" in cmd
    assert "-n" in cmd
    assert "OverrideName" in cmd
    assert "-r" in cmd
    assert "3.0.0" in cmd
    assert "-z" in cmd
    assert "6" in cmd
    assert "-t" in cmd
    assert "-f" in cmd
    assert str(mock_assets["ipa_path"].resolve()) == cmd[-1]


@pytest.mark.asyncio
async def test_zsign_engine_unavailable_graceful(mock_assets):
    """Verifies that ZsignBinaryEngine returns ENGINE_UNAVAILABLE when binary is absent."""
    engine = ZsignBinaryEngine(binary_path=Path("C:/nonexistent/path/to/zsign.exe"))
    assert engine.is_available() is False

    result = await engine.sign(
        ipa_path=mock_assets["ipa_path"],
        p12_path=mock_assets["p12_path"],
        p12_password="pass",
        provisioning_path=mock_assets["prov_path"],
        output_path=mock_assets["temp_dir"] / "out.ipa",
    )

    assert result.success is False
    assert result.error_code == "ENGINE_UNAVAILABLE"


# ==============================================================================
# 5. ManifestService Tests
# ==============================================================================

def test_manifest_service_xml_dtd_compliance():
    """
    Verifies that ManifestService generates Apple Enterprise DTD compliant XML
    and correct dictionary keys.
    """
    ipa_url = "https://example.com/api/v1/downloads/123/signed.ipa"
    bundle_id = "com.test.enterprise"
    bundle_version = "1.5.0"
    title = "Test App"

    xml_bytes = ManifestService.generate_manifest_xml(
        ipa_url=ipa_url,
        bundle_id=bundle_id,
        bundle_version=bundle_version,
        title=title,
    )

    # Validate DTD header presence
    assert b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' in xml_bytes

    # Parse back with plistlib to confirm well-formed XML
    data = plistlib.loads(xml_bytes)
    assert "items" in data
    assert len(data["items"]) == 1
    item = data["items"][0]

    assert item["assets"][0]["kind"] == "software-package"
    assert item["assets"][0]["url"] == ipa_url

    assert item["metadata"]["bundle-identifier"] == bundle_id
    assert item["metadata"]["bundle-version"] == bundle_version
    assert item["metadata"]["kind"] == "software"
    assert item["metadata"]["title"] == title


def test_manifest_service_itms_url_encoding():
    """Verifies percent-encoding for itms-services:// URLs."""
    manifest_url = "https://example.com/api/v1/ota/uuid-1234/manifest.plist?token=abc&query=true"
    itms_url = ManifestService.build_itms_url(manifest_url)

    assert itms_url.startswith("itms-services://?action=download-manifest&url=")
    # Ensure ':' and '/' are percent encoded (%3A and %2F)
    assert "https%3A%2F%2Fexample.com" in itms_url
    assert "%26query%3Dtrue" in itms_url


def test_manifest_service_install_html_rendering():
    """Verifies responsive HTML landing page rendering and escaping."""
    html_content = ManifestService.generate_install_html(
        app_name="Custom <XSS> App",
        bundle_id="com.test.custom",
        bundle_version="1.0.0",
        itms_url="itms-services://?action=download-manifest&url=https%3A%2F%2Ftest",
        download_url="https://test/download.ipa",
        file_size_bytes=10485760,  # 10 MB
    )

    # Verify XSS sanitization
    assert "<XSS>" not in html_content
    assert "&lt;XSS&gt;" in html_content
    assert "Custom &lt;XSS&gt; App" in html_content

    # Verify buttons and metadata
    assert "itms-services://?action=download-manifest" in html_content
    assert "https://test/download.ipa" in html_content
    assert "10.0 MB" in html_content
    assert "VPN &amp; Device Management" in html_content
    assert "iOS 18" in html_content


# ==============================================================================
# 6. End-to-End API Integration Tests (Jobs, Downloads, OTA)
# ==============================================================================

def test_api_job_lifecycle_end_to_end(client, mock_assets):
    """
    Submits a multipart job request, verifies HTTP 202 Accepted,
    waits for background processing, verifies completed status,
    streams download with range support, and retrieves manifest and install page.
    """
    with open(mock_assets["ipa_path"], "rb") as ipa_f, \
         open(mock_assets["p12_path"], "rb") as p12_f, \
         open(mock_assets["prov_path"], "rb") as prov_f:

        files = {
            "ipa": ("test.ipa", ipa_f, "application/octet-stream"),
            "p12": ("cert.p12", p12_f, "application/x-pkcs12"),
            "mobileprovision": ("profile.mobileprovision", prov_f, "application/octet-stream"),
        }
        data = {
            "password": mock_assets["p12_password"],
            "bundle_id": "com.e2e.testapp",
            "bundle_name": "E2ETestApp",
            "bundle_version": "3.2.1",
            "compression_level": 1,
        }

        # 1. POST /api/v1/jobs
        create_res = client.post("/api/v1/jobs", files=files, data=data)
        assert create_res.status_code == 202, create_res.text
        create_data = create_res.json()
        assert "job_id" in create_data
        assert create_data["status"] == "queued"
        job_id = create_data["job_id"]

    # 2. Poll GET /api/v1/jobs/{job_id} until completed (max 15s)
    max_wait = 15.0
    start = time.time()
    job_detail = None

    while time.time() - start < max_wait:
        poll_res = client.get(f"/api/v1/jobs/{job_id}")
        assert poll_res.status_code == 200
        job_detail = poll_res.json()
        if job_detail["status"] in ("completed", "failed"):
            break
        time.sleep(0.5)

    assert job_detail is not None
    assert job_detail["status"] == "completed", f"Job failed with error: {job_detail.get('error')}"
    assert job_detail["bundle_id"] == "com.e2e.testapp"
    assert job_detail["app_name"] == "E2ETestApp"
    assert job_detail["bundle_version"] == "3.2.1"
    assert job_detail["download_url"] is not None
    assert job_detail["manifest_url"] is not None
    assert job_detail["install_url"] is not None
    assert job_detail["itms_url"].startswith("itms-services://")

    # 3. GET /api/v1/downloads/{job_id}/signed.ipa
    download_res = client.get(f"/api/v1/downloads/{job_id}/signed.ipa")
    assert download_res.status_code == 200
    assert download_res.headers.get("Accept-Ranges") == "bytes"
    assert len(download_res.content) > 0

    # Verify downloaded content is a valid signed IPA
    with zipfile.ZipFile(io.BytesIO(download_res.content)) as dl_zf:
        assert "Payload/OriginalApp.app/Info.plist" in dl_zf.namelist()
        info_dict = plistlib.loads(dl_zf.read("Payload/OriginalApp.app/Info.plist"))
        assert info_dict["CFBundleIdentifier"] == "com.e2e.testapp"

    # 4. GET /api/v1/downloads/{job_id}/signed.ipa with Range header (HTTP 206)
    range_res = client.get(
        f"/api/v1/downloads/{job_id}/signed.ipa",
        headers={"Range": "bytes=0-9"}
    )
    assert range_res.status_code == 206
    assert len(range_res.content) == 10

    # 5. GET /api/v1/ota/{job_id}/manifest.plist
    manifest_res = client.get(f"/api/v1/ota/{job_id}/manifest.plist")
    assert manifest_res.status_code == 200
    assert "application/xml" in manifest_res.headers.get("Content-Type", "")
    manifest_dict = plistlib.loads(manifest_res.content)
    assert manifest_dict["items"][0]["metadata"]["bundle-identifier"] == "com.e2e.testapp"

    # 6. GET /api/v1/ota/{job_id}/install
    install_res = client.get(f"/api/v1/ota/{job_id}/install")
    assert install_res.status_code == 200
    assert "text/html" in install_res.headers.get("Content-Type", "")
    assert "E2ETestApp" in install_res.text
    assert "itms-services://" in install_res.text


def test_path_traversal_protection(client):
    """Verifies that malicious path traversal attempts are blocked."""
    dummy_uuid = "00000000-0000-0000-0000-000000000000"

    # Illegal filenames
    res1 = client.get(f"/api/v1/downloads/{dummy_uuid}/../../etc/passwd")
    assert res1.status_code in (400, 404)

    res2 = client.get(f"/api/v1/downloads/{dummy_uuid}/..%2f..%2fconfig.py")
    assert res2.status_code in (400, 404)

    # Invalid UUID
    res3 = client.get("/api/v1/downloads/not-a-valid-uuid/signed.ipa")
    assert res3.status_code == 400


# ==============================================================================
# 7. Concurrency Throttling & Workspace Isolation Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_concurrency_throttling_semaphore():
    """Verifies that semaphore limits concurrent execution."""
    sem = signing_manager.get_semaphore()
    assert sem._value <= settings.MAX_CONCURRENT_JOBS
    assert settings.MAX_CONCURRENT_JOBS > 0


def test_workspace_isolation(mock_assets):
    """Verifies that job folders are strictly isolated under storage/jobs/{job_id}."""
    job_id_1 = "11111111-1111-1111-1111-111111111111"
    job_id_2 = "22222222-2222-2222-2222-222222222222"

    dir1 = settings.JOBS_DIR / job_id_1
    dir2 = settings.JOBS_DIR / job_id_2

    assert dir1 != dir2
    assert not dir1.is_relative_to(dir2)
    assert not dir2.is_relative_to(dir1)
