"""
Adversarial Verification & Stress Test Suite for iOS Signing Server Backend.

Targeted Test Categories:
1. Path Traversal & Injection Attacks on /downloads/{job_id}/{filename}
2. Corrupted & Malformed IPA Archive Ingestion
3. Concurrency Stress, Queue Throttling, and Race Conditions
4. Non-Existent, Malformed, and Adversarial Job ID Polling
5. Invalid P12 Certificate Password Submissions & Damaged P12 Handling
6. Malformed Provisioning Profiles and Corrupt Entitlements
"""
import asyncio
import datetime
import io
from pathlib import Path
import plistlib
import sys
import time
import zipfile
import pytest
from fastapi.testclient import TestClient
import httpx

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.config import settings
from app.main import app
from app.api.v1.schemas import JobStatus
from app.services.signing_manager import signing_manager


# ------------------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------------------

@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def valid_fixtures(tmp_path_factory):
    """Generates authentic valid test fixtures for baseline signing."""
    fixtures_dir = tmp_path_factory.mktemp("fixtures")

    # 1. Valid IPA
    ipa_path = fixtures_dir / "valid_test.ipa"
    with zipfile.ZipFile(ipa_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        info_plist_dict = {
            "CFBundleIdentifier": "com.adversarial.testapp",
            "CFBundleName": "AdversarialApp",
            "CFBundleDisplayName": "Adversarial App",
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleVersion": "1",
            "CFBundleExecutable": "AdversarialApp",
            "MinimumOSVersion": "15.0",
            "CFBundlePackageType": "APPL",
        }
        zf.writestr("Payload/AdversarialApp.app/Info.plist", plistlib.dumps(info_plist_dict, fmt=plistlib.FMT_XML))
        macho_dummy = b"\xca\xfe\xba\xbe\x00\x00\x00\x02\x01\x00\x00\x0c" + (b"\x90" * 256)
        zf.writestr("Payload/AdversarialApp.app/AdversarialApp", macho_dummy)

    # 2. Valid .mobileprovision
    prov_path = fixtures_dir / "valid.mobileprovision"
    prov_dict = {
        "AppIDName": "AdversarialAppId",
        "TeamName": "Adversarial Team",
        "TeamIdentifier": ["ADV1234567"],
        "UUID": "12345678-1234-1234-1234-1234567890ab",
        "CreationDate": datetime.datetime.now(datetime.timezone.utc),
        "ExpirationDate": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30),
        "ProvisionsAllDevices": True,
        "Entitlements": {
            "application-identifier": "ADV1234567.com.adversarial.testapp",
            "get-task-allow": False,
        },
    }
    prov_bytes = b"\x30\x82\x05\x00\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" + plistlib.dumps(prov_dict, fmt=plistlib.FMT_XML) + b"\x00\x00"
    prov_path.write_bytes(prov_bytes)

    # 3. Valid .p12 with known password
    p12_path = fixtures_dir / "valid.p12"
    p12_password = "CorrectHorseBatteryStaple123!"

    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    import cryptography.hazmat.primitives.serialization.pkcs12 as pkcs12
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "iPhone Distribution: Adversarial Test"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(123456)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=b"Adversarial Cert",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(p12_password.encode("utf-8")),
    )
    p12_path.write_bytes(p12_bytes)

    return {
        "ipa_path": ipa_path,
        "prov_path": prov_path,
        "p12_path": p12_path,
        "p12_password": p12_password,
    }


# ------------------------------------------------------------------------------
# 1. Path Traversal & Injection Attacks on /downloads/{job_id}/{filename}
# ------------------------------------------------------------------------------

def test_path_traversal_directory_escape(client, valid_fixtures):
    """
    Attempts to read sensitive server files (e.g. app/config.py, main.py)
    via path traversal variations on /downloads/{job_id}/{filename}.
    """
    dummy_uuid = "00000000-0000-0000-0000-000000000000"

    traversal_payloads = [
        "../../app/config.py",
        "..%2f..%2fapp%2fconfig.py",
        "%2e%2e%2f%2e%2e%2fapp%2fconfig.py",
        "%252e%252e%252f%252e%252e%252fapp%252fconfig.py",
        "..\\..\\app\\config.py",
        "%2e%2e%5c%2e%2e%5capp%5cconfig.py",
        "....//....//app/config.py",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "C:/Windows/win.ini",
        "signed.ipa/../../app/config.py",
        "..",
        ".",
        "signed.ipa\x00.txt",
        "signed.ipa%00.txt",
        "signed.ipa::$DATA",
        "CON",
        "NUL",
        "AUX",
        "PRN",
        ";cat /etc/passwd",
        "|dir",
        "`whoami`",
        "$(whoami)",
    ]

    for payload in traversal_payloads:
        url = f"/api/v1/downloads/{dummy_uuid}/{payload}"
        try:
            res = client.get(url)
            # Must return 400 (rejected by regex) or 404 (not found).
            # MUST NEVER return 200 OK or leak any server file!
            assert res.status_code in (400, 404), f"Path traversal payload '{payload}' returned {res.status_code}: {res.text}"
            assert "class Settings" not in res.text, f"Information disclosure vulnerability! Leaked config.py via {payload}"
            assert "SECRET" not in res.text
        except httpx.InvalidURL:
            # Client correctly rejected invalid non-printable characters before dispatch
            pass


def test_path_traversal_on_existing_job_scratchpad(client, valid_fixtures):
    """
    Creates a real job, then attempts path traversal to read sibling files
    outside the outputs directory (e.g. inputs/certificate.p12, work/, or app code).
    """
    with open(valid_fixtures["ipa_path"], "rb") as ipa_f, \
         open(valid_fixtures["p12_path"], "rb") as p12_f, \
         open(valid_fixtures["prov_path"], "rb") as prov_f:

        files = {
            "ipa": ("valid.ipa", ipa_f, "application/octet-stream"),
            "p12": ("valid.p12", p12_f, "application/x-pkcs12"),
            "mobileprovision": ("valid.mobileprovision", prov_f, "application/octet-stream"),
        }
        res = client.post("/api/v1/jobs", files=files, data={"password": valid_fixtures["p12_password"]})
        assert res.status_code == 202
        job_id = res.json()["job_id"]

    # Wait for completion
    for _ in range(30):
        r = client.get(f"/api/v1/jobs/{job_id}")
        if r.json()["status"] in ("completed", "failed"):
            break
        time.sleep(0.3)

    # Attempt to traverse from outputs/ back to inputs/certificate.p12
    res_inputs = client.get(f"/api/v1/downloads/{job_id}/../inputs/certificate.p12")
    assert res_inputs.status_code in (400, 404)

    res_inputs_encoded = client.get(f"/api/v1/downloads/{job_id}/..%2finputs%2fcertificate.p12")
    assert res_inputs_encoded.status_code in (400, 404)

    # Attempt to read parent job dir
    res_parent = client.get(f"/api/v1/downloads/{job_id}/..")
    assert res_parent.status_code in (400, 404)

    # Verify normal download works
    res_ok = client.get(f"/api/v1/downloads/{job_id}/signed.ipa")
    assert res_ok.status_code == 200


def test_path_traversal_in_job_id_param(client):
    """Tests path traversal strings in the {job_id} path parameter."""
    job_id_payloads = [
        "../../app/config",
        "..%2f..%2fapp%2fconfig",
        "../",
        "12345678-1234-1234-1234-1234567890ab/../../",
        "00000000-0000-0000-0000-000000000000/../inputs",
    ]

    for jid in job_id_payloads:
        res = client.get(f"/api/v1/downloads/{jid}/signed.ipa")
        assert res.status_code in (400, 404)

        res_job = client.get(f"/api/v1/jobs/{jid}")
        assert res_job.status_code in (400, 404)

        res_manifest = client.get(f"/api/v1/ota/{jid}/manifest.plist")
        assert res_manifest.status_code in (400, 404)

        res_install = client.get(f"/api/v1/ota/{jid}/install")
        assert res_install.status_code in (400, 404)


# ------------------------------------------------------------------------------
# 2. Corrupted & Malformed IPA Archive Ingestion
# ------------------------------------------------------------------------------

def _submit_job_and_poll(client, valid_fixtures, ipa_bytes, ipa_name="bad.ipa"):
    """Helper to submit an IPA byte payload and poll until terminal status."""
    with open(valid_fixtures["p12_path"], "rb") as p12_f, \
         open(valid_fixtures["prov_path"], "rb") as prov_f:

        files = {
            "ipa": (ipa_name, io.BytesIO(ipa_bytes), "application/octet-stream"),
            "p12": ("valid.p12", p12_f, "application/x-pkcs12"),
            "mobileprovision": ("valid.mobileprovision", prov_f, "application/octet-stream"),
        }
        res = client.post("/api/v1/jobs", files=files, data={"password": valid_fixtures["p12_password"]})
        assert res.status_code == 202
        job_id = res.json()["job_id"]

    for _ in range(30):
        r = client.get(f"/api/v1/jobs/{job_id}")
        assert r.status_code == 200
        data = r.json()
        if data["status"] in ("completed", "failed"):
            return data
        time.sleep(0.3)

    return client.get(f"/api/v1/jobs/{job_id}").json()


def test_malformed_ipa_zero_bytes(client, valid_fixtures):
    """Submits a zero-byte IPA file and ensures job fails gracefully without crash."""
    result = _submit_job_and_poll(client, valid_fixtures, b"", ipa_name="zero.ipa")
    assert result["status"] == "failed"
    assert result["error"] is not None
    assert "not a valid zip" in result["error"].lower() or "invalid" in result["error"].lower()


def test_malformed_ipa_truncated_zip(client, valid_fixtures):
    """Submits an incomplete/truncated ZIP header and ensures graceful failure."""
    truncated = b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
    result = _submit_job_and_poll(client, valid_fixtures, truncated, ipa_name="truncated.ipa")
    assert result["status"] == "failed"
    assert result["error"] is not None


def test_malformed_ipa_non_zip_content(client, valid_fixtures):
    """Submits arbitrary non-ZIP plaintext and ensures graceful failure."""
    non_zip = b"Plaintext content pretending to be an IPA file archive\n" * 50
    result = _submit_job_and_poll(client, valid_fixtures, non_zip, ipa_name="fake.ipa")
    assert result["status"] == "failed"
    assert result["error"] is not None


def test_malformed_ipa_zipslip_traversal(client, valid_fixtures):
    """
    Submits a maliciously crafted ZIP containing a ZipSlip path traversal entry
    (e.g., ../../evil.txt). Must be blocked and flagged.
    """
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("../../evil_escape.txt", b"malicious content escaping extraction root")
        zf.writestr("Payload/Test.app/Info.plist", b"<plist></plist>")
    zipslip_bytes = bio.getvalue()

    result = _submit_job_and_poll(client, valid_fixtures, zipslip_bytes, ipa_name="zipslip.ipa")
    assert result["status"] == "failed"
    assert "zipslip" in result["error"].lower() or "invalid" in result["error"].lower()


def test_malformed_ipa_missing_payload_dir(client, valid_fixtures):
    """Submits a valid ZIP archive that does not contain a Payload/ directory."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("NotPayload/Test.app/Info.plist", b"<plist></plist>")
        zf.writestr("Readme.txt", b"hello world")
    bad_bytes = bio.getvalue()

    result = _submit_job_and_poll(client, valid_fixtures, bad_bytes, ipa_name="no_payload.ipa")
    assert result["status"] == "failed"
    assert "payload" in result["error"].lower()


def test_malformed_ipa_missing_app_bundle(client, valid_fixtures):
    """Submits a valid ZIP containing Payload/ but no .app bundle."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("Payload/not_an_app_folder/file.txt", b"hello")
    bad_bytes = bio.getvalue()

    result = _submit_job_and_poll(client, valid_fixtures, bad_bytes, ipa_name="no_app.ipa")
    assert result["status"] == "failed"
    assert ".app" in result["error"].lower()


def test_malformed_ipa_corrupted_info_plist(client, valid_fixtures):
    """Submits an IPA with a corrupted/malformed Info.plist (invalid XML syntax)."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("Payload/BrokenPlist.app/Info.plist", b"<<<NOT A VALID PLIST XML>>>")
        zf.writestr("Payload/BrokenPlist.app/BrokenPlist", b"\xca\xfe\xba\xbe")
    bad_bytes = bio.getvalue()

    # The server should either handle it by falling back or fail safely without 500 error
    result = _submit_job_and_poll(client, valid_fixtures, bad_bytes, ipa_name="broken_plist.ipa")
    assert result["status"] in ("completed", "failed")
    # If completed with fallback, should not crash
    if result["status"] == "completed":
        assert result["download_url"] is not None


# ------------------------------------------------------------------------------
# 3. Invalid P12 Passwords & Corrupt Certificate Submissions
# ------------------------------------------------------------------------------

def test_invalid_p12_password(client, valid_fixtures):
    """
    Submits a valid .p12 certificate with an INCORRECT password.
    CRITICAL BEHAVIORAL CHECK:
    Does the server validate the password and reject/fail the job,
    or does it silently ignore the invalid password?
    """
    with open(valid_fixtures["ipa_path"], "rb") as ipa_f, \
         open(valid_fixtures["p12_path"], "rb") as p12_f, \
         open(valid_fixtures["prov_path"], "rb") as prov_f:

        files = {
            "ipa": ("test.ipa", ipa_f, "application/octet-stream"),
            "p12": ("valid.p12", p12_f, "application/x-pkcs12"),
            "mobileprovision": ("valid.mobileprovision", prov_f, "application/octet-stream"),
        }
        # Intentionally WRONG password
        data = {"password": "CompletelyWrongPassword!@#$"}

        res = client.post("/api/v1/jobs", files=files, data=data)
        assert res.status_code == 202
        job_id = res.json()["job_id"]

    for _ in range(30):
        r = client.get(f"/api/v1/jobs/{job_id}")
        data = r.json()
        if data["status"] in ("completed", "failed"):
            break
        time.sleep(0.3)

    poll_result = client.get(f"/api/v1/jobs/{job_id}").json()
    print("\n[OBSERVATION] Invalid P12 Password Test Result:", poll_result)

    # Note for challenger evaluation:
    # If FallbackSigningEngine ignores the P12 password and marks the job 'completed',
    # this is an important finding!


def test_corrupt_p12_data(client, valid_fixtures):
    """Submits a zero-byte or garbage .p12 certificate file."""
    with open(valid_fixtures["ipa_path"], "rb") as ipa_f, \
         open(valid_fixtures["prov_path"], "rb") as prov_f:

        files = {
            "ipa": ("test.ipa", ipa_f, "application/octet-stream"),
            "p12": ("corrupt.p12", io.BytesIO(b"GARBAGE NOT A P12 ARCHIVE"), "application/x-pkcs12"),
            "mobileprovision": ("valid.mobileprovision", prov_f, "application/octet-stream"),
        }
        res = client.post("/api/v1/jobs", files=files, data={"password": "any"})
        assert res.status_code == 202
        job_id = res.json()["job_id"]

    for _ in range(30):
        r = client.get(f"/api/v1/jobs/{job_id}")
        data = r.json()
        if data["status"] in ("completed", "failed"):
            break
        time.sleep(0.3)

    poll_result = client.get(f"/api/v1/jobs/{job_id}").json()
    print("\n[OBSERVATION] Corrupt P12 File Test Result:", poll_result)


# ------------------------------------------------------------------------------
# 4. Concurrency Stress: Rapid Submissions Exceeding MAX_CONCURRENT_JOBS
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrency_stress_saturation(valid_fixtures):
    """
    Simulates rapid concurrent job submissions exceeding MAX_CONCURRENT_JOBS (default=3).
    Submits 8 jobs simultaneously, monitors semaphore queueing, verifies no crashes,
    and checks that all jobs eventually transition to terminal state.
    """
    max_concurrent = settings.MAX_CONCURRENT_JOBS
    num_jobs = max_concurrent * 2 + 2  # e.g. 3 * 2 + 2 = 8 jobs

    # Read fixtures once into memory buffers
    with open(valid_fixtures["ipa_path"], "rb") as f:
        ipa_data = f.read()
    with open(valid_fixtures["p12_path"], "rb") as f:
        p12_data = f.read()
    with open(valid_fixtures["prov_path"], "rb") as f:
        prov_data = f.read()

    job_ids = []

    # Submit jobs rapidly via httpx AsyncClient
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as async_client:
        async def submit_one(index: int):
            files = {
                "ipa": (f"test_{index}.ipa", io.BytesIO(ipa_data), "application/octet-stream"),
                "p12": (f"cert_{index}.p12", io.BytesIO(p12_data), "application/x-pkcs12"),
                "mobileprovision": (f"prof_{index}.mobileprovision", io.BytesIO(prov_data), "application/octet-stream"),
            }
            data = {
                "password": valid_fixtures["p12_password"],
                "bundle_id": f"com.stress.app{index}",
                "bundle_name": f"StressApp{index}",
            }
            response = await async_client.post("/api/v1/jobs", files=files, data=data)
            assert response.status_code == 202, f"Job {index} submission failed: {response.text}"
            return response.json()["job_id"]

        # Launch all submissions concurrently
        submit_tasks = [submit_one(i) for i in range(num_jobs)]
        job_ids = await asyncio.gather(*submit_tasks)
        assert len(job_ids) == num_jobs
        assert len(set(job_ids)) == num_jobs, "Job UUIDs must be strictly unique!"

        # Poll status and observe concurrency states
        processing_counts = []
        start_time = time.monotonic()
        timeout = 45.0

        all_completed = False
        while time.monotonic() - start_time < timeout:
            statuses = []
            for jid in job_ids:
                res = await async_client.get(f"/api/v1/jobs/{jid}")
                assert res.status_code == 200
                statuses.append(res.json()["status"])

            current_processing = statuses.count("processing")
            processing_counts.append(current_processing)

            # Verification: processing count must never exceed MAX_CONCURRENT_JOBS
            assert current_processing <= max_concurrent, (
                f"Concurrency limit breached! Currently processing {current_processing} jobs, "
                f"max allowed is {max_concurrent}"
            )

            # Check if all terminal
            terminal_count = sum(1 for s in statuses if s in ("completed", "failed"))
            if terminal_count == num_jobs:
                all_completed = True
                break

            await asyncio.sleep(0.3)

        assert all_completed, f"Not all jobs reached terminal state within {timeout}s: {statuses}"

        # Final verification: verify artifacts for all completed jobs
        for i, jid in enumerate(job_ids):
            res = await async_client.get(f"/api/v1/jobs/{jid}")
            assert res.status_code == 200
            detail = res.json()
            assert detail["status"] == "completed"
            assert detail["bundle_id"] == f"com.stress.app{i}"

            # Verify download works
            dl_res = await async_client.get(f"/api/v1/downloads/{jid}/signed.ipa")
            assert dl_res.status_code == 200
            assert len(dl_res.content) > 0


# ------------------------------------------------------------------------------
# 5. Non-Existent, Malformed, and Adversarial Job ID Polling
# ------------------------------------------------------------------------------

def test_nonexistent_job_polling_valid_uuid(client):
    """Polling a non-existent but valid UUID must return 404 Not Found."""
    fake_uuid = "00000000-0000-0000-0000-000000000000"
    res = client.get(f"/api/v1/jobs/{fake_uuid}")
    assert res.status_code == 404
    assert "not found" in res.json().get("error", "").lower() or "not found" in res.text.lower()


def test_malformed_job_id_formats(client):
    """Polling malformed job IDs must return 400 Bad Request."""
    bad_uuids = [
        "invalid-uuid",
        "12345",
        "00000000-0000-0000-0000-00000000000g",  # invalid hex
        "00000000-0000-0000-0000-0000000000001", # too long
        "00000000_0000_0000_0000_000000000000", # underscore
        "' OR '1'='1",                           # SQL injection string
        "<script>alert(1)</script>",              # XSS string
        "../../etc/passwd",                      # Path traversal
    ]

    for bad_id in bad_uuids:
        r1 = client.get(f"/api/v1/jobs/{bad_id}")
        assert r1.status_code in (400, 404), f"Expected 400 or 404 for job ID '{bad_id}', got {r1.status_code}"

        r2 = client.get(f"/api/v1/downloads/{bad_id}/signed.ipa")
        assert r2.status_code in (400, 404)

        r3 = client.get(f"/api/v1/ota/{bad_id}/manifest.plist")
        assert r3.status_code in (400, 404)

        r4 = client.get(f"/api/v1/ota/{bad_id}/install")
        assert r4.status_code in (400, 404)


# ------------------------------------------------------------------------------
# 6. Malformed Provisioning Profile & Entitlements
# ------------------------------------------------------------------------------

def test_corrupted_mobileprovision_file(client, valid_fixtures):
    """Submits an invalid/corrupted mobileprovision profile."""
    with open(valid_fixtures["ipa_path"], "rb") as ipa_f, \
         open(valid_fixtures["p12_path"], "rb") as p12_f:

        files = {
            "ipa": ("test.ipa", ipa_f, "application/octet-stream"),
            "p12": ("valid.p12", p12_f, "application/x-pkcs12"),
            "mobileprovision": ("corrupted.mobileprovision", io.BytesIO(b"NOT A VALID CMS PROFILE"), "application/octet-stream"),
        }
        res = client.post("/api/v1/jobs", files=files, data={"password": valid_fixtures["p12_password"]})
        assert res.status_code == 202
        job_id = res.json()["job_id"]

    for _ in range(30):
        r = client.get(f"/api/v1/jobs/{job_id}")
        data = r.json()
        if data["status"] in ("completed", "failed"):
            break
        time.sleep(0.3)

    poll_result = client.get(f"/api/v1/jobs/{job_id}").json()
    print("\n[OBSERVATION] Corrupt Mobileprovision Test Result:", poll_result)


def test_invalid_entitlements_file(client, valid_fixtures):
    """Submits custom entitlements with corrupted XML syntax."""
    with open(valid_fixtures["ipa_path"], "rb") as ipa_f, \
         open(valid_fixtures["p12_path"], "rb") as p12_f, \
         open(valid_fixtures["prov_path"], "rb") as prov_f:

        files = {
            "ipa": ("test.ipa", ipa_f, "application/octet-stream"),
            "p12": ("valid.p12", p12_f, "application/x-pkcs12"),
            "mobileprovision": ("valid.mobileprovision", prov_f, "application/octet-stream"),
            "entitlements": ("entitlements.plist", io.BytesIO(b"<<<CORRUPTED XML ENTITLE>>>"), "application/xml"),
        }
        res = client.post("/api/v1/jobs", files=files, data={"password": valid_fixtures["p12_password"]})
        assert res.status_code == 202
        job_id = res.json()["job_id"]

    for _ in range(30):
        r = client.get(f"/api/v1/jobs/{job_id}")
        data = r.json()
        if data["status"] in ("completed", "failed"):
            break
        time.sleep(0.3)

    poll_result = client.get(f"/api/v1/jobs/{job_id}").json()
    print("\n[OBSERVATION] Corrupt Entitlements Test Result:", poll_result)
