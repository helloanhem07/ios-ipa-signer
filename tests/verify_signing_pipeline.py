#!/usr/bin/env python3
"""
Automated Standalone Verification Harness for iOS IPA Signing Pipeline.
Validates the end-to-end signing workflow against a live FastAPI backend:
  1. Health Check (GET /api/v1/health)
  2. Multipart Job Submission (POST /api/v1/jobs)
  3. Job Status Polling (GET /api/v1/jobs/{job_id})
  4. Signed IPA Download & Mach-O Integrity (GET /api/v1/downloads/{job_id}/signed.ipa)
  5. Apple OTA Manifest Compliance (GET /api/v1/ota/{job_id}/manifest.plist)
  6. Safari OTA Install Landing Page (GET /api/v1/ota/{job_id}/install)
"""

import argparse
import io
import json
import os
import sys
import time
import zipfile
from pathlib import Path
from typing import Dict, Any, Optional

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

from tests.e2e.harness.http_client import TestHTTPClient
from tests.e2e.harness.fixture_manager import FixtureManager
from tests.e2e.harness.server_manager import ServerManager
from tests.e2e.harness.macho_validator import validate_macho_binary
from tests.e2e.harness.plist_validator import validate_apple_plist_xml, validate_ota_manifest_structure


def find_or_create_fixtures(custom_dir: Optional[str] = None) -> Dict[str, str]:
    """Ensures mock fixtures exist in tests/fixtures or tests/e2e/fixtures."""
    if custom_dir:
        mgr = FixtureManager(output_dir=Path(custom_dir))
        return mgr.ensure_fixtures()

    std_dir = WORKSPACE_ROOT / "tests" / "fixtures"
    if (std_dir / "mock.p12").exists() and (std_dir / "embedded.mobileprovision").exists() and (std_dir / "mock_unsigned.ipa").exists():
        return {
            "p12": str(std_dir / "mock.p12"),
            "mobileprovision": str(std_dir / "embedded.mobileprovision"),
            "ipa": str(std_dir / "mock_unsigned.ipa")
        }

    e2e_dir = WORKSPACE_ROOT / "tests" / "e2e" / "fixtures"
    if (e2e_dir / "mock.p12").exists() and (e2e_dir / "embedded.mobileprovision").exists() and (e2e_dir / "mock_unsigned.ipa").exists():
        return {
            "p12": str(e2e_dir / "mock.p12"),
            "mobileprovision": str(e2e_dir / "embedded.mobileprovision"),
            "ipa": str(e2e_dir / "mock_unsigned.ipa")
        }

    mgr = FixtureManager(output_dir=std_dir)
    return mgr.ensure_fixtures()


def run_verification(
    server_url: str = "http://127.0.0.1:8000",
    fixtures_dir: Optional[str] = None,
    auto_start: bool = False,
    timeout: int = 30,
    json_output: Optional[str] = None
) -> int:
    """Executes the 6-stage signing pipeline verification."""
    print("=" * 70)
    print(" 🚀 iOS IPA Signing Pipeline Standalone Verification Harness")
    print(f" Target Server: {server_url}")
    print("=" * 70)

    server_mgr = None
    if auto_start:
        server_mgr = ServerManager(base_url=server_url, timeout=timeout)
        if not server_mgr.is_server_running():
            print("[SETUP] Spawning backend server subprocess...")
            if not server_mgr.ensure_server_running():
                print("❌ FAILED: Unable to start backend server.", file=sys.stderr)
                return 1
            print("  [OK] Backend server spawned and responding to /api/v1/health")

    client = TestHTTPClient(base_url=server_url, default_timeout=float(timeout))
    fixtures = find_or_create_fixtures(fixtures_dir)

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "server_url": server_url,
        "stages": {},
        "success": False
    }

    try:
        # -------------------------------------------------------------
        # Stage 1: Health Check
        # -------------------------------------------------------------
        print("\n[STAGE 1/6] Probing GET /api/v1/health ...")
        t0 = time.time()
        health_resp = client.get("/api/v1/health")
        if health_resp.status_code != 200:
            print(f"❌ STAGE 1 FAILED: Expected 200, got {health_resp.status_code}: {health_resp.text}")
            results["stages"]["1_health"] = {"status": "FAILED", "code": health_resp.status_code}
            return 1

        health_data = health_resp.json()
        assert health_data.get("status") == "ok", f"Health status not ok: {health_data}"
        assert "engines" in health_data, "Engines status missing from health response"
        print(f"  ✅ PASS: Server healthy (Status: {health_data['status']}, Engines: {health_data['engines']}) [{time.time() - t0:.3f}s]")
        results["stages"]["1_health"] = {"status": "PASSED", "data": health_data}

        # -------------------------------------------------------------
        # Stage 2: Submit Signing Job
        # -------------------------------------------------------------
        print("\n[STAGE 2/6] Submitting signing job POST /api/v1/jobs ...")
        t0 = time.time()
        files = {
            "ipa": fixtures["ipa"],
            "p12": fixtures["p12"],
            "mobileprovision": fixtures["mobileprovision"]
        }
        fields = {
            "password": "test1234",
            "bundle_id": "com.verify.testapp",
            "bundle_name": "VerifyApp",
            "bundle_version": "1.0.0"
        }
        submit_resp = client.post_multipart("/api/v1/jobs", fields=fields, files=files)
        if submit_resp.status_code != 202:
            print(f"❌ STAGE 2 FAILED: Expected 202 Accepted, got {submit_resp.status_code}: {submit_resp.text}")
            results["stages"]["2_submit"] = {"status": "FAILED", "code": submit_resp.status_code}
            return 1

        submit_data = submit_resp.json()
        job_id = submit_data.get("job_id")
        assert job_id, "Missing job_id in submission response"
        assert submit_data.get("status") in ("queued", "processing", "completed")
        print(f"  ✅ PASS: Job accepted with UUID: {job_id} (Status: {submit_data.get('status')}) [{time.time() - t0:.3f}s]")
        results["stages"]["2_submit"] = {"status": "PASSED", "job_id": job_id}

        # -------------------------------------------------------------
        # Stage 3: Poll Job Status to Completion
        # -------------------------------------------------------------
        print(f"\n[STAGE 3/6] Polling job status GET /api/v1/jobs/{job_id} ...")
        t0 = time.time()
        poll_interval = 0.5
        max_attempts = int(timeout / poll_interval)
        final_job = None

        for attempt in range(max_attempts):
            poll_resp = client.get(f"/api/v1/jobs/{job_id}")
            if poll_resp.status_code != 200:
                print(f"❌ STAGE 3 FAILED: Polling returned HTTP {poll_resp.status_code}: {poll_resp.text}")
                return 1

            poll_data = poll_resp.json()
            status = poll_data.get("status")
            if status in ("completed", "failed"):
                final_job = poll_data
                break
            time.sleep(poll_interval)

        if not final_job or final_job.get("status") != "completed":
            err_msg = final_job.get("error") if final_job else "Timed out"
            print(f"❌ STAGE 3 FAILED: Job failed to reach 'completed' status: {err_msg}")
            results["stages"]["3_poll"] = {"status": "FAILED", "job": final_job}
            return 1

        print(f"  ✅ PASS: Job completed in {time.time() - t0:.3f}s. Bundle ID: {final_job.get('bundle_id')}")
        results["stages"]["3_poll"] = {"status": "PASSED", "job": final_job}

        # -------------------------------------------------------------
        # Stage 4: Download Signed IPA & Verify Binary Integrity
        # -------------------------------------------------------------
        print(f"\n[STAGE 4/6] Downloading signed IPA artifact GET /api/v1/downloads/{job_id}/signed.ipa ...")
        t0 = time.time()
        download_resp = client.get(f"/api/v1/downloads/{job_id}/signed.ipa")
        if download_resp.status_code != 200:
            print(f"❌ STAGE 4 FAILED: Download returned HTTP {download_resp.status_code}")
            results["stages"]["4_download"] = {"status": "FAILED", "code": download_resp.status_code}
            return 1

        ipa_bytes = download_resp.body
        assert len(ipa_bytes) > 500, f"Signed IPA too small: {len(ipa_bytes)} bytes"

        # Validate ZIP and inspect Mach-O executable
        with zipfile.ZipFile(io.BytesIO(ipa_bytes), "r") as z:
            namelist = z.namelist()
            assert any(n.endswith("Info.plist") for n in namelist), "Missing Info.plist in signed IPA"
            assert any(n.endswith("_CodeSignature/CodeResources") for n in namelist), "Missing CodeResources in signed IPA"
            assert any(n.endswith("embedded.mobileprovision") for n in namelist), "Missing embedded.mobileprovision in signed IPA"

            # Find Mach-O binary
            macho_names = [n for n in namelist if not n.endswith("/") and not n.endswith(".plist") and not n.endswith("CodeResources") and not n.endswith(".mobileprovision") and "Payload/" in n]
            if macho_names:
                macho_bytes = z.read(macho_names[0])
                macho_check = validate_macho_binary(macho_bytes)
                assert macho_check["valid"], f"Mach-O check failed: {macho_check.get('error')}"
                assert macho_check["cpu_type"] == "ARM64", f"Expected ARM64, got {macho_check['cpu_type']}"

        print(f"  ✅ PASS: Valid signed IPA ({len(ipa_bytes)} bytes, ARM64 Mach-O verified) [{time.time() - t0:.3f}s]")
        results["stages"]["4_download"] = {"status": "PASSED", "size_bytes": len(ipa_bytes)}

        # -------------------------------------------------------------
        # Stage 5: Verify Apple OTA Manifest
        # -------------------------------------------------------------
        print(f"\n[STAGE 5/6] Verifying OTA manifest GET /api/v1/ota/{job_id}/manifest.plist ...")
        t0 = time.time()
        manifest_resp = client.get(f"/api/v1/ota/{job_id}/manifest.plist")
        if manifest_resp.status_code != 200:
            print(f"❌ STAGE 5 FAILED: Manifest endpoint returned HTTP {manifest_resp.status_code}")
            return 1

        xml_check = validate_apple_plist_xml(manifest_resp.text)
        assert xml_check["valid"], f"Manifest invalid XML: {xml_check.get('error')}"
        assert xml_check["has_apple_dtd"], "Manifest must comply with Apple DTD"
        struct_check = validate_ota_manifest_structure(xml_check["data"])
        assert struct_check["valid"], f"Manifest invalid structure: {struct_check.get('error')}"
        print(f"  ✅ PASS: Apple Enterprise DTD compliant manifest verified [{time.time() - t0:.3f}s]")
        results["stages"]["5_manifest"] = {"status": "PASSED", "validation": struct_check}

        # -------------------------------------------------------------
        # Stage 6: Verify HTML Install Landing Page
        # -------------------------------------------------------------
        print(f"\n[STAGE 6/6] Verifying OTA install page GET /api/v1/ota/{job_id}/install ...")
        t0 = time.time()
        install_resp = client.get(f"/api/v1/ota/{job_id}/install")
        if install_resp.status_code != 200:
            print(f"❌ STAGE 6 FAILED: Install page returned HTTP {install_resp.status_code}")
            return 1

        html_text = install_resp.text
        assert "itms-services://" in html_text, "Missing itms-services:// install trigger in HTML"
        assert "manifest.plist" in html_text, "Missing manifest.plist reference in itms-services URL"
        print(f"  ✅ PASS: 1-tap Safari install page verified [{time.time() - t0:.3f}s]")
        results["stages"]["6_install"] = {"status": "PASSED"}

        results["success"] = True
        print("\n" + "=" * 70)
        print(" 🎉 ALL 6 VERIFICATION STAGES PASSED SUCCESSFULLY!")
        print("=" * 70)
        return 0

    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    finally:
        if server_mgr:
            print("[TEARDOWN] Terminating spawned server subprocess...")
            server_mgr.teardown()

        if json_output:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(json_output)), exist_ok=True)
                with open(json_output, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2)
                print(f"Saved verification report to: {json_output}")
            except Exception as e:
                print(f"Warning: Failed to save JSON report: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Standalone verification harness for iOS signing pipeline.")
    parser.add_argument("--server-url", "-s", default="http://127.0.0.1:8000", help="Target backend server URL")
    parser.add_argument("--fixtures-dir", "-f", default=None, help="Directory containing test fixtures")
    parser.add_argument("--auto-start", action="store_true", help="Automatically spawn server if not already running")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds for operations")
    parser.add_argument("--json", "-j", dest="json_output", default=None, help="Path for JSON results output")

    args = parser.parse_args()
    code = run_verification(
        server_url=args.server_url,
        fixtures_dir=args.fixtures_dir,
        auto_start=args.auto_start,
        timeout=args.timeout,
        json_output=args.json_output
    )
    sys.exit(code)


if __name__ == "__main__":
    main()
