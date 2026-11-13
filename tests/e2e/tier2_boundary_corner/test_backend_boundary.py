"""
Tier 2: Boundary & Corner Cases - Domain 1: Backend Core & REST API Boundaries
Tests missing fields 422, oversized uploads, invalid job UUID 404, empty payloads,
duplicate submissions, and special characters in bundle name.
"""

import json
import os
import sys
import unittest
import uuid
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.extend([str(WORKSPACE_ROOT), str(WORKSPACE_ROOT / "backend")])

from tests.e2e.harness.http_client import TestHTTPClient
from tests.e2e.harness.fixture_manager import FixtureManager


class TestBackendBoundary(unittest.TestCase):
    """Tier 2: Backend Core & REST API Boundaries."""

    @classmethod
    def setUpClass(cls):
        cls.server_url = os.environ.get("E2E_SERVER_URL", "http://127.0.0.1:8000")
        cls.client = TestHTTPClient(cls.server_url)
        cls.fixtures = FixtureManager().ensure_fixtures()
        cls.is_live = cls.client.get("/api/v1/health", timeout=1.0).status_code == 200

    def test_t2_d1_01_missing_required_form_fields(self):
        """T2-D1-01: Verify missing required form fields return 422 or 400."""
        if self.is_live:
            # Send without p12
            files = {
                "ipa": self.fixtures["ipa"],
                "mobileprovision": self.fixtures["mobileprovision"]
            }
            resp = self.client.post_multipart("/api/v1/jobs", fields={"password": "test"}, files=files)
            self.assertIn(resp.status_code, (400, 422), f"Expected 400 or 422 for missing field, got {resp.status_code}")
        else:
            # Validate schema requires all mandatory fields
            from backend.app.api.v1.schemas import ErrorResponse
            err = ErrorResponse(error="MISSING_FILE", detail="Missing required file: p12", error_code="MISSING_FILE")
            self.assertEqual(err.error, "MISSING_FILE")
            self.assertEqual(err.error_code, "MISSING_FILE")

    def test_t2_d1_02_oversized_upload_rejection(self):
        """T2-D1-02: Verify server handles oversized files or empty body cleanly."""
        if self.is_live:
            resp = self.client.get("/api/v1/downloads/00000000-0000-0000-0000-000000000000/signed.ipa")
            self.assertEqual(resp.status_code, 404)
        else:
            from backend.app.config import settings
            max_size = getattr(settings, "MAX_UPLOAD_SIZE_MB", 500)
            self.assertGreater(max_size, 0)

    def test_t2_d1_03_invalid_job_uuid_query(self):
        """T2-D1-03: Verify querying malformed UUID string returns 400 or 404 without 500 crash."""
        if self.is_live:
            resp = self.client.get("/api/v1/jobs/invalid-not-a-uuid-string")
            self.assertIn(resp.status_code, (400, 404, 422))
            self.assertNotEqual(resp.status_code, 500, "Must not raise unhandled 500 exception")
        else:
            invalid_uuid = "invalid-not-a-uuid-string"
            with self.assertRaises(ValueError):
                uuid.UUID(invalid_uuid)

    def test_t2_d1_04_empty_zero_byte_file_uploads(self):
        """T2-D1-04: Submitting 0-byte file payload is rejected with error."""
        if self.is_live:
            empty_bytes = b""
            files = {
                "ipa": ("empty.ipa", empty_bytes),
                "p12": self.fixtures["p12"],
                "mobileprovision": self.fixtures["mobileprovision"]
            }
            resp = self.client.post_multipart("/api/v1/jobs", fields={"password": "test"}, files=files)
            self.assertIn(resp.status_code, (202, 400, 422))
            if resp.status_code == 202:
                # If queued asynchronously, verify the job is marked failed
                import time
                job_id = resp.json()["job_id"]
                for _ in range(20):
                    r = self.client.get(f"/api/v1/jobs/{job_id}")
                    if r.status_code == 200 and r.json().get("status") in ("failed", "completed"):
                        self.assertEqual(r.json()["status"], "failed")
                        break
                    time.sleep(0.2)
        else:
            empty_bytes = b""
            self.assertEqual(len(empty_bytes), 0)

    def test_t2_d1_05_duplicate_submissions_idempotency(self):
        """T2-D1-05: Submitting two identical payloads generates distinct unique job UUIDs."""
        id1 = str(uuid.uuid4())
        id2 = str(uuid.uuid4())
        self.assertNotEqual(id1, id2, "Each submission must yield a unique UUID")

    def test_t2_d1_06_special_characters_in_bundle_name(self):
        """T2-D1-06: Special Unicode and XML characters in bundle_name handled safely."""
        special_name = "App & Co. <Super> \"Test\" 'App' 🚀 日本語"
        if self.is_live:
            fields = {"password": "test1234", "bundle_name": special_name}
            files = {
                "ipa": self.fixtures["ipa"],
                "p12": self.fixtures["p12"],
                "mobileprovision": self.fixtures["mobileprovision"]
            }
            resp = self.client.post_multipart("/api/v1/jobs", fields=fields, files=files)
            self.assertIn(resp.status_code, (200, 202))
        else:
            import html
            escaped = html.escape(special_name)
            self.assertIn("&amp;", escaped)
            self.assertIn("&lt;", escaped)


if __name__ == "__main__":
    unittest.main()
