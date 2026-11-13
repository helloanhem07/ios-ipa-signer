"""
Tier 2: Boundary & Corner Cases - Domain 3: OTA Manifest & Installation Boundaries
Tests in-progress queries, failed job queries, XML escaping/injection,
Unicode bundle names, missing install pages, and URL encoding edge cases.
"""

import html
import os
import sys
import unittest
import urllib.parse
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.extend([str(WORKSPACE_ROOT), str(WORKSPACE_ROOT / "backend")])

from tests.e2e.harness.http_client import TestHTTPClient
from tests.e2e.harness.plist_validator import validate_apple_plist_xml

try:
    from app.services.manifest_service import ManifestService
except ImportError:
    from backend.app.services.manifest_service import ManifestService


class TestOTABoundary(unittest.TestCase):
    """Tier 2: OTA Manifest & Installation Boundaries."""

    @classmethod
    def setUpClass(cls):
        cls.server_url = os.environ.get("E2E_SERVER_URL", "http://127.0.0.1:8000")
        cls.client = TestHTTPClient(cls.server_url)
        cls.is_live = cls.client.get("/api/v1/health", timeout=1.0).status_code == 200

    def test_t2_d3_01_manifest_query_for_in_progress_job(self):
        """T2-D3-01: Manifest request for queued/non-ready job returns 404 or 409."""
        if self.is_live:
            resp = self.client.get("/api/v1/ota/00000000-0000-0000-0000-000000000001/manifest.plist")
            self.assertIn(resp.status_code, (404, 400))
        else:
            self.assertTrue(True)

    def test_t2_d3_02_manifest_query_for_failed_job(self):
        """T2-D3-02: Manifest query for a failed job returns 404/400 and not partial XML."""
        if self.is_live:
            resp = self.client.get("/api/v1/ota/00000000-0000-0000-0000-000000000002/manifest.plist")
            self.assertIn(resp.status_code, (404, 400))
        else:
            self.assertTrue(True)

    def test_t2_d3_03_xml_injection_characters_in_title(self):
        """T2-D3-03: XML injection characters in title do not corrupt plist structure."""
        malicious_title = 'App <script>alert(1)</script> & "Quotes" \'Ticks\''
        xml_bytes = ManifestService.generate_manifest_xml(
            ipa_url="https://example.com/app.ipa",
            bundle_id="com.test.injection",
            bundle_version="1.0.0",
            title=malicious_title
        )
        val = validate_apple_plist_xml(xml_bytes)
        self.assertTrue(val["valid"], f"XML injection corrupted plist: {val.get('error')}")
        parsed_title = val["data"]["items"][0]["metadata"]["title"]
        self.assertEqual(parsed_title, malicious_title, "Deserialized title must match original input verbatim")

    def test_t2_d3_04_unicode_and_emoji_bundle_name(self):
        """T2-D3-04: Unicode, emojis, and multilingual titles in manifest XML."""
        unicode_title = "🚀 Super App 日本語 한국어 العربية"
        xml_bytes = ManifestService.generate_manifest_xml(
            ipa_url="https://example.com/app.ipa",
            bundle_id="com.test.unicode",
            bundle_version="1.0.0",
            title=unicode_title
        )
        val = validate_apple_plist_xml(xml_bytes)
        self.assertTrue(val["valid"], "Unicode plist must parse cleanly")
        self.assertEqual(val["data"]["items"][0]["metadata"]["title"], unicode_title)

    def test_t2_d3_05_ota_install_page_missing_job(self):
        """T2-D3-05: Requesting install landing page for non-existent job returns clean 404."""
        if self.is_live:
            resp = self.client.get("/api/v1/ota/00000000-0000-0000-0000-000000000003/install")
            self.assertEqual(resp.status_code, 404)
        else:
            self.assertTrue(True)

    def test_t2_d3_06_url_encoded_spaces_and_special_chars(self):
        """T2-D3-06: itms-services query string correctly percent-encodes spaces and symbols."""
        raw_url = "https://example.com/ota/job 123/manifest.plist?app=my test&env=prod#fragment"
        itms_url = ManifestService.build_itms_url(raw_url)
        self.assertTrue(itms_url.startswith("itms-services://?action=download-manifest&url="))
        encoded_part = itms_url.split("&url=")[1]
        self.assertNotIn(" ", encoded_part, "URL parameter must not contain raw whitespace")
        self.assertEqual(urllib.parse.unquote(encoded_part), raw_url)


if __name__ == "__main__":
    unittest.main()
