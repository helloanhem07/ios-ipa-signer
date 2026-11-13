"""
Tier 1: Feature Coverage - Domain 3: OTA Manifest & Installation
Tests F6 (Apple Enterprise DTD Manifest Generation) and F7 (OTA HTML Install Page).
"""

import os
import sys
import unittest
import urllib.parse
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.extend([str(WORKSPACE_ROOT), str(WORKSPACE_ROOT / "backend")])

from tests.e2e.harness.http_client import TestHTTPClient
from tests.e2e.harness.plist_validator import validate_apple_plist_xml, validate_ota_manifest_structure, APPLE_DTD_SUBSTRING

try:
    from app.services.manifest_service import ManifestService
except ImportError:
    from backend.app.services.manifest_service import ManifestService


class TestOTAManifest(unittest.TestCase):
    """Tier 1: OTA Manifest & Installation Verification."""

    @classmethod
    def setUpClass(cls):
        cls.server_url = os.environ.get("E2E_SERVER_URL", "http://127.0.0.1:8000")
        cls.client = TestHTTPClient(cls.server_url)
        cls.is_live = cls.client.get("/api/v1/health", timeout=1.0).status_code == 200

    def test_t1_d3_01_manifest_endpoint_content_type(self):
        """F6: Verify manifest.plist endpoint serves XML content type."""
        if self.is_live:
            # If server has any completed jobs, query one, or check mock job
            resp = self.client.get("/api/v1/ota/test-job/manifest.plist")
            if resp.status_code == 200:
                ct = resp.headers.get("content-type", "")
                self.assertTrue("xml" in ct, f"Expected XML Content-Type, got '{ct}'")
        else:
            xml_bytes = ManifestService.generate_manifest_xml(
                ipa_url="https://example.com/app.ipa",
                bundle_id="com.example.app",
                bundle_version="1.0.0",
                title="Example App"
            )
            self.assertIsInstance(xml_bytes, bytes)
            self.assertTrue(len(xml_bytes) > 0)

    def test_t1_d3_02_manifest_apple_dtd_compliance(self):
        """F6: Verify manifest XML begins with declaration and strict Apple Enterprise DTD."""
        xml_bytes = ManifestService.generate_manifest_xml(
            ipa_url="https://example.com/downloads/signed.ipa",
            bundle_id="com.enterprise.app",
            bundle_version="2.0.0",
            title="Enterprise Portal"
        )
        val = validate_apple_plist_xml(xml_bytes)
        self.assertTrue(val["valid"], f"Manifest plist is not valid XML: {val.get('error')}")
        self.assertTrue(val["has_xml_decl"], "Manifest must contain <?xml declaration")
        self.assertTrue(val["has_apple_dtd"], f"Manifest must contain Apple DTD: {APPLE_DTD_SUBSTRING}")

    def test_t1_d3_03_manifest_dictionary_structure(self):
        """F6: Verify root dictionary contains items array with assets and metadata dictionaries."""
        m_dict = ManifestService.generate_manifest_dict(
            ipa_url="https://example.com/downloads/job123/signed.ipa",
            bundle_id="com.enterprise.app",
            bundle_version="1.2.3",
            title="Enterprise App"
        )
        self.assertIn("items", m_dict)
        self.assertIsInstance(m_dict["items"], list)
        self.assertEqual(len(m_dict["items"]), 1)
        item = m_dict["items"][0]
        self.assertIn("assets", item)
        self.assertIn("metadata", item)

    def test_t1_d3_04_manifest_asset_package_url(self):
        """F6: Verify assets array contains software-package entry pointing to signed IPA artifact."""
        test_url = "https://example.com/api/v1/downloads/job99/signed.ipa"
        m_dict = ManifestService.generate_manifest_dict(
            ipa_url=test_url,
            bundle_id="com.test.app",
            bundle_version="1.0",
            title="Test App"
        )
        check = validate_ota_manifest_structure(m_dict)
        self.assertTrue(check["valid"], f"Manifest validation failed: {check.get('error')}")
        self.assertEqual(check["package_url"], test_url)

    def test_t1_d3_05_manifest_metadata_properties(self):
        """F6: Verify metadata contains bundle-identifier, bundle-version, kind='software', and title."""
        m_dict = ManifestService.generate_manifest_dict(
            ipa_url="https://example.com/app.ipa",
            bundle_id="com.corp.internal",
            bundle_version="3.4.1",
            title="Internal Directory"
        )
        check = validate_ota_manifest_structure(m_dict)
        self.assertTrue(check["valid"])
        self.assertEqual(check["bundle_id"], "com.corp.internal")
        self.assertEqual(check["bundle_version"], "3.4.1")
        self.assertEqual(check["title"], "Internal Directory")

    def test_t1_d3_06_ota_install_landing_page_html(self):
        """F7: Verify mobile Safari landing page contains properly percent-encoded itms-services URL."""
        manifest_url = "https://signing.example.com/api/v1/ota/job123/manifest.plist?token=abc"
        itms_url = ManifestService.build_itms_url(manifest_url)

        self.assertTrue(itms_url.startswith("itms-services://?action=download-manifest&url="))
        encoded_part = itms_url.split("&url=")[1]
        self.assertEqual(urllib.parse.unquote(encoded_part), manifest_url)

        html_content = ManifestService.generate_install_html(
            app_name="My Cool App",
            bundle_id="com.example.cool",
            bundle_version="1.0.0",
            itms_url=itms_url,
            download_url="https://signing.example.com/api/v1/downloads/job123/signed.ipa"
        )
        self.assertIn("<html", html_content)
        self.assertIn("itms-services://?action=download-manifest", html_content)
        self.assertIn("My Cool App", html_content)


if __name__ == "__main__":
    unittest.main()
