"""
Tier 2: Boundary & Corner Cases - Domain 6: Fixture Generation & Harness Boundaries
Tests invalid output paths, empty password handling, Mach-O odd-byte length
alignment, tampered ASN.1 DER tags, server-down offline resilience, and
temporary scratchpad cleanup.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent

from tests.e2e.harness.fixture_manager import FixtureManager
from tests.e2e.harness.macho_validator import validate_macho_binary
from tests.e2e.harness.cms_validator import validate_cms_envelope
from tests.e2e.harness.http_client import TestHTTPClient


class TestFixturesBoundary(unittest.TestCase):
    """Tier 2: Fixture Generation & Harness Boundaries."""

    @classmethod
    def setUpClass(cls):
        cls.fixture_mgr = FixtureManager()
        cls.fixtures = cls.fixture_mgr.ensure_fixtures()
        cls.temp_dir = tempfile.mkdtemp(prefix="e2e_fixture_boundary_")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_t2_d6_01_invalid_fixture_output_path(self):
        """T2-D6-01: Verify invalid fixture output path is handled cleanly."""
        # Non-existent or invalid drive path / illegal characters
        invalid_path = "Z:\\non_existent_drive_999\\dir\\mock.ipa" if os.name == "nt" else "/proc/illegal/mock.ipa"
        with self.assertRaises((OSError, IOError, ValueError)):
            FixtureManager.create_mock_macho_binary(invalid_path)

    def test_t2_d6_02_empty_password_parameter_handling(self):
        """T2-D6-02: Verify handling of empty or blank password for fixture certificates."""
        out_p12 = Path(self.temp_dir) / "empty_pass.p12"
        with self.assertRaises(ValueError):
            FixtureManager.create_mock_p12(str(out_p12), password="")

    def test_t2_d6_03_macho_odd_byte_length_padding_alignment(self):
        """T2-D6-03: Verify Mach-O validator detects odd byte lengths and non-aligned binaries."""
        valid_bytes = FixtureManager.create_mock_macho_binary()
        # Create odd byte length Mach-O binary (append 1 byte)
        odd_bytes = valid_bytes + b"\x00"
        self.assertEqual(len(odd_bytes) % 4, 1)

        result = validate_macho_binary(odd_bytes)
        self.assertTrue(result["valid"])
        self.assertFalse(result["is_aligned"], "Odd-length binary must fail 4-byte alignment check")

        # Even 4-byte aligned binary
        even_result = validate_macho_binary(valid_bytes)
        self.assertTrue(even_result["valid"])
        self.assertTrue(even_result["is_aligned"], "Standard 4096-byte Mach-O must be 4-byte aligned")

    def test_t2_d6_04_tampered_asn1_der_tags(self):
        """T2-D6-04: Verify mutated ASN.1 tags are rejected cleanly by validate_cms_envelope."""
        prov_path = self.fixtures["mobileprovision"]
        with open(prov_path, "rb") as f:
            prov_bytes = bytearray(f.read())

        # Corrupt first byte (ASN.1 SEQUENCE tag 0x30 -> 0x00)
        prov_bytes[0] = 0x00
        res = validate_cms_envelope(bytes(prov_bytes))
        self.assertFalse(res.get("has_cms_tag", True), "Mutated ASN.1 tag must not report valid CMS tag")

        # Truncate completely
        res_truncated = validate_cms_envelope(b"TRUNCATED")
        self.assertFalse(res_truncated["valid"])
        self.assertIn("error", res_truncated)

    def test_t2_d6_05_server_down_verification_handling(self):
        """T2-D6-05: Verify TestHTTPClient returns 599 without unhandled crash when server is offline."""
        offline_client = TestHTTPClient("http://127.0.0.1:59999", default_timeout=1.0)
        resp = offline_client.get("/api/v1/health")
        self.assertEqual(resp.status_code, 599, "Offline server probe must return status 599")
        self.assertIn("Connection error", resp.text)

    def test_t2_d6_06_temp_scratchpad_cleanup_on_interruption(self):
        """T2-D6-06: Verify temporary scratchpad directories can be isolated and cleanly removed."""
        scratchpad = Path(tempfile.mkdtemp(prefix="scratchpad_test_"))
        try:
            # Create some mock workspace files
            (scratchpad / "inputs").mkdir()
            (scratchpad / "inputs" / "temp.dat").write_bytes(b"temp_data_content")
            (scratchpad / "work").mkdir()
            self.assertTrue(scratchpad.exists())
            self.assertTrue((scratchpad / "inputs" / "temp.dat").exists())
        finally:
            shutil.rmtree(scratchpad, ignore_errors=True)
            self.assertFalse(scratchpad.exists(), "Scratchpad directory must be cleaned up")


if __name__ == "__main__":
    unittest.main()
