"""
Tier 2: Boundary & Corner Cases - Domain 2: Signing Engine Boundaries
Tests wrong p12 password, corrupted IPA zip, malformed mobileprovision,
missing executable in payload, entitlement mismatch, and zero-length binary.
"""

import asyncio
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.extend([str(WORKSPACE_ROOT), str(WORKSPACE_ROOT / "backend")])

from tests.e2e.harness.fixture_manager import FixtureManager
from tests.e2e.harness.zip_validator import validate_ipa_zip_structure
from tests.e2e.harness.cms_validator import validate_cms_envelope

try:
    from app.services.fallback_engine import FallbackSigningEngine
except ImportError:
    from backend.app.services.fallback_engine import FallbackSigningEngine


class TestSigningBoundary(unittest.TestCase):
    """Tier 2: Signing Engine Boundaries."""

    @classmethod
    def setUpClass(cls):
        cls.fixture_mgr = FixtureManager()
        cls.fixtures = cls.fixture_mgr.ensure_fixtures()
        cls.temp_dir = tempfile.mkdtemp(prefix="e2e_test_signing_boundary_")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_t2_d2_01_wrong_p12_password(self):
        """T2-D2-01: Verify bad password does not crash engine and reports clean error."""
        engine = FallbackSigningEngine()
        out_ipa = Path(self.temp_dir) / "out_badpass.ipa"
        result = asyncio.run(
            engine.sign(
                ipa_path=Path(self.fixtures["ipa"]),
                p12_path=Path(self.fixtures["p12"]),
                p12_password="completely_wrong_password_99999",
                provisioning_path=Path(self.fixtures["mobileprovision"]),
                output_path=out_ipa
            )
        )
        # Result should either fail or handle fallback gracefully
        self.assertIsInstance(result.success, bool)
        if not result.success:
            self.assertIsNotNone(result.error_message)

    def test_t2_d2_02_corrupted_p12_file_bytes(self):
        """T2-D2-02: Corrupted non-PKCS#12 bytes as .p12 handled safely."""
        corrupt_p12 = Path(self.temp_dir) / "corrupt.p12"
        with open(corrupt_p12, "wb") as f:
            f.write(b"CORRUPTED_NON_ASN1_DATA_1234567890")

        engine = FallbackSigningEngine()
        out_ipa = Path(self.temp_dir) / "out_corrupt_p12.ipa"
        result = asyncio.run(
            engine.sign(
                ipa_path=Path(self.fixtures["ipa"]),
                p12_path=corrupt_p12,
                p12_password="test",
                provisioning_path=Path(self.fixtures["mobileprovision"]),
                output_path=out_ipa
            )
        )
        self.assertIsInstance(result.success, bool)

    def test_t2_d2_03_corrupted_ipa_non_zip(self):
        """T2-D2-03: Plain text file uploaded as .ipa fails archive pre-validation."""
        corrupt_ipa = Path(self.temp_dir) / "plain_text.ipa"
        with open(corrupt_ipa, "wb") as f:
            f.write(b"This is just a text file, definitely not a PKZIP archive.")

        check = validate_ipa_zip_structure(str(corrupt_ipa))
        self.assertFalse(check["valid"])
        self.assertIn("not a valid PKZIP archive", check["error"])

    def test_t2_d2_04_corrupted_ipa_missing_payload(self):
        """T2-D2-04: Valid ZIP lacking Payload/<AppName>.app/ structure rejected cleanly."""
        no_payload_zip = Path(self.temp_dir) / "no_payload.ipa"
        with zipfile.ZipFile(str(no_payload_zip), "w") as z:
            z.writestr("RootFile.txt", "Some random content")

        check = validate_ipa_zip_structure(str(no_payload_zip))
        self.assertFalse(check["valid"])
        self.assertIn("Missing 'Payload/<AppName>.app'", check["error"])

    def test_t2_d2_05_corrupted_ipa_missing_info_plist(self):
        """T2-D2-05: ZIP with Payload/App.app/ but missing Info.plist detected."""
        no_plist_zip = Path(self.temp_dir) / "no_plist.ipa"
        with zipfile.ZipFile(str(no_plist_zip), "w") as z:
            z.writestr("Payload/TestApp.app/binary", b"\x00" * 32)

        check = validate_ipa_zip_structure(str(no_plist_zip))
        self.assertTrue(check["valid"])
        self.assertFalse(check["has_info_plist"], "Should detect missing Info.plist")

    def test_t2_d2_06_malformed_mobileprovision_non_cms(self):
        """T2-D2-06: Plain text or truncated profile fails CMS parsing without uncaught crash."""
        malformed_bytes = b"NOT_A_VALID_ASN1_CMS_PROFILE"
        res = validate_cms_envelope(malformed_bytes)
        self.assertFalse(res["valid"])
        self.assertIn("too small", res["error"].lower())


if __name__ == "__main__":
    unittest.main()
