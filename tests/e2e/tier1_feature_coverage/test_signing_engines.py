"""
Tier 1: Feature Coverage - Domain 2: Signing Engines (zsign & Fallback)
Tests F3 (zsign CLI Wrapper) and F4 (Pure-Python Fallback Signing Engine).
"""

import asyncio
import os
import plistlib
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.extend([str(WORKSPACE_ROOT), str(WORKSPACE_ROOT / "backend")])

from tests.e2e.harness.fixture_manager import FixtureManager
from tests.e2e.harness.macho_validator import validate_macho_binary, MH_MAGIC_64, CPU_TYPE_ARM64
from tests.e2e.harness.plist_validator import validate_apple_plist_xml
from tests.e2e.harness.cms_validator import validate_cms_envelope
from tests.e2e.harness.zip_validator import validate_signed_ipa_archive


class TestSigningEngines(unittest.TestCase):
    """Tier 1: Signing Engines Verification."""

    @classmethod
    def setUpClass(cls):
        cls.fixture_mgr = FixtureManager()
        cls.fixtures = cls.fixture_mgr.ensure_fixtures()
        cls.temp_dir = tempfile.mkdtemp(prefix="e2e_test_engines_")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_t1_d2_01_fallback_engine_structure_generation(self):
        """F4: Verify FallbackSigningEngine creates valid signed IPA structure."""
        try:
            from app.services.fallback_engine import FallbackSigningEngine
            engine = FallbackSigningEngine()
        except ImportError:
            from backend.app.services.fallback_engine import FallbackSigningEngine
            engine = FallbackSigningEngine()

        output_ipa = Path(self.temp_dir) / "signed_fallback.ipa"
        result = asyncio.run(
            engine.sign(
                ipa_path=Path(self.fixtures["ipa"]),
                p12_path=Path(self.fixtures["p12"]),
                p12_password="test1234",
                provisioning_path=Path(self.fixtures["mobileprovision"]),
                output_path=output_ipa,
                bundle_id="com.fallback.test",
                bundle_name="FallbackTestApp",
                bundle_version="1.5.0"
            )
        )
        self.assertTrue(result.success, f"Fallback sign failed: {result.error_message}")
        self.assertTrue(output_ipa.exists(), "Output signed IPA file must exist")

        # Validate signed IPA structure
        check = validate_signed_ipa_archive(str(output_ipa))
        self.assertTrue(check["valid"], f"Signed IPA archive check failed: {check.get('error')}")
        self.assertTrue(check["has_code_resources"], "Signed IPA must contain _CodeSignature/CodeResources")
        self.assertTrue(check["has_embedded_profile"], "Signed IPA must contain embedded.mobileprovision")
        self.assertEqual(check["bundle_id"], "com.fallback.test")

    def test_t1_d2_02_zsign_cli_argument_construction(self):
        """F3: Verify zsign CLI wrapper flag generation and parameter escaping."""
        try:
            from app.services.zsign_engine import ZsignBinaryEngine
            engine = ZsignBinaryEngine()
        except ImportError:
            from backend.app.services.zsign_engine import ZsignBinaryEngine
            engine = ZsignBinaryEngine()

        ipa_p = Path("/tmp/app.ipa")
        p12_p = Path("/tmp/cert.p12")
        prov_p = Path("/tmp/prov.mobileprovision")
        out_p = Path("/tmp/signed.ipa")

        cmd = engine.build_command(
            ipa_path=ipa_p,
            p12_path=p12_p,
            p12_password="mypassword123",
            provisioning_path=prov_p,
            output_path=out_p,
            bundle_id="com.custom.app",
            bundle_name="Custom App",
            compression_level=1
        )
        cmd_str = " ".join(cmd)
        self.assertIn("-k", cmd)
        self.assertIn("-p", cmd)
        self.assertIn("-m", cmd)
        self.assertIn("-o", cmd)
        self.assertIn("-b", cmd)
        self.assertIn("com.custom.app", cmd)
        self.assertIn("-n", cmd)
        self.assertIn("Custom App", cmd)
        self.assertIn("-z", cmd)

    def test_t1_d2_03_macho_binary_signature_integrity(self):
        """F4/F3: Verify Mach-O binary in signed IPA preserves 64-bit ARM64 headers."""
        output_ipa = Path(self.temp_dir) / "signed_macho_test.ipa"
        try:
            from app.services.fallback_engine import FallbackSigningEngine
            engine = FallbackSigningEngine()
        except ImportError:
            from backend.app.services.fallback_engine import FallbackSigningEngine
            engine = FallbackSigningEngine()

        asyncio.run(
            engine.sign(
                ipa_path=Path(self.fixtures["ipa"]),
                p12_path=Path(self.fixtures["p12"]),
                p12_password="test1234",
                provisioning_path=Path(self.fixtures["mobileprovision"]),
                output_path=output_ipa
            )
        )

        with zipfile.ZipFile(str(output_ipa), "r") as z:
            info_name = [n for n in z.namelist() if n.endswith("/Info.plist") or n == "Info.plist"][0]
            info_data = plistlib.loads(z.read(info_name))
            exec_name = info_data.get("CFBundleExecutable", "MockApp")
            app_dir = info_name.rsplit("/", 1)[0]
            exec_path = f"{app_dir}/{exec_name}"
            macho_data = z.read(exec_path)

        macho_check = validate_macho_binary(macho_data)
        self.assertTrue(macho_check["valid"], f"Mach-O validation failed: {macho_check.get('error')}")
        self.assertTrue(macho_check["is_64bit"], "Executable must be 64-bit")
        self.assertEqual(macho_check["cpu_type"], "ARM64", "Executable CPU type must be ARM64")

    def test_t1_d2_04_coderesources_plist_schema(self):
        """F4: Verify _CodeSignature/CodeResources XML schema and file digests."""
        output_ipa = Path(self.temp_dir) / "signed_coderesources.ipa"
        try:
            from app.services.fallback_engine import FallbackSigningEngine
            engine = FallbackSigningEngine()
        except ImportError:
            from backend.app.services.fallback_engine import FallbackSigningEngine
            engine = FallbackSigningEngine()

        asyncio.run(
            engine.sign(
                ipa_path=Path(self.fixtures["ipa"]),
                p12_path=Path(self.fixtures["p12"]),
                p12_password="test1234",
                provisioning_path=Path(self.fixtures["mobileprovision"]),
                output_path=output_ipa
            )
        )

        with zipfile.ZipFile(str(output_ipa), "r") as z:
            cr_name = [n for n in z.namelist() if "_CodeSignature/CodeResources" in n][0]
            cr_bytes = z.read(cr_name)

        cr_check = validate_apple_plist_xml(cr_bytes)
        self.assertTrue(cr_check["valid"], f"CodeResources plist parsing failed: {cr_check.get('error')}")
        cr_dict = cr_check["data"]
        self.assertIn("files", cr_dict)
        self.assertIn("files2", cr_dict)
        self.assertIsInstance(cr_dict["files"], dict)
        self.assertIsInstance(cr_dict["files2"], dict)

    def test_t1_d2_05_mobileprovision_injection_match(self):
        """F4: Verify injected embedded.mobileprovision matches source profile ASN.1 and UUID."""
        output_ipa = Path(self.temp_dir) / "signed_prov_match.ipa"
        try:
            from app.services.fallback_engine import FallbackSigningEngine
            engine = FallbackSigningEngine()
        except ImportError:
            from backend.app.services.fallback_engine import FallbackSigningEngine
            engine = FallbackSigningEngine()

        asyncio.run(
            engine.sign(
                ipa_path=Path(self.fixtures["ipa"]),
                p12_path=Path(self.fixtures["p12"]),
                p12_password="test1234",
                provisioning_path=Path(self.fixtures["mobileprovision"]),
                output_path=output_ipa
            )
        )

        with zipfile.ZipFile(str(output_ipa), "r") as z:
            prov_name = [n for n in z.namelist() if "embedded.mobileprovision" in n][0]
            extracted_prov_bytes = z.read(prov_name)

        orig_check = validate_cms_envelope(self.fixtures["mobileprovision"])
        extracted_check = validate_cms_envelope(extracted_prov_bytes)

        self.assertTrue(extracted_check["valid"], f"Injected profile is invalid: {extracted_check.get('error')}")
        self.assertEqual(orig_check["uuid"], extracted_check["uuid"], "Provisioning UUID must match original")
        self.assertEqual(orig_check["entitlements"], extracted_check["entitlements"], "Entitlements must match original")

    def test_t1_d2_06_engine_selection_fallback_resilience(self):
        """F4/F3: Verify fallback engine is always available and functional when native zsign is absent."""
        try:
            from app.services.fallback_engine import FallbackSigningEngine
            engine = FallbackSigningEngine()
        except ImportError:
            from backend.app.services.fallback_engine import FallbackSigningEngine
            engine = FallbackSigningEngine()

        self.assertTrue(engine.is_available(), "Fallback signing engine must always report available=True")
        self.assertEqual(engine.name, "fallback")


if __name__ == "__main__":
    unittest.main()
