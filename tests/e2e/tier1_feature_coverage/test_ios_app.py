"""
Tier 1: Feature Coverage - Domain 4: iOS App Architecture & Contracts
Tests F9 (Xcode Project Layout & iOS 16 Target), F10 (CertificatesView),
F11 (ProfilesView & Parser), F12 (IPALibraryView), F13 (SigningSettingsView),
F14 (RemoteSigningClient), F15 (ZsignBridge Objective-C++ Signatures), and F16 (LocalOTAServer).
"""

import os
import re
import sys
import unittest
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent


class TestIOSApp(unittest.TestCase):
    """Tier 1: iOS Application Architecture & Contract Verification."""

    @classmethod
    def setUpClass(cls):
        cls.ios_root = WORKSPACE_ROOT / "iOSApp"
        cls.xcodeproj = cls.ios_root / "iOSApp.xcodeproj" / "project.pbxproj"
        cls.sources = cls.ios_root / "Sources"

    def test_t1_d4_01_xcode_project_structure(self):
        """F9: Verify Xcode project layout, IPHONEOS_DEPLOYMENT_TARGET >= 16.0, and required build settings."""
        self.assertTrue(self.xcodeproj.exists(), f"Missing Xcode project file: {self.xcodeproj}")
        with open(self.xcodeproj, "r", encoding="utf-8") as f:
            pbx_content = f.read()

        self.assertIn("IPHONEOS_DEPLOYMENT_TARGET", pbx_content)
        # Check target is at least 16.0
        match = re.search(r"IPHONEOS_DEPLOYMENT_TARGET\s*=\s*([0-9\.]+);", pbx_content)
        self.assertIsNotNone(match, "Could not find IPHONEOS_DEPLOYMENT_TARGET in project.pbxproj")
        target_ver = float(match.group(1))
        self.assertGreaterEqual(target_ver, 16.0, f"Deployment target must be >= 16.0, got {target_ver}")
        self.assertIn("SWIFT_VERSION", pbx_content)

    def test_t1_d4_02_swiftui_views_presence(self):
        """F9/F10/F11/F12/F13: Verify all 5 SwiftUI feature tabs and MainTabView exist and declare Views."""
        views_dir = self.sources / "Views"
        required_views = [
            "MainTabView.swift",
            "CertificatesView.swift",
            "ProfilesView.swift",
            "IPALibraryView.swift",
            "SigningSettingsView.swift",
            "ServerConnectionView.swift",
        ]
        for v in required_views:
            path = views_dir / v
            self.assertTrue(path.exists(), f"Missing view file: {path}")
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("struct ", content)
            self.assertIn(": View", content)

    def test_t1_d4_03_mvvm_model_contracts(self):
        """F10/F11/F12/F13: Verify Identifiable models: CertificateItem, ProfileItem, IPAItem, SigningJob."""
        models_dir = self.sources / "Models"
        required_models = {
            "CertificateItem.swift": ["CertificateItem", "Identifiable"],
            "ProfileItem.swift": ["ProfileItem", "Identifiable"],
            "IPAItem.swift": ["IPAItem", "Identifiable"],
            "SigningJob.swift": ["SigningJob", "Identifiable"],
        }
        for file_name, keywords in required_models.items():
            path = models_dir / file_name
            self.assertTrue(path.exists(), f"Missing model file: {path}")
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            for kw in keywords:
                self.assertIn(kw, content, f"Keyword '{kw}' missing in {file_name}")

    def test_t1_d4_04_objc_zsign_bridge_interface(self):
        """F15: Verify Objective-C++ bridging header ZsignBridge.h and implementation."""
        bridge_h = self.sources / "Bridge" / "ZsignBridge.h"
        bridge_mm = self.sources / "Bridge" / "ZsignBridge.mm"

        self.assertTrue(bridge_h.exists(), f"Missing bridge header: {bridge_h}")
        self.assertTrue(bridge_mm.exists(), f"Missing bridge implementation: {bridge_mm}")

        with open(bridge_h, "r", encoding="utf-8") as f:
            h_content = f.read()

        self.assertIn("@interface ZsignResult", h_content)
        self.assertIn("@interface ZsignBridge", h_content)
        self.assertIn("signAppBundleWithIpaPath", h_content)

    def test_t1_d4_05_local_ota_server_network_framework(self):
        """F16: Verify LocalOTAServer implements Network.framework HTTP daemon to host manifest and IPAs."""
        ota_server_swift = self.sources / "Services" / "LocalOTAServer.swift"
        self.assertTrue(ota_server_swift.exists(), f"Missing LocalOTAServer: {ota_server_swift}")

        with open(ota_server_swift, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("import Network", content)
        self.assertTrue("NWListener" in content or "class LocalOTAServer" in content)
        self.assertIn("manifest.plist", content)

    def test_t1_d4_06_remote_signing_client_api_contract(self):
        """F14: Verify RemoteSigningClient conforms to FastAPI REST endpoints (/api/v1/jobs)."""
        client_swift = self.sources / "Services" / "RemoteSigningClient.swift"
        self.assertTrue(client_swift.exists(), f"Missing RemoteSigningClient: {client_swift}")

        with open(client_swift, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("/api/v1/jobs", content)
        self.assertIn("/api/v1/health", content)
        self.assertIn("multipart/form-data", content)


if __name__ == "__main__":
    unittest.main()
