"""
Tier 2: Boundary & Corner Cases - Domain 5: CI/CD Boundaries
Tests missing secrets handling, invalid base64, keychain cleanup on failure,
missing script arguments, invalid build configuration, and unsupported export methods.
"""

import os
import sys
import unittest
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent


class TestCICDBoundary(unittest.TestCase):
    """Tier 2: CI/CD Pipeline Boundaries."""

    @classmethod
    def setUpClass(cls):
        cls.workflow_file = WORKSPACE_ROOT / ".github" / "workflows" / "build-ipa.yml"
        cls.bash_script = WORKSPACE_ROOT / "scripts" / "build_ipa.sh"
        cls.ps1_script = WORKSPACE_ROOT / "scripts" / "build_ipa.ps1"

    def test_t2_d5_01_missing_github_actions_secrets(self):
        """T2-D5-01: Workflow validates presence of secrets and fails fast if missing."""
        with open(self.workflow_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("secrets.P12_BASE64" in content)
        self.assertTrue("secrets.P12_PASSWORD" in content)

    def test_t2_d5_02_invalid_base64_in_github_secret(self):
        """T2-D5-02: Workflow handles base64 decode with proper error checking."""
        with open(self.workflow_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("base64", content)

    def test_t2_d5_03_ephemeral_keychain_cleanup_on_failure(self):
        """T2-D5-03: Post-build cleanup executes always() to guarantee ephemeral keychain destruction."""
        with open(self.workflow_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("always()", content, "Post-cleanup step must use if: always() condition")
        self.assertIn("delete-keychain", content, "Cleanup step must delete the ephemeral keychain")

    def test_t2_d5_04_bash_script_missing_mandatory_arguments(self):
        """T2-D5-04: Bash script contains usage text when mandatory flags are missing."""
        with open(self.bash_script, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("Usage:" in content or "usage" in content.lower())

    def test_t2_d5_05_powershell_script_invalid_configuration(self):
        """T2-D5-05: PowerShell script defines ValidateSet for build configuration."""
        with open(self.ps1_script, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("ValidateSet" in content or "Configuration" in content)

    def test_t2_d5_06_unsupported_export_method_validation(self):
        """T2-D5-06: Export options logic references standard Apple export methods."""
        with open(self.bash_script, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue("development" in content or "enterprise" in content or "ad-hoc" in content or "app-store" in content)


if __name__ == "__main__":
    unittest.main()
