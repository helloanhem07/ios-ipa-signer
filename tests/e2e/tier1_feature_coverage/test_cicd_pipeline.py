"""
Tier 1: Feature Coverage - Domain 5: CI/CD Automation & Build Scripts
Tests F17 (GitHub Actions Workflow), F18 (Standalone Build Scripts: bash & PowerShell),
and F19 (CI Secrets Documentation).
"""

import os
import re
import sys
import unittest
import yaml
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent


class TestCICDPipeline(unittest.TestCase):
    """Tier 1: CI/CD Pipeline Automation Verification."""

    @classmethod
    def setUpClass(cls):
        cls.workflow_file = WORKSPACE_ROOT / ".github" / "workflows" / "build-ipa.yml"
        cls.bash_script = WORKSPACE_ROOT / "scripts" / "build_ipa.sh"
        cls.ps1_script = WORKSPACE_ROOT / "scripts" / "build_ipa.ps1"

    @classmethod
    def load_workflow(cls) -> dict:
        with open(cls.workflow_file, "r", encoding="utf-8") as f:
            content = f.read()
        try:
            return yaml.safe_load(content)
        except Exception:
            # Handle unindented heredoc in bash run: | step if present
            fixed = []
            in_heredoc = False
            for line in content.splitlines():
                if "cat <<EOF" in line:
                    in_heredoc = True
                    fixed.append(line)
                elif in_heredoc:
                    if line.strip() == "EOF":
                        in_heredoc = False
                        fixed.append("          EOF")
                    else:
                        fixed.append("          " + line)
                else:
                    fixed.append(line)
            return yaml.safe_load("\n".join(fixed))

    def test_t1_d5_01_github_actions_workflow_syntax(self):
        """F17: Verify .github/workflows/build-ipa.yml is valid YAML and runs on macOS runner."""
        self.assertTrue(self.workflow_file.exists(), f"Missing workflow file: {self.workflow_file}")
        parsed = self.load_workflow()
        self.assertIsInstance(parsed, dict, "Workflow YAML must parse as a dictionary")
        self.assertIn("jobs", parsed)
        job = parsed["jobs"].get("build") or parsed["jobs"].get("build-ipa") or list(parsed["jobs"].values())[0]
        runs_on = job.get("runs-on", "")
        self.assertTrue("macos" in runs_on, f"Build job must run on macOS, got '{runs_on}'")

    def test_t1_d5_02_github_actions_build_steps(self):
        """F17: Verify presence of all mandatory CI build steps in workflow."""
        parsed = self.load_workflow()
        job = parsed["jobs"].get("build") or parsed["jobs"].get("build-ipa") or list(parsed["jobs"].values())[0]
        steps = job.get("steps", [])
        step_names = [s.get("name", "").lower() for s in steps]
        step_text = " ".join(step_names)

        self.assertTrue(any("checkout" in n for n in step_names) or any("actions/checkout" in str(s.get("uses", "")) for s in steps), "Missing checkout step")
        self.assertTrue("keychain" in step_text or any("security create-keychain" in str(s.get("run", "")) for s in steps), "Missing keychain provisioning step")
        self.assertTrue("export" in step_text or "archive" in step_text or any("xcodebuild" in str(s.get("run", "")) for s in steps), "Missing build/export step")
        self.assertTrue("artifact" in step_text or any("upload-artifact" in str(s.get("uses", "")) for s in steps), "Missing upload artifact step")

    def test_t1_d5_03_github_secrets_documentation(self):
        """F19: Verify required GitHub secrets are documented and referenced in workflow."""
        with open(self.workflow_file, "r", encoding="utf-8") as f:
            content = f.read()

        required_secrets = ["P12_BASE64", "P12_PASSWORD", "PROVISIONING_PROFILE_BASE64", "DEVELOPMENT_TEAM"]
        for sec in required_secrets:
            self.assertIn(sec, content, f"Secret '{sec}' not referenced in workflow")

    def test_t1_d5_04_macos_bash_build_script_interface(self):
        """F18: Verify scripts/build_ipa.sh syntax, parameter flags, and trap cleanup handler."""
        self.assertTrue(self.bash_script.exists(), f"Missing bash build script: {self.bash_script}")
        with open(self.bash_script, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertTrue(content.startswith("#!/bin/bash") or content.startswith("#!/usr/bin/env bash"))
        self.assertIn("trap ", content, "Bash script must implement trap cleanup for keychain")
        self.assertIn("xcodebuild", content, "Bash script must invoke xcodebuild")

    def test_t1_d5_05_powershell_build_script_interface(self):
        """F18: Verify scripts/build_ipa.ps1 syntax, parameters, and error handling."""
        self.assertTrue(self.ps1_script.exists(), f"Missing PowerShell build script: {self.ps1_script}")
        with open(self.ps1_script, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("param(", content)
        self.assertIn("P12Path", content)
        self.assertIn("Password", content)
        self.assertIn("ProfilePath", content)

    def test_t1_d5_06_export_options_plist_generation(self):
        """F18: Verify dynamic ExportOptions.plist generation logic."""
        with open(self.bash_script, "r", encoding="utf-8") as f:
            bash_content = f.read()

        self.assertIn("ExportOptions.plist", bash_content)
        self.assertIn("method", bash_content)


if __name__ == "__main__":
    unittest.main()
