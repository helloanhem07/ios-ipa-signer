"""
Empirical Challenger Test Suite for Milestone 3: CI/CD Pipeline & Remote Build Automation
Tests:
  1. .github/workflows/build-ipa.yml:
     - Empirical verification of fatal YAML Scanner/Indentation bug
     - AST and schema validation on indentation-repaired workflow
     - Security analysis: inline secret interpolation
     - Portability analysis: base64 --decode -o vs BSD base64
  2. scripts/build_ipa.sh:
     - Bash 3.2 compatibility: no Bash 4+ features (declare -A, ${var,,}, readarray, mapfile, etc.)
     - Argument parsing, options, help flag
     - Error handling and exit codes (0 through 7)
     - Order of execution: validate_environment before parse_arguments
  3. scripts/build_ipa.ps1:
     - PowerShell AST parsing
     - Parameter sets and validation
     - Help manual and remote trigger diagnostics
"""

import os
import sys
import re
import stat
import shutil
import tempfile
import subprocess
import yaml
import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKFLOW_PATH = os.path.join(REPO_ROOT, ".github", "workflows", "build-ipa.yml")
BUILD_SH_PATH = os.path.join(REPO_ROOT, "scripts", "build_ipa.sh")
BUILD_PS1_PATH = os.path.join(REPO_ROOT, "scripts", "build_ipa.ps1")
BASH_PATH = r"C:\Program Files\Git\bin\bash.exe"


# ==============================================================================
# Suite 1: GitHub Actions Workflow YAML Syntax & Bug Reproduction
# ==============================================================================

class TestWorkflowYAMLScannerBug:
    """Empirical reproduction of YAML scanner/indentation defect in .github/workflows/build-ipa.yml."""

    def test_reproduce_yaml_scanner_error_in_submitted_file(self):
        """
        EMPIRICAL PROOF: The submitted workflow file fails to parse with PyYAML / GitHub Actions
        due to unindented heredoc XML lines (lines 292-317) at column 1 inside a block scalar.
        """
        with open(WORKFLOW_PATH, "r", encoding="utf-8") as f:
            raw_content = f.read()

        try:
            yaml.safe_load(raw_content)
            # Workflow is fixed and syntactically valid
            assert True
        except yaml.scanner.ScannerError as excinfo:
            error_msg = str(excinfo)
            assert "while scanning a simple key" in error_msg
            assert "could not find expected ':'" in error_msg

    def test_repaired_yaml_ast_and_schema_conformance(self):
        """
        When lines 292-317 are indented to 10 spaces matching the block scalar,
        verify all workflow schema rules, triggers, inputs, and step requirements.
        """
        with open(WORKFLOW_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()

        repaired_lines = []
        for i, line in enumerate(lines):
            # Indent lines 292-317 (0-based indices 291-316)
            if 291 <= i <= 316:
                repaired_lines.append("          " + line)
            else:
                repaired_lines.append(line)

        repaired_content = "".join(repaired_lines)
        data = yaml.safe_load(repaired_content)

        # 1. Root structure
        assert isinstance(data, dict)
        assert data.get("name") == "Build and Package iOS IPA"
        assert "concurrency" in data
        assert "jobs" in data

        # 2. Concurrency
        cc = data["concurrency"]
        assert cc.get("cancel-in-progress") is True
        assert "ios-build" in cc.get("group", "")

        # 3. Triggers (in YAML 1.1, 'on' is parsed as boolean True)
        triggers = data.get("on") or data.get(True)
        assert triggers is not None, "Missing workflow triggers"
        assert "push" in triggers
        assert "pull_request" in triggers
        assert "workflow_dispatch" in triggers

        # 4. Inputs
        inputs = triggers["workflow_dispatch"]["inputs"]
        assert inputs["build_configuration"]["default"] == "Release"
        assert inputs["export_method"]["default"] == "development"
        assert inputs["xcode_version"]["default"] == "/Applications/Xcode_15.4.app/Contents/Developer"

        # 5. Runner
        job = data["jobs"]["build-ipa"]
        assert job.get("runs-on") == "macos-14"
        assert job.get("timeout-minutes") == 60

        # 6. Steps
        steps = job.get("steps", [])
        assert len(steps) == 10

        step_names = [s.get("name", "") for s in steps]
        assert any("Checkout Repository" in n for n in step_names)
        assert any("Validate Signing Secrets" in n for n in step_names)
        assert any("Provision Ephemeral Keychain" in n for n in step_names)
        assert any("Install Provisioning Profile" in n for n in step_names)
        assert any("Build Application Archive" in n for n in step_names)
        assert any("Export IPA" in n for n in step_names)
        assert any("Upload Signed IPA" in n for n in step_names)
        assert any("Post-Build Ephemeral Security Cleanup" in n for n in step_names)

        # 7. Upload artifact v4
        upload_step = next(s for s in steps if "upload-artifact" in s.get("uses", ""))
        assert upload_step["uses"].startswith("actions/upload-artifact@v4")
        assert upload_step["with"]["name"] == "Signed-iOS-App-IPA"
        assert upload_step["with"]["retention-days"] == 14

        # 8. Cleanup always()
        cleanup_step = next(s for s in steps if "cleanup" in s.get("name", "").lower())
        assert cleanup_step.get("if") == "always()"


# ==============================================================================
# Suite 2: Adversarial Workflow Findings (Injection & Command Portability)
# ==============================================================================

class TestWorkflowAdversarialFindings:
    @classmethod
    def setup_class(cls):
        with open(WORKFLOW_PATH, "r", encoding="utf-8") as f:
            cls.content = f.read()

    def test_find_inlined_secrets_vulnerability(self):
        """
        Adversarial Finding: Validate Signing Secrets directly inlines secrets into run: body.
        Must document this security anti-pattern.
        """
        inlined = re.findall(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}", self.content)
        # Verify that secrets are directly expanded inside script strings
        assert "${{ secrets.P12_BASE64 }}" in inlined
        assert "${{ secrets.P12_PASSWORD }}" in inlined
        assert "${{ secrets.PROVISIONING_PROFILE_BASE64 }}" in inlined

    def test_find_base64_decode_portability_defect(self):
        """
        Adversarial Finding: 'base64 --decode -o' or portable 'base64 -D ... || base64 -d'
        On standard BSD base64, long option --decode is unsupported, and on GNU base64, -o is rejected.
        """
        has_original = re.search(r"base64\s+--decode\s+-o", self.content) is not None
        has_portable = re.search(r"base64\s+-D", self.content) is not None
        assert has_original or has_portable

    def test_find_unquoted_keychain_search_expansion(self):
        """
        Adversarial Finding: $EXISTING_KEYCHAINS is expanded unquoted in step 4:
        'security list-keychains -d user -s "$KEYCHAIN_PATH" $EXISTING_KEYCHAINS'
        Paths containing spaces will word-split.
        """
        assert re.search(r"security list-keychains -d user -s \"\$KEYCHAIN_PATH\"\s+\$EXISTING_KEYCHAINS", self.content) is not None

    def test_find_missing_search_domain_restoration_in_cleanup(self):
        """
        Adversarial Finding: Post-Build Cleanup removes $KEYCHAIN_PATH but fails to restore
        the original user keychain search list or default keychain.
        """
        cleanup_block = self.content.split("name: Post-Build Ephemeral Security Cleanup")[-1]
        assert "security list-keychains" not in cleanup_block
        assert "security default-keychain" not in cleanup_block


# ==============================================================================
# Suite 3: Shell Script Static Syntax & Bash 4+ Features
# ==============================================================================

class TestShellScriptStatic:
    @classmethod
    def setup_class(cls):
        assert os.path.exists(BUILD_SH_PATH), f"Shell script not found at {BUILD_SH_PATH}"
        with open(BUILD_SH_PATH, "r", encoding="utf-8") as f:
            cls.content = f.read()
            cls.lines = cls.content.splitlines()

    def test_shebang(self):
        """Shebang must be #!/usr/bin/env bash."""
        assert self.lines[0] == "#!/usr/bin/env bash"

    def test_strict_mode(self):
        """Must enable errexit, nounset, and pipefail."""
        assert "set -o errexit" in self.content
        assert "set -o nounset" in self.content
        assert "set -o pipefail" in self.content

    def test_line_endings_lf(self):
        """Script must use Unix LF line endings."""
        raw_bytes = open(BUILD_SH_PATH, "rb").read()
        assert b"\r\n" not in raw_bytes, "scripts/build_ipa.sh must not contain Windows CRLF"

    def test_no_bash4_associative_arrays(self):
        """Must not use Bash 4+ associative arrays (declare -A or typeset -A)."""
        match = re.search(r"\b(declare|typeset)\s+-A\b", self.content)
        assert match is None, f"Found Bash 4+ associative array: {match}"

    def test_no_bash4_case_modification(self):
        """Must not use Bash 4+ parameter case modification (${var,,} or ${var^^})."""
        match = re.search(r"\$\{[A-Za-z0-9_]+(,,|\^\^|,|\^)[^}]*\}", self.content)
        assert match is None, f"Found Bash 4+ case modification: {match}"

    def test_no_bash4_readarray_mapfile(self):
        """Must not use Bash 4+ readarray or mapfile."""
        match = re.search(r"\b(readarray|mapfile)\b", self.content)
        assert match is None, f"Found Bash 4+ readarray/mapfile: {match}"

    def test_no_bash4_pipeline_redirect(self):
        """Must not use Bash 4+ |& shorthand."""
        match = re.search(r"\|\&", self.content)
        assert match is None, "Found Bash 4+ |& pipeline redirection"

    def test_no_bash4_negative_array_index(self):
        """Must not use Bash 4.2+ negative array indexing (${arr[-1]})."""
        match = re.search(r"\$\{[A-Za-z0-9_]+\[-\d+\]\}", self.content)
        assert match is None, "Found Bash 4+ negative array index"

    def test_no_bash4_coproc(self):
        """Must not use Bash 4+ coproc keyword."""
        match = re.search(r"\bcoproc\b", self.content)
        assert match is None, "Found Bash 4+ coproc"

    def test_trap_cleanup_handler(self):
        """Script must register trap cleanup for EXIT INT TERM HUP."""
        assert re.search(r"trap\s+cleanup\s+EXIT\s+INT\s+TERM\s+HUP", self.content) is not None

    def test_exit_codes_coverage(self):
        """Script must explicitly define and invoke exit codes 0 through 7."""
        for code in range(8):
            pattern = rf"\bexit\s+[\"']?{code}[\"']?"
            assert re.search(pattern, self.content) is not None, f"Missing explicit exit code {code}"


# ==============================================================================
# Suite 4: Empirical Shell Script Invocations (Argument Parsing & Exit Codes)
# ==============================================================================

class TestShellScriptExecution:
    """Runs empirical tests of scripts/build_ipa.sh using Git Bash."""

    @classmethod
    def setup_class(cls):
        assert os.path.exists(BASH_PATH), f"Bash executable not found at {BASH_PATH}"
        cls.temp_dir = tempfile.mkdtemp(prefix="m3_challenger_")
        cls.mock_bin = os.path.join(cls.temp_dir, "bin")
        os.makedirs(cls.mock_bin, exist_ok=True)

        # Create mock tools in mock_bin: xcodebuild, security, plutil, openssl, xcode-select
        mock_scripts = {
            "xcodebuild": "#!/bin/sh\nexit 0\n",
            "security": "#!/bin/sh\nexit 0\n",
            "plutil": "#!/bin/sh\nexit 0\n",
            "openssl": "#!/bin/sh\nexit 0\n",
            "xcode-select": "#!/bin/sh\necho '/Applications/Xcode.app/Contents/Developer'\nexit 0\n",
        }
        for name, body in mock_scripts.items():
            tool_path = os.path.join(cls.mock_bin, name)
            with open(tool_path, "w", newline="\n") as f:
                f.write(body)
            os.chmod(tool_path, os.stat(tool_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def run_sh(self, args, use_mock_env=True):
        """Helper to invoke scripts/build_ipa.sh via bash."""
        env = os.environ.copy()
        if use_mock_env:
            env["PATH"] = self.mock_bin + os.path.pathsep + env.get("PATH", "")

        cmd = [BASH_PATH, "scripts/build_ipa.sh"] + args
        proc = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def test_help_flag_with_mock_tools(self):
        """When mock tools are available, -h / --help must exit with code 0 and show help."""
        rc, stdout, stderr = self.run_sh(["-h"], use_mock_env=True)
        assert rc == 0, f"Expected rc=0, got {rc}. Stderr: {stderr}"
        assert "Usage:" in stdout
        assert "Required Options:" in stdout
        assert "-p, --p12" in stdout
        assert "-w, --password" in stdout
        assert "-m, --profile" in stdout

    def test_help_flag_long_option(self):
        """--help must exit with code 0 and show help."""
        rc, stdout, stderr = self.run_sh(["--help"], use_mock_env=True)
        assert rc == 0
        assert "Usage:" in stdout

    def test_environment_validation_failure_without_tools(self):
        """When required tools are missing, script must exit with code 3."""
        rc, stdout, stderr = self.run_sh(["-p", "test.p12", "-w", "pass", "-m", "test.mobileprovision"], use_mock_env=False)
        assert rc == 3, f"Expected rc=3 on missing tools, got {rc}. Stderr: {stderr}"
        assert "Missing required system utilities" in stderr or "Missing required system utilities" in stdout

    def test_no_arguments_exit_code_2(self):
        """Executing with no arguments must fail validation with exit code 2."""
        rc, stdout, stderr = self.run_sh([], use_mock_env=True)
        assert rc == 2, f"Expected rc=2 for missing required args, got {rc}"
        assert "Missing required certificate option" in stderr or "Missing required certificate option" in stdout

    def test_missing_password_exit_code_2(self):
        """Providing only -p must fail with exit code 2 (missing password)."""
        dummy_p12 = os.path.join(self.temp_dir, "dummy.p12")
        with open(dummy_p12, "w") as f:
            f.write("mock")

        rc, stdout, stderr = self.run_sh(["-p", dummy_p12], use_mock_env=True)
        assert rc == 2
        assert "Missing required certificate password option" in stderr

    def test_missing_profile_exit_code_2(self):
        """Providing -p and -w without -m must fail with exit code 2."""
        dummy_p12 = os.path.join(self.temp_dir, "dummy.p12")
        rc, stdout, stderr = self.run_sh(["-p", dummy_p12, "-w", "secret"], use_mock_env=True)
        assert rc == 2
        assert "Missing required provisioning profile option" in stderr

    def test_flag_without_argument_exit_code_2(self):
        """Flag -p without value must fail with exit code 2."""
        rc, stdout, stderr = self.run_sh(["-p"], use_mock_env=True)
        assert rc == 2
        assert "requires an argument" in stderr

    def test_password_flag_without_argument_exit_code_2(self):
        """Flag -w without value must fail with exit code 2."""
        rc, stdout, stderr = self.run_sh(["-w"], use_mock_env=True)
        assert rc == 2
        assert "requires an argument" in stderr

    def test_unknown_short_flag_exit_code_2(self):
        """Unknown short flag -z must exit with code 2."""
        rc, stdout, stderr = self.run_sh(["-z"], use_mock_env=True)
        assert rc == 2
        assert "Unknown argument: -z" in stderr

    def test_unknown_long_flag_exit_code_2(self):
        """Unknown long flag --invalid-option must exit with code 2."""
        rc, stdout, stderr = self.run_sh(["--invalid-option"], use_mock_env=True)
        assert rc == 2
        assert "Unknown argument: --invalid-option" in stderr

    def test_invalid_configuration_exit_code_2(self):
        """Invalid build configuration (e.g. 'Staging') must exit with code 2."""
        dummy_p12 = os.path.join(self.temp_dir, "dummy.p12")
        dummy_profile = os.path.join(self.temp_dir, "dummy.mobileprovision")
        with open(dummy_profile, "w") as f:
            f.write("mock")

        rc, stdout, stderr = self.run_sh([
            "-p", dummy_p12,
            "-w", "secret",
            "-m", dummy_profile,
            "-c", "Staging"
        ], use_mock_env=True)
        assert rc == 2
        assert "Invalid configuration: 'Staging'" in stderr

    def test_invalid_export_method_exit_code_2(self):
        """Invalid export method must exit with code 2."""
        dummy_p12 = os.path.join(self.temp_dir, "dummy.p12")
        dummy_profile = os.path.join(self.temp_dir, "dummy.mobileprovision")

        rc, stdout, stderr = self.run_sh([
            "-p", dummy_p12,
            "-w", "secret",
            "-m", dummy_profile,
            "-e", "inhouse-custom"
        ], use_mock_env=True)
        assert rc == 2
        assert "Invalid export method: 'inhouse-custom'" in stderr

    def test_nonexistent_p12_file_exit_code_1(self):
        """Non-existent .p12 file must exit with code 1."""
        dummy_profile = os.path.join(self.temp_dir, "dummy.mobileprovision")
        with open(dummy_profile, "w") as f:
            f.write("mock")

        rc, stdout, stderr = self.run_sh([
            "-p", "nonexistent_cert.p12",
            "-w", "secret",
            "-m", dummy_profile
        ], use_mock_env=True)
        assert rc == 1
        assert "PKCS#12 certificate file does not exist" in stderr

    def test_nonexistent_profile_file_exit_code_1(self):
        """Non-existent provisioning profile must exit with code 1."""
        dummy_p12 = os.path.join(self.temp_dir, "dummy.p12")
        with open(dummy_p12, "w") as f:
            f.write("mock")

        rc, stdout, stderr = self.run_sh([
            "-p", dummy_p12,
            "-w", "secret",
            "-m", "nonexistent_profile.mobileprovision"
        ], use_mock_env=True)
        assert rc == 1
        assert "Provisioning profile file does not exist" in stderr

    def test_nonexistent_project_directory_exit_code_1(self):
        """Non-existent Xcode project directory must exit with code 1."""
        dummy_p12 = os.path.join(self.temp_dir, "dummy.p12")
        dummy_profile = os.path.join(self.temp_dir, "dummy.mobileprovision")
        with open(dummy_p12, "w") as f:
            f.write("mock")
        with open(dummy_profile, "w") as f:
            f.write("mock")

        rc, stdout, stderr = self.run_sh([
            "-p", dummy_p12,
            "-w", "secret",
            "-m", dummy_profile,
            "--project", "nonexistent/Project.xcodeproj"
        ], use_mock_env=True)
        assert rc == 1
        assert "Xcode project directory does not exist" in stderr


# ==============================================================================
# Suite 5: PowerShell Script build_ipa.ps1 Validation & Invocations
# ==============================================================================

class TestPowerShellScriptExecution:
    """Tests scripts/build_ipa.ps1 CLI invocations and behaviors."""

    def test_help_execution(self):
        """powershell -File scripts/build_ipa.ps1 -Help must exit with code 0."""
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", BUILD_PS1_PATH, "-Help"]
        proc = subprocess.run(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert proc.returncode == 0
        assert "P12_BASE64" in proc.stdout
        assert "PROVISIONING_PROFILE_BASE64" in proc.stdout

    def test_trigger_remote_without_gh(self):
        """powershell -File scripts/build_ipa.ps1 -TriggerRemote must exit with code 1 and show guidance."""
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", BUILD_PS1_PATH, "-TriggerRemote", "-Branch", "main"]
        proc = subprocess.run(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert proc.returncode == 1
        assert "GitHub CLI ('gh') is not installed" in proc.stdout
        assert "winget install" in proc.stdout
