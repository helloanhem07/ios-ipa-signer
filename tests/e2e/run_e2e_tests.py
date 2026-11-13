#!/usr/bin/env python3
"""
Master E2E Test Suite Runner for iOS IPA Signing System.
Executes Tier 1 (Feature Coverage) and Tier 2 (Boundary & Corner Cases) suites,
manages server lifecycle, records execution metrics, and generates JSON/Markdown reports.
"""

import argparse
import os
import sys
import time
import unittest
from pathlib import Path
from typing import Dict, Any, List

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

from tests.e2e.harness.server_manager import ServerManager
from tests.e2e.harness.report_generator import generate_json_report, generate_markdown_report


class E2ETestResult(unittest.TestResult):
    """Custom TestResult to record individual test timing and failure diagnostics."""

    def __init__(self, stream=None, descriptions=None, verbosity=None):
        super().__init__(stream, descriptions, verbosity)
        self.records: List[Dict[str, Any]] = []
        self._test_start_time: float = 0.0

    def startTest(self, test):
        super().startTest(test)
        self._test_start_time = time.monotonic()

    def addSuccess(self, test):
        super().addSuccess(test)
        duration = time.monotonic() - self._test_start_time
        self.records.append({
            "class": test.__class__.__name__,
            "name": test._testMethodName,
            "status": "PASSED",
            "duration_sec": round(duration, 4),
            "error": None
        })

    def addFailure(self, test, err):
        super().addFailure(test, err)
        duration = time.monotonic() - self._test_start_time
        self.records.append({
            "class": test.__class__.__name__,
            "name": test._testMethodName,
            "status": "FAILED",
            "duration_sec": round(duration, 4),
            "error": self._exc_info_to_string(err, test)
        })

    def addError(self, test, err):
        super().addError(test, err)
        duration = time.monotonic() - self._test_start_time
        self.records.append({
            "class": test.__class__.__name__,
            "name": test._testMethodName,
            "status": "ERROR",
            "duration_sec": round(duration, 4),
            "error": self._exc_info_to_string(err, test)
        })


def discover_suite(tier: str, pattern_filter: str = None) -> unittest.TestSuite:
    """Discovers test suites based on the specified tier and pattern filter."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    tier_str = str(tier).lower().strip()

    dirs_to_discover = []
    if tier_str in ("1", "tier1", "all"):
        dirs_to_discover.append(WORKSPACE_ROOT / "tests" / "e2e" / "tier1_feature_coverage")
    if tier_str in ("2", "tier2", "all"):
        dirs_to_discover.append(WORKSPACE_ROOT / "tests" / "e2e" / "tier2_boundary_corner")

    for d in dirs_to_discover:
        if d.exists():
            discovered = loader.discover(start_dir=str(d), pattern="test_*.py", top_level_dir=str(WORKSPACE_ROOT))
            suite.addTests(discovered)

    if pattern_filter:
        filtered_suite = unittest.TestSuite()
        pattern_lower = pattern_filter.lower()
        for test in _flatten_suite(suite):
            test_id = f"{test.__class__.__name__}.{test._testMethodName}".lower()
            if pattern_lower in test_id:
                filtered_suite.addTest(test)
        return filtered_suite

    return suite


def _flatten_suite(suite):
    """Flattens nested TestSuite objects into an iterator of individual tests."""
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _flatten_suite(item)
        else:
            yield item


def run_e2e_tests(
    tier: str = "all",
    verbose: bool = False,
    json_output: str = "tests/e2e/reports/results.json",
    report_file: str = "tests/e2e/reports/summary.md",
    server_url: str = "http://127.0.0.1:8000",
    skip_server_spawn: bool = False,
    test_filter: str = None,
    timeout: int = 30
) -> int:
    """Master orchestration function for running the E2E test suites."""
    print("=" * 70)
    print(" 🚀 iOS IPA Signing E2E Master Test Runner")
    print(f" Target Tier: {tier.upper()} | Server URL: {server_url}")
    print("=" * 70)

    # Set environment variable for test classes
    os.environ["E2E_SERVER_URL"] = server_url

    # Server lifecycle management
    server_mgr = None
    if not skip_server_spawn:
        server_mgr = ServerManager(base_url=server_url, timeout=timeout)
        if not server_mgr.is_server_running():
            print("\n[PRE-FLIGHT] Server is not running. Spawning backend server...")
            if not server_mgr.ensure_server_running():
                print("❌ FAILED: Unable to start backend server.", file=sys.stderr)
                return 1
            print("  [OK] Backend server spawned and healthy.")
        else:
            print("\n[PRE-FLIGHT] Existing backend server detected and healthy.")

    suite = discover_suite(tier=tier, pattern_filter=test_filter)
    total_tests = suite.countTestCases()
    print(f"\n[DISCOVERY] Discovered {total_tests} test cases matching criteria.")

    start_time = time.monotonic()
    result = E2ETestResult()
    verbosity = 2 if verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity, resultclass=lambda *args, **kwargs: result)

    print("\n[EXECUTION] Running test suites...\n")
    runner.run(suite)
    duration = time.monotonic() - start_time

    # Cleanup server if spawned
    if server_mgr:
        print("\n[TEARDOWN] Terminating spawned backend server subprocess...")
        server_mgr.teardown()

    passed_count = total_tests - len(result.failures) - len(result.errors)
    failed_count = len(result.failures)
    error_count = len(result.errors)

    summary_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tier": tier,
        "total": total_tests,
        "passed": passed_count,
        "failed": failed_count,
        "errors": error_count,
        "duration_seconds": round(duration, 3),
        "records": result.records
    }

    # Generate Reports
    reports_dir = WORKSPACE_ROOT / "tests" / "e2e" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    json_path = WORKSPACE_ROOT / json_output if not Path(json_output).is_absolute() else Path(json_output)
    md_path = WORKSPACE_ROOT / report_file if not Path(report_file).is_absolute() else Path(report_file)

    generate_json_report(summary_data, str(json_path))
    generate_markdown_report(summary_data, str(md_path))

    print("\n" + "=" * 70)
    print(f" 📊 TEST EXECUTION SUMMARY:")
    print(f" Total: {total_tests} | Passed: {passed_count} | Failed: {failed_count} | Errors: {error_count}")
    print(f" Duration: {duration:.2f}s | JSON: {json_path} | MD: {md_path}")
    if failed_count == 0 and error_count == 0 and total_tests > 0:
        print(" 🎉 VERDICT: ALL E2E TESTS PASSED!")
        print("=" * 70)
        return 0
    else:
        print(" ❌ VERDICT: FAILURES DETECTED!")
        print("=" * 70)
        return 1


def main():
    parser = argparse.ArgumentParser(description="Run E2E test suite for iOS IPA signing system.")
    parser.add_argument("--tier", "-t", default="all", choices=["1", "2", "all"], help="Test tier to execute")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose test output")
    parser.add_argument("--json-output", "-j", default="tests/e2e/reports/results.json", help="Path for JSON results")
    parser.add_argument("--report-file", "-r", default="tests/e2e/reports/summary.md", help="Path for Markdown report")
    parser.add_argument("--server-url", "-s", default="http://127.0.0.1:8000", help="Target server URL")
    parser.add_argument("--skip-server-spawn", action="store_true", help="Do not spawn local server")
    parser.add_argument("--filter", "-k", default=None, help="Substring filter for test names")
    parser.add_argument("--timeout", type=int, default=30, help="Server polling timeout in seconds")

    args = parser.parse_args()
    code = run_e2e_tests(
        tier=args.tier,
        verbose=args.verbose,
        json_output=args.json_output,
        report_file=args.report_file,
        server_url=args.server_url,
        skip_server_spawn=args.skip_server_spawn,
        test_filter=args.filter,
        timeout=args.timeout
    )
    sys.exit(code)


if __name__ == "__main__":
    main()
