"""
Report Generator for E2E Test Suite.
Generates structured JSON and human-readable Markdown test execution reports.
"""

import json
from typing import Dict, Any


def generate_json_report(summary_data: Dict[str, Any], output_path: str):
    """Saves test execution results as structured JSON."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)


def generate_markdown_report(summary_data: Dict[str, Any], output_path: str):
    """Generates a comprehensive Markdown summary of the E2E test run."""
    total = summary_data.get("total", 0)
    passed = summary_data.get("passed", 0)
    failed = summary_data.get("failed", 0)
    errors = summary_data.get("errors", 0)
    duration = summary_data.get("duration_seconds", 0.0)
    tier = summary_data.get("tier", "all")
    timestamp = summary_data.get("timestamp", "")
    records = summary_data.get("records", [])

    pass_rate = (passed / total * 100) if total > 0 else 0.0

    lines = [
        "# E2E Test Execution Summary Report",
        "",
        f"- **Timestamp**: `{timestamp}`",
        f"- **Target Tier**: `{tier.upper()}`",
        f"- **Total Tests Executed**: `{total}`",
        f"- **Passed**: `{passed}` (`{pass_rate:.1f}%`)",
        f"- **Failed**: `{failed}`",
        f"- **Errors**: `{errors}`",
        f"- **Duration**: `{duration:.3f}s`",
        "",
        "## Overall Status",
        f"> **Result**: {'✅ ALL PASSED' if (failed == 0 and errors == 0 and total > 0) else '❌ FAILURES DETECTED'}",
        "",
        "## Detailed Test Execution Records",
        "",
        "| Class | Test Name | Status | Duration (s) | Error / Reason |",
        "| :--- | :--- | :---: | :---: | :--- |"
    ]

    for r in records:
        status_icon = "✅ PASS" if r["status"] == "PASSED" else ("❌ FAIL" if r["status"] == "FAILED" else "⚠️ ERR")
        err_msg = (r.get("error") or "").replace("\n", " ")[:80]
        if err_msg:
            err_msg = f"`{err_msg}`"
        lines.append(f"| {r['class']} | `{r['name']}` | {status_icon} | {r['duration_sec']} | {err_msg} |")

    lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
