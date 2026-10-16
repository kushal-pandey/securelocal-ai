from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from pathlib import Path

from reports.exporter import report_data
from scanner.engine import scan_project


def _terminal_safe(value: str) -> str:
    return "".join(
        f"\\x{ord(character):02x}" if unicodedata.category(character) == "Cc" else character
        for character in value
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a Python project using local static rules.")
    parser.add_argument("project", type=Path, help="Path to the project directory")
    parser.add_argument("--json", action="store_true", help="Print a JSON summary")
    arguments = parser.parse_args()
    try:
        result = scan_project(arguments.project)
    except (OSError, ValueError) as error:
        print(f"Scan could not start: {error}", file=sys.stderr)
        return 2

    if arguments.json:
        print(json.dumps(report_data(result), indent=2, ensure_ascii=True))
        return 0

    print(
        f"SecureLocal AI {report_data(result)['scanner_version']} - "
        f"{_terminal_safe(result.project_name)}"
    )
    print(f"Scanned {result.files_scanned} Python file(s); {len(result.skipped_files)} skipped.")
    for finding in result.findings:
        print(
            f"{finding.severity.value} {finding.rule_id} "
            f"{_terminal_safe(finding.file_path)}:{finding.line}:{finding.column} — {finding.title}"
        )
        print(f"  Evidence: {_terminal_safe(finding.evidence)}")
        print(f"  Remediation: {finding.remediation}")
    if not result.findings:
        print("No findings reported by the enabled rules.")
    if result.truncated:
        print("A safety limit was reached; the scan may be incomplete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
