from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path

from scanner.engine import SCANNER_VERSION
from scanner.models import Finding, ScanResult, Severity
from scanner.rules import RULES, redact_line

DISCLAIMER = (
    "This tool reports heuristic patterns in Python source. Findings may be false positives or "
    "miss vulnerabilities. Review the source and consult a qualified security professional for "
    "a security assessment. It does not replace a professional audit."
)
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _markdown_code(value: str) -> str:
    longest_run = max(
        (len(match.group(0)) for match in re.finditer(r"`+", value)),
        default=0,
    )
    delimiter = "`" * (longest_run + 1)
    return f"{delimiter}{value}{delimiter}"


def _finding_dict(finding: Finding) -> dict:
    item = asdict(finding)
    item["severity"] = finding.severity.value
    item["evidence"] = redact_line(finding.evidence)[:240]
    return item


def report_data(result: ScanResult) -> dict:
    return {
        "scanner_version": SCANNER_VERSION,
        "scanned_at": result.scanned_at,
        "project_name": result.project_name,
        "files_scanned": result.files_scanned,
        "files_skipped": [
            {"file_path": item.file_path, "reason": item.reason}
            for item in result.skipped_files
        ],
        "counts_by_severity": result.counts_by_severity,
        "truncated": result.truncated,
        "findings": [_finding_dict(finding) for finding in result.findings],
        "rule_limitations": [
            {"rule_id": rule.rule_id, "title": rule.title, "limitations": rule.limitations}
            for rule in RULES.values()
        ],
        "disclaimer": DISCLAIMER,
    }


def export_json(result: ScanResult, destination: str | Path) -> Path:
    path = Path(destination)
    content = json.dumps(report_data(result), indent=2, ensure_ascii=True) + "\n"
    path.write_text(content, encoding="utf-8", newline="\n")
    return path


def export_markdown(result: ScanResult, destination: str | Path) -> Path:
    path = Path(destination)
    lines = [
        "# SecureLocal AI scan report",
        "",
        f"- **Scanner version:** {SCANNER_VERSION}",
        f"- **Scanned at (UTC):** {result.scanned_at}",
        f"- **Project:** {_markdown_code(result.project_name)}",
        f"- **Python files scanned:** {result.files_scanned}",
        f"- **Files skipped:** {len(result.skipped_files)}",
        f"- **Scan truncated by a safety limit:** {'Yes' if result.truncated else 'No'}",
        "",
        "## Severity summary",
        "",
    ]
    for severity in Severity:
        lines.append(f"- **{severity.value}:** {result.counts_by_severity[severity.value]}")
    lines.extend(["", "## Findings", ""])

    for finding in sorted(
        result.findings,
        key=lambda item: (
            SEVERITY_ORDER[item.severity],
            item.file_path,
            item.line,
            item.rule_id,
        ),
    ):
        evidence = redact_line(finding.evidence)
        lines.extend(
            [
                f"### {finding.severity.value} — {finding.title} (`{finding.rule_id}`)",
                "",
                f"- **Location:** {_markdown_code(f'{finding.file_path}:{finding.line}:{finding.column}')}",
                f"- **Confidence:** {finding.confidence}",
                f"- **Evidence:** {_markdown_code(evidence)}",
                f"- **Why it matters:** {finding.description}",
                f"- **Remediation:** {finding.remediation}",
                f"- **Limitations:** {finding.limitations}",
                "",
            ]
        )
    if not result.findings:
        lines.append("No findings were reported by the enabled rules.")
        lines.append("")
    if result.skipped_files:
        lines.extend(["## Skipped files", ""])
        lines.extend(
            f"- {_markdown_code(item.file_path)} — {item.reason}" for item in result.skipped_files
        )
        lines.append("")
    lines.extend(["## Rule limitations", ""])
    for rule in RULES.values():
        lines.append(f"- **{rule.rule_id} — {rule.title}:** {rule.limitations}")
    lines.append("")
    lines.extend(["## Disclaimer", "", DISCLAIMER, ""])
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return path
