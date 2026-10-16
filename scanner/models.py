from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    file_path: str
    line: int
    column: int
    evidence: str
    description: str
    remediation: str
    confidence: str
    limitations: str


@dataclass(frozen=True)
class SkippedFile:
    file_path: str
    reason: str


@dataclass(frozen=True)
class ScanResult:
    project_name: str
    scanned_at: str
    files_scanned: int
    skipped_files: tuple[SkippedFile, ...]
    findings: tuple[Finding, ...]
    truncated: bool

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts
