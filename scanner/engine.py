from __future__ import annotations

import ast
import os
import stat
import io
import tokenize
from datetime import datetime, timezone
from pathlib import Path

from scanner.file_discovery import DEFAULT_MAX_FILES, discover_python_files
from scanner.models import Finding, ScanResult, SkippedFile
from scanner.rules import analyze_source

SCANNER_VERSION = "0.1.0"
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FINDINGS = 5000


def scan_project(
    project_root: str | Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    max_findings: int = MAX_FINDINGS,
) -> ScanResult:
    if min(max_file_bytes, max_total_bytes, max_findings) < 1:
        raise ValueError("Scan limits must be greater than zero.")
    discovery = discover_python_files(project_root, max_files=max_files)
    root = discovery.root
    skipped = list(discovery.skipped_files)
    findings: list[Finding] = []
    files_scanned = 0
    total_bytes = 0
    truncated = discovery.truncated

    for file_index, path in enumerate(discovery.files):
        relative = path.relative_to(root).as_posix()
        if total_bytes >= max_total_bytes:
            skipped.append(SkippedFile(relative, "Project byte-count limit reached."))
            truncated = True
            continue
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
            if path.is_symlink() or resolved.is_symlink():
                skipped.append(SkippedFile(relative, "Symbolic links are not scanned."))
                continue
            before_open = resolved.lstat()
            if not stat.S_ISREG(before_open.st_mode):
                skipped.append(SkippedFile(relative, "File is not a regular file."))
                continue
            open_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(resolved, open_flags)
            with os.fdopen(descriptor, "rb") as source_file:
                opened = os.fstat(source_file.fileno())
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (before_open.st_dev, before_open.st_ino)
                ):
                    skipped.append(SkippedFile(relative, "File changed before it could be scanned safely."))
                    continue
                raw_source = source_file.read(
                    min(max_file_bytes, max_total_bytes - total_bytes) + 1
                )
        except FileNotFoundError:
            skipped.append(SkippedFile(relative, "File was removed before it could be scanned."))
            continue
        except (OSError, ValueError):
            skipped.append(SkippedFile(relative, "File could not be read safely."))
            continue

        if len(raw_source) > max_file_bytes:
            skipped.append(SkippedFile(relative, "File exceeds the per-file size limit."))
            continue
        if total_bytes + len(raw_source) > max_total_bytes:
            skipped.append(SkippedFile(relative, "Project byte-count limit reached."))
            truncated = True
            continue
        total_bytes += len(raw_source)
        try:
            encoding, _ = tokenize.detect_encoding(io.BytesIO(raw_source).readline)
            source = raw_source.decode(encoding)
        except (UnicodeDecodeError, LookupError, SyntaxError):
            skipped.append(SkippedFile(relative, "File is not valid UTF-8 text."))
            continue
        try:
            file_findings = analyze_source(source, relative)
        except SyntaxError as error:
            line_note = f" at line {error.lineno}" if error.lineno else ""
            skipped.append(SkippedFile(relative, f"Invalid Python syntax{line_note}."))
            continue
        except RecursionError:
            skipped.append(SkippedFile(relative, "Python syntax is too deeply nested to analyze."))
            continue

        files_scanned += 1
        available = max_findings - len(findings)
        if len(file_findings) > available:
            findings.extend(file_findings[:available])
            truncated = True
            break
        findings.extend(file_findings)
        if len(findings) >= max_findings:
            truncated = file_index + 1 < len(discovery.files)
            break

    findings.sort(
        key=lambda finding: (
            finding.file_path,
            finding.line,
            finding.column,
            finding.rule_id,
        )
    )
    skipped.sort(key=lambda item: (item.file_path, item.reason))
    return ScanResult(
        project_name=root.name or "Selected project",
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        files_scanned=files_scanned,
        skipped_files=tuple(skipped),
        findings=tuple(findings),
        truncated=truncated,
    )
