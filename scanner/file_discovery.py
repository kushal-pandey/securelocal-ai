from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from scanner.models import SkippedFile

IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".idea",
        ".vscode",
        "build",
        "dist",
        "coverage",
        "htmlcov",
        "site-packages",
    }
)
DEFAULT_MAX_FILES = 5000
MAX_SKIPPED_FILES = 1000


@dataclass(frozen=True)
class DiscoveryResult:
    root: Path
    files: tuple[Path, ...]
    skipped_files: tuple[SkippedFile, ...]
    truncated: bool


def discover_python_files(
    project_root: str | os.PathLike[str], max_files: int = DEFAULT_MAX_FILES
) -> DiscoveryResult:
    root = Path(project_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("The selected project path is not a directory.")
    if max_files < 1:
        raise ValueError("max_files must be greater than zero.")

    files: list[Path] = []
    skipped: list[SkippedFile] = []
    truncated = False
    stop_discovery = False

    def add_skipped(item: SkippedFile) -> None:
        if len(skipped) < MAX_SKIPPED_FILES:
            skipped.append(item)

    def on_walk_error(error: OSError) -> None:
        path = Path(error.filename) if error.filename else root
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            relative = "."
        add_skipped(SkippedFile(relative, "Directory could not be read."))

    for current, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False, onerror=on_walk_error
    ):
        current_path = Path(current)
        kept_directories: list[str] = []
        for name in sorted(directory_names):
            candidate = current_path / name
            if name in IGNORED_DIRECTORIES or candidate.is_symlink():
                continue
            try:
                candidate.resolve(strict=True).relative_to(root)
            except (OSError, ValueError):
                continue
            kept_directories.append(name)
        directory_names[:] = kept_directories

        for name in sorted(file_names):
            if not name.endswith(".py"):
                continue
            candidate = current_path / name
            try:
                relative = candidate.relative_to(root).as_posix()
            except ValueError:
                add_skipped(SkippedFile(name, "Path is outside the selected project."))
                continue
            if candidate.is_symlink():
                add_skipped(SkippedFile(relative, "Symbolic links are not scanned."))
                continue
            try:
                candidate.resolve(strict=True).relative_to(root)
            except (OSError, ValueError):
                add_skipped(SkippedFile(relative, "File is outside the selected project."))
                continue
            if len(files) >= max_files:
                add_skipped(SkippedFile(relative, "Project file-count limit reached."))
                truncated = True
                stop_discovery = True
                break
            files.append(candidate)
        if stop_discovery:
            break

    files.sort(key=lambda path: path.relative_to(root).as_posix())
    skipped.sort(key=lambda item: (item.file_path, item.reason))
    return DiscoveryResult(root, tuple(files), tuple(skipped), truncated)
