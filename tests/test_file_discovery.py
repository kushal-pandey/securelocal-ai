from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scanner.file_discovery import discover_python_files


class FileDiscoveryTests(unittest.TestCase):
    def test_only_python_files_and_ignored_directories_are_returned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("pass\n", encoding="utf-8")
            (root / "notes.txt").write_text("not python\n", encoding="utf-8")
            (root / ".venv").mkdir()
            (root / ".venv" / "hidden.py").write_text("pass\n", encoding="utf-8")
            (root / "build").mkdir()
            (root / "build" / "generated.py").write_text("pass\n", encoding="utf-8")
            result = discover_python_files(root)
            self.assertEqual([path.relative_to(root).as_posix() for path in result.files], ["app.py"])

    def test_file_limit_is_reported_and_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("b.py", "a.py", "c.py"):
                (root / name).write_text("pass\n", encoding="utf-8")
            result = discover_python_files(root, max_files=2)
            self.assertEqual([path.name for path in result.files], ["a.py", "b.py"])
            self.assertTrue(result.truncated)
            self.assertEqual(len(result.skipped_files), 1)

    def test_symbolic_links_are_not_scanned_when_supported(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            external = Path(outside) / "outside.py"
            external.write_text("pass\n", encoding="utf-8")
            try:
                (root / "linked.py").symlink_to(external)
            except (OSError, NotImplementedError):
                self.skipTest("Symbolic link creation is unavailable.")
            result = discover_python_files(root)
            self.assertEqual(result.files, ())
            self.assertEqual(result.skipped_files[0].reason, "Symbolic links are not scanned.")


if __name__ == "__main__":
    unittest.main()
