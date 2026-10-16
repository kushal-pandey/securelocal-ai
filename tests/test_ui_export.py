from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scanner.models import ScanResult
from ui.main_window import _report_dialog_options


class ReportDialogOptionsTests(unittest.TestCase):
    def test_json_and_markdown_defaults_use_project_reports_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            result = ScanResult("vulnerable", "2026-01-01T00:00:00+00:00", 0, (), (), False)

            markdown = _report_dialog_options(result, "markdown", project_root)
            json = _report_dialog_options(result, "json", project_root)

            reports_dir = project_root / "reports"
            self.assertTrue(reports_dir.is_dir())
            self.assertEqual(markdown["initialdir"], str(reports_dir))
            self.assertEqual(json["initialdir"], str(reports_dir))
            self.assertEqual(markdown["initialfile"], "securelocal-vulnerable-report.md")
            self.assertEqual(json["initialfile"], "securelocal-vulnerable-report.json")
            self.assertTrue(markdown["confirmoverwrite"])
            self.assertTrue(json["confirmoverwrite"])

    def test_default_filename_avoids_existing_report(self):
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory)
            reports_dir = project_root / "reports"
            reports_dir.mkdir()
            existing = reports_dir / "securelocal-vulnerable-report.md"
            existing.write_text("existing report", encoding="utf-8")
            result = ScanResult("vulnerable", "2026-01-01T00:00:00+00:00", 0, (), (), False)

            options = _report_dialog_options(result, "markdown", project_root)

            self.assertEqual(options["initialfile"], "securelocal-vulnerable-report-2.md")
            self.assertEqual(existing.read_text(encoding="utf-8"), "existing report")

    def test_project_name_is_sanitized_for_default_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            result = ScanResult("bad/name:project", "2026-01-01T00:00:00+00:00", 0, (), (), False)

            options = _report_dialog_options(result, "json", Path(directory))

            self.assertEqual(options["initialfile"], "securelocal-bad_name_project-report.json")


if __name__ == "__main__":
    unittest.main()
