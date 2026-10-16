from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reports.exporter import export_json, export_markdown
from scanner.engine import scan_project
from scanner.models import ScanResult

FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "FAKE_TEST_SECRET_NOT_REAL_12345"


class ReportTests(unittest.TestCase):
    def test_json_and_markdown_reports_redact_credentials(self):
        result = scan_project(FIXTURES / "vulnerable")
        with tempfile.TemporaryDirectory() as directory:
            json_path = export_json(result, Path(directory) / "report.json")
            markdown_path = export_markdown(result, Path(directory) / "report.md")
            json_text = json_path.read_text(encoding="utf-8")
            markdown_text = markdown_path.read_text(encoding="utf-8")
            self.assertNotIn(SECRET, json_text)
            self.assertNotIn(SECRET, markdown_text)
            self.assertIn("[REDACTED]", json_text)
            self.assertIn("SLA007", json_text)
            self.assertIn("professional audit", markdown_text)

    def test_zero_findings_report_contains_summary_and_disclaimer(self):
        result = scan_project(FIXTURES / "clean")
        with tempfile.TemporaryDirectory() as directory:
            path = export_markdown(result, Path(directory) / "clean.md")
            content = path.read_text(encoding="utf-8")
            self.assertIn("No findings were reported", content)
            self.assertIn("Severity summary", content)
            self.assertIn("Disclaimer", content)

    def test_reports_redact_service_credentials_from_finding_evidence(self):
        database_password = "db-password-value"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            source = root / "query.py"
            source.write_text(
                "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}') "
                f"# postgres://user:{database_password}@db.local/app\n",
                encoding="utf-8",
            )
            result = scan_project(root)
            json_path = export_json(result, Path(directory) / "report.json")
            markdown_path = export_markdown(result, Path(directory) / "report.md")
            json_text = json_path.read_text(encoding="utf-8")
            markdown_text = markdown_path.read_text(encoding="utf-8")
        self.assertNotIn(database_password, json_text)
        self.assertNotIn(database_password, markdown_text)
        self.assertIn("postgres://[REDACTED]@db.local/app", json_text)

    def test_reports_redact_bracketed_credentials_and_escape_markdown_evidence(self):
        secret = "bracket-secret-value"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            (root / "query.py").write_text(
                f'eval(user_input); config["api_key"] = "{secret}" # ` <img src=x>\\n',
                encoding="utf-8",
            )
            result = scan_project(root)
            json_path = export_json(result, Path(directory) / "report.json")
            markdown_path = export_markdown(result, Path(directory) / "report.md")
            json_text = json_path.read_text(encoding="utf-8")
            markdown_text = markdown_path.read_text(encoding="utf-8")
        self.assertNotIn(secret, json_text)
        self.assertNotIn(secret, markdown_text)
        data = json.loads(json_text)
        self.assertIn(
            'config["api_key"] = "[REDACTED]"',
            data["findings"][0]["evidence"],
        )
        self.assertIn("``", markdown_text)
        self.assertNotIn("\\` <img src=x>", markdown_text)

    def test_json_has_scanner_metadata_counts_and_multiple_findings(self):
        result = scan_project(FIXTURES / "vulnerable")
        with tempfile.TemporaryDirectory() as directory:
            path = export_json(result, Path(directory) / "report.json")
            data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["scanner_version"], "0.1.0")
        self.assertEqual(data["files_scanned"], 1)
        self.assertGreater(len(data["findings"]), 1)
        self.assertEqual(data["counts_by_severity"]["High"], 8)

    def test_report_with_no_scanned_files_is_supported(self):
        result = ScanResult("empty", "2026-01-01T00:00:00+00:00", 0, (), (), False)
        with tempfile.TemporaryDirectory() as directory:
            path = export_json(result, Path(directory) / "empty.json")
            data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["counts_by_severity"]["Critical"], 0)


if __name__ == "__main__":
    unittest.main()
