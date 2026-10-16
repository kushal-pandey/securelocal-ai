from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.engine import scan_project

FIXTURES = Path(__file__).parent / "fixtures"


class ScannerTests(unittest.TestCase):
    def test_vulnerable_fixture_reports_expected_rules_and_redacted_secret(self):
        result = scan_project(FIXTURES / "vulnerable")
        ids = {finding.rule_id for finding in result.findings}
        self.assertEqual(
            ids,
            {"SLA001", "SLA002", "SLA003", "SLA004", "SLA005", "SLA006", "SLA007"},
        )
        secret = "FAKE_TEST_SECRET_NOT_REAL_12345"
        self.assertTrue(all(secret not in finding.evidence for finding in result.findings))
        self.assertEqual(result.files_scanned, 1)

    def test_clean_fixture_has_no_findings(self):
        result = scan_project(FIXTURES / "clean")
        self.assertEqual(result.findings, ())
        self.assertEqual(result.files_scanned, 1)

    def test_invalid_syntax_is_skipped_without_source_text_in_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.py"
            path.write_text("this is not valid Python !!!\n", encoding="utf-8")
            result = scan_project(directory)
            self.assertEqual(result.findings, ())
            self.assertEqual(result.files_scanned, 0)
            self.assertIn("Invalid Python syntax", result.skipped_files[0].reason)
            self.assertNotIn("this is not valid", result.skipped_files[0].reason)

    def test_large_and_invalid_encoding_files_are_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "large.py").write_text("x" * 20, encoding="utf-8")
            (root / "encoding.py").write_bytes(b"\xff\xfe\x00")
            result = scan_project(root, max_file_bytes=10)
            reasons = {item.file_path: item.reason for item in result.skipped_files}
            self.assertEqual(reasons["large.py"], "File exceeds the per-file size limit.")
            self.assertEqual(reasons["encoding.py"], "File is not valid UTF-8 text.")

    def test_declared_python_encoding_is_respected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "latin1.py"
            path.write_bytes("# coding: latin-1\nlabel = 'caf\xe9'\neval(user_input)\n".encode("latin-1"))
            result = scan_project(directory)
            self.assertEqual(result.files_scanned, 1)
            self.assertEqual([item.rule_id for item in result.findings], ["SLA001"])

    def test_scan_results_are_deterministic(self):
        first = scan_project(FIXTURES / "vulnerable")
        second = scan_project(FIXTURES / "vulnerable")
        self.assertEqual(first.findings, second.findings)
        self.assertEqual(first.files_scanned, second.files_scanned)
        self.assertEqual(first.skipped_files, second.skipped_files)

    def test_scan_does_not_execute_or_modify_source_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "should-not-exist"
            source = root / "payload.py"
            original = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\neval('1 + 1')\n"
            source.write_text(original, encoding="utf-8")
            result = scan_project(root)
            self.assertIn("SLA001", {finding.rule_id for finding in result.findings})
            self.assertFalse(marker.exists())
            self.assertEqual(source.read_text(encoding="utf-8"), original)

    def test_file_identity_change_before_open_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            source = root / "sample.py"
            external = Path(outside) / "outside.py"
            source.write_text("eval(user_input)\n", encoding="utf-8")
            external.write_text("eval(external_input)\n", encoding="utf-8")
            real_open = os.open

            def open_external(_path, flags):
                return real_open(external, flags)

            with patch("scanner.engine.os.open", side_effect=open_external):
                result = scan_project(root)

        self.assertEqual(result.files_scanned, 0)
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.skipped_files[0].reason,
            "File changed before it could be scanned safely.",
        )


if __name__ == "__main__":
    unittest.main()
