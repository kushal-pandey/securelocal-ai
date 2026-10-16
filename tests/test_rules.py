from __future__ import annotations

import unittest

from scanner.models import Severity
from scanner.rules import RULES, analyze_source, redact_line


class RuleTests(unittest.TestCase):
    def _rule_ids(self, source: str) -> set[str]:
        return {finding.rule_id for finding in analyze_source(source, "sample.py")}

    def test_all_required_rule_ids_have_metadata(self):
        self.assertEqual(
            set(RULES),
            {"SLA001", "SLA002", "SLA003", "SLA004", "SLA005", "SLA006", "SLA007"},
        )
        
    

    def test_dynamic_execution_is_detected(self):
        findings = analyze_source("eval(user_input)\nexec(source)\n", "sample.py")
        self.assertEqual([item.rule_id for item in findings], ["SLA001", "SLA001"])
        self.assertEqual([item.line for item in findings], [1, 2])
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_pickle_import_aliases_are_detected(self):
        source = (
            "import pickle as p\n"
            "from pickle import loads as decode, Unpickler as Reader\n"
            "p.loads(data)\n"
            "decode(data)\n"
            "p.Unpickler(stream).load()\n"
            "Reader(stream).load()\n"
        )
        findings = analyze_source(source, "sample.py")
        self.assertEqual([item.rule_id for item in findings], ["SLA002"] * 4)

    def test_subprocess_requires_shell_true(self):
        source = (
            "import subprocess\n"
            "subprocess.run(command)\n"
            "subprocess.run(command, shell=True)\n"
            "subprocess.run(command, shell=False)\n"
        )
        findings = analyze_source(source, "sample.py")
        self.assertEqual([(item.rule_id, item.line) for item in findings], [("SLA003", 3)])

    def test_hardcoded_secret_evidence_is_redacted(self):
        secret = "sk_live_7f3a9c2d8e4b6a1f"
        findings = analyze_source(f'API_TOKEN = "{secret}"\n', "sample.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SLA004")
        self.assertNotIn(secret, findings[0].evidence)
        self.assertIn("REDACTED", findings[0].evidence)

    def test_credential_dictionary_values_are_detected_and_redacted(self):
        secret = "key-value-secret-123456"
        findings = analyze_source(f'config = {{"api_key": "{secret}"}}\n', "sample.py")
        self.assertEqual([item.rule_id for item in findings], ["SLA004"])
        self.assertNotIn(secret, findings[0].evidence)

    def test_redaction_handles_cloud_key_names_and_quotes_inside_secrets(self):
        line = 'AWS_SECRET_ACCESS_KEY = "fake-secret\'suffix123"'
        redacted = redact_line(line)
        self.assertNotIn("fake-secret", redacted)
        self.assertNotIn("suffix123", redacted)
        self.assertIn("REDACTED", redacted)

    def test_redaction_handles_service_urls_and_basic_authorization(self):
        database_password = "db-password-value"
        basic_credential = "synthetic_basic_auth_fixture"
        line = (
            f'DATABASE_URL = "postgres://user:{database_password}@db.local/app" '
            f"Authorization: Basic {basic_credential}"
        )
        redacted = redact_line(line)
        self.assertNotIn(database_password, redacted)
        self.assertNotIn(basic_credential, redacted)
        self.assertIn("postgres://[REDACTED]@db.local/app", redacted)
        self.assertEqual(redacted.count("[REDACTED CREDENTIAL]"), 1)

    def test_redaction_handles_bracketed_secrets_and_short_basic_credentials(self):
        secret = "bracket-secret-value"
        line = f'eval(value); config["api_key"] = "{secret}"'
        redacted = redact_line(line)
        self.assertNotIn(secret, redacted)
        self.assertIn('config["api_key"] = "[REDACTED]"', redacted)
        self.assertEqual(
            redact_line("Authorization: Basic dTpw"),
            "[REDACTED CREDENTIAL]",
        )

    def test_placeholder_and_non_secret_assignments_are_not_reported(self):
        source = (
            'API_KEY = "replace-me-with-a-real-secret"\n'
            'password = "test"\n'
            'name = "a long ordinary string value"\n'
        )
        self.assertEqual(self._rule_ids(source), set())
        
    def test_explicit_fake_test_credential_is_not_reported(self):
        source = 'API_KEY = "FAKE_TEST_CREDENTIAL_NOT_REAL"\n'
        self.assertEqual(self._rule_ids(source), set())
        

    def test_weak_hash_algorithms_are_detected(self):
        source = (
            "import hashlib\n"
            "from hashlib import new as make_hash\n"
            "hashlib.md5(value)\n"
            "hashlib.sha1(value)\n"
            "hashlib.new('md5')\n"
            "make_hash('sha1')\n"
        )
        findings = analyze_source(source, "sample.py")
        self.assertEqual([item.rule_id for item in findings], ["SLA005"] * 4)

    def test_tls_verification_detection_is_scoped_to_http_clients(self):
        source = (
            "import requests\n"
            "requests.get(url, verify=False)\n"
            "requests.get(url, verify=True)\n"
            "custom.get(url, verify=False)\n"
            "requests.Session().get(url, verify=False)\n"
            "session = requests.Session()\n"
            "session.get(url, verify=False)\n"
            "requests.Session(verify=False)\n"
        )
        findings = analyze_source(source, "sample.py")
        self.assertEqual(
            [(item.rule_id, item.line) for item in findings],
            [("SLA006", 2), ("SLA006", 5), ("SLA006", 7), ("SLA006", 8)],
        )

    def test_sql_dynamic_construction_is_detected_but_parameters_are_not(self):
        source = (
            "cursor.execute(f'SELECT * FROM users WHERE name = {name}')\n"
            "cursor.execute('SELECT * FROM users WHERE name = ' + name)\n"
            "cursor.execute('SELECT * FROM users WHERE name = ?', (name,))\n"
            "cursor.execute(f'hello {name}')\n"
        )
        findings = analyze_source(source, "sample.py")
        self.assertEqual([(item.rule_id, item.line) for item in findings], [
            ("SLA007", 1),
            ("SLA007", 2),
        ])

    def test_rule_finding_order_and_locations_are_stable(self):
        source = "eval(x)\nimport subprocess\nsubprocess.run(x, shell=True)\n"
        first = analyze_source(source, "sample.py")
        second = analyze_source(source, "sample.py")
        self.assertEqual(first, second)
        self.assertEqual([(item.rule_id, item.line, item.column) for item in first], [
            ("SLA001", 1, 1),
            ("SLA003", 3, 1),
        ])

    def test_column_counts_unicode_characters_not_utf8_bytes(self):
        finding = analyze_source("é = 1; eval(user_input)\n", "sample.py")[0]
        self.assertEqual(finding.column, 8)


if __name__ == "__main__":
    unittest.main()
