from __future__ import annotations

import json
import socket
import unittest
from unittest.mock import MagicMock, patch

from ai.ollama_client import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    OllamaClient,
    OllamaError,
    validate_base_url,
)
from scanner.models import Finding, Severity


def response(status: int, payload: bytes) -> MagicMock:
    result = MagicMock()
    result.status = status
    result.read.side_effect = [payload, b""]
    return result


class OllamaClientTests(unittest.TestCase):
    def test_default_endpoint_and_model_are_local(self):
        self.assertEqual(DEFAULT_BASE_URL, "http://127.0.0.1:11434")
        self.assertEqual(DEFAULT_MODEL, "qwen2.5-coder:3b")
        self.assertEqual(validate_base_url(DEFAULT_BASE_URL), ("127.0.0.1", 11434))

    def test_only_127_0_0_1_is_accepted(self):
        self.assertEqual(validate_base_url("http://127.0.0.1:1234"), ("127.0.0.1", 1234))

    def test_remote_endpoints_and_unsafe_url_forms_are_rejected(self):
        for address in (
            "http://example.com:11434",
            "http://192.168.1.2:11434",
            "http://127.0.0.2:11434",
            "http://[::1]:11434",
            "http://localhost:11434",
            "https://127.0.0.1:11434",
            "http://user@127.0.0.1:11434",
            "http://127.0.0.1:11434/path",
            "http://127.0.0.1:99999",
            "http://127.0.0.1:0",
        ):
            with self.subTest(address=address), self.assertRaises(OllamaError):
                validate_base_url(address)

    @patch("ai.ollama_client.http.client.HTTPConnection")
    def test_unavailable_service_is_reported(self, connection_type):
        connection_type.return_value.request.side_effect = OSError("connection refused")
        with self.assertRaisesRegex(OllamaError, "unavailable"):
            OllamaClient().list_models()

    @patch("ai.ollama_client.http.client.HTTPConnection")
    def test_timeout_is_reported(self, connection_type):
        connection_type.return_value.request.side_effect = socket.timeout()
        with self.assertRaisesRegex(OllamaError, "timed out"):
            OllamaClient().list_models()

    @patch("ai.ollama_client.http.client.HTTPConnection")
    def test_missing_model_is_reported_without_download(self, connection_type):
        connection = connection_type.return_value
        connection.getresponse.return_value = response(
            200, json.dumps({"models": [{"name": "other-model"}]}).encode()
        )
        finding = Finding(
            "SLA001", "Dynamic code execution", Severity.HIGH, "x.py", 1, 1,
            "eval(value)", "description", "remediation", "High", "limitations"
        )
        with self.assertRaisesRegex(OllamaError, "not installed"):
            OllamaClient().explain_finding(finding, "missing-model")
        self.assertEqual(connection.request.call_count, 1)

    @patch("ai.ollama_client.http.client.HTTPConnection")
    def test_malformed_model_list_is_reported(self, connection_type):
        connection_type.return_value.getresponse.return_value = response(200, b"{")
        with self.assertRaisesRegex(OllamaError, "invalid JSON"):
            OllamaClient().list_models()

    @patch("ai.ollama_client.http.client.HTTPConnection")
    def test_redirect_is_rejected_without_following_it(self, connection_type):
        connection_type.return_value.getresponse.return_value = response(302, b"")
        with self.assertRaisesRegex(OllamaError, "redirect"):
            OllamaClient().list_models()
        self.assertEqual(connection_type.return_value.request.call_count, 1)

    @patch("ai.ollama_client.http.client.HTTPConnection")
    def test_explanation_sends_only_redacted_finding_context(self, connection_type):
        connection = connection_type.return_value
        connection.getresponse.side_effect = [
            response(200, json.dumps({"models": [{"name": DEFAULT_MODEL}]}).encode()),
            response(200, json.dumps({"response": "Review the input source."}).encode()),
        ]
        secret = "FAKE_TEST_SECRET_NOT_REAL_12345"
        finding = Finding(
            "SLA004", "Possible hardcoded credential", Severity.HIGH, "private/name.py",
            1, 1, f'API_TOKEN = "{secret}"', "Credential-like assignment",
            "Remove it", "Medium", "Heuristic",
        )
        explanation = OllamaClient().explain_finding(finding)
        request_body = connection.request.call_args.kwargs["body"]
        request_payload = json.loads(request_body.decode("utf-8"))
        finding_context = json.loads(request_payload["prompt"].split("\n\n", 1)[1])
        self.assertIn("Review the input source.", explanation)
        self.assertNotIn(secret, request_body.decode("utf-8"))
        self.assertNotIn("private/name.py", request_body.decode("utf-8"))
        self.assertIn("REDACTED", request_body.decode("utf-8"))
        self.assertEqual(
            set(finding_context),
            {"rule_id", "title", "severity", "description", "redacted_evidence", "remediation"},
        )
        self.assertNotIn("source", finding_context)
        self.assertEqual(request_payload["options"]["num_predict"], 384)

    @patch("ai.ollama_client.http.client.HTTPConnection")
    def test_long_response_is_not_truncated_by_client(self, connection_type):
        connection = connection_type.return_value
        explanation = "Review this finding. " * 400
        connection.getresponse.side_effect = [
            response(200, json.dumps({"models": [{"name": DEFAULT_MODEL}]}).encode()),
            response(200, json.dumps({"response": explanation}).encode()),
        ]
        finding = Finding(
            "SLA001", "Dynamic code execution", Severity.HIGH, "x.py", 1, 1,
            "eval(value)", "description", "remediation", "High", "limitations"
        )

        self.assertEqual(OllamaClient().explain_finding(finding), explanation.strip())

    @patch("ai.ollama_client.http.client.HTTPConnection")
    def test_missing_explanation_response_is_reported(self, connection_type):
        connection = connection_type.return_value
        connection.getresponse.side_effect = [
            response(200, json.dumps({"models": [{"name": DEFAULT_MODEL}]}).encode()),
            response(200, json.dumps({"response": ""}).encode()),
        ]
        finding = Finding(
            "SLA001", "Dynamic code execution", Severity.HIGH, "x.py", 1, 1,
            "eval(value)", "description", "remediation", "High", "limitations"
        )
        with self.assertRaisesRegex(OllamaError, "no explanation"):
            OllamaClient().explain_finding(finding)

    @patch("ai.ollama_client.http.client.HTTPConnection")
    def test_unexpected_explanation_response_type_is_reported(self, connection_type):
        connection = connection_type.return_value
        connection.getresponse.side_effect = [
            response(200, json.dumps({"models": [{"name": DEFAULT_MODEL}]}).encode()),
            response(200, json.dumps({"response": ["unexpected"]}).encode()),
        ]
        finding = Finding(
            "SLA001", "Dynamic code execution", Severity.HIGH, "x.py", 1, 1,
            "eval(value)", "description", "remediation", "High", "limitations"
        )

        with self.assertRaisesRegex(OllamaError, "no explanation text"):
            OllamaClient().explain_finding(finding)


if __name__ == "__main__":
    unittest.main()
