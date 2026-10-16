from __future__ import annotations

import queue
import unittest
from unittest.mock import patch

from ai.ollama_client import OllamaError
from scanner.models import Finding, Severity
from ui.main_window import SecureLocalApp


class OllamaUiTests(unittest.TestCase):
    def test_explanation_error_is_queued_for_ui_without_escaping_worker(self):
        app = SecureLocalApp.__new__(SecureLocalApp)
        app.events = queue.Queue()
        finding = Finding(
            "SLA001", "Dynamic code execution", Severity.HIGH, "x.py", 1, 1,
            "eval(value)", "description", "remediation", "High", "limitations"
        )

        with patch(
            "ui.main_window.OllamaClient.explain_finding",
            side_effect=OllamaError("Ollama is unavailable at the configured loopback address."),
        ):
            app._explanation_worker(finding, "qwen2.5-coder:3b")

        self.assertEqual(
            app.events.get_nowait(),
            (
                "explanation",
                (False, "Ollama is unavailable at the configured loopback address."),
            ),
        )


if __name__ == "__main__":
    unittest.main()
