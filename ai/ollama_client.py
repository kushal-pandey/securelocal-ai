from __future__ import annotations

import http.client
import ipaddress
import json
import socket
from urllib.parse import urlsplit

from scanner.models import Finding
from scanner.rules import redact_line

DEFAULT_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen2.5-coder:3b"
REQUEST_TIMEOUT_SECONDS = 120
MAX_RESPONSE_BYTES = 1024 * 1024


class OllamaError(RuntimeError):
    """A safe-to-display error from the optional local model service."""


def validate_base_url(base_url: str) -> tuple[str, int]:
    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
        port = parsed.port if parsed.port is not None else 11434
    except ValueError as error:
        raise OllamaError("The local Ollama address is invalid.") from error
    if (
        parsed.scheme != "http"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or not 1 <= port <= 65535
    ):
        raise OllamaError("Ollama must use a plain HTTP loopback address.")
    try:
        if ipaddress.ip_address(hostname) != ipaddress.ip_address("127.0.0.1"):
            raise OllamaError("Only the 127.0.0.1 Ollama endpoint is allowed.")
    except ValueError as error:
        raise OllamaError("Only the 127.0.0.1 Ollama endpoint is allowed.") from error
    return hostname, port


class OllamaClient:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: float = REQUEST_TIMEOUT_SECONDS):
        self.host, self.port = validate_base_url(base_url)
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero.")
        self.timeout = timeout

    def _request(self, method: str, endpoint: str, payload: dict | None = None) -> dict:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if body is not None else {}
        try:
            connection.request(method, endpoint, body=body, headers=headers)
            response = connection.getresponse()
            if response.status != 200:
                response.read(4096)
                if response.status == 404:
                    raise OllamaError("Ollama could not find that model or API endpoint.")
                if 300 <= response.status < 400:
                    raise OllamaError("Ollama returned a redirect; redirects are not followed.")
                raise OllamaError(f"Ollama returned HTTP status {response.status}.")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise OllamaError("Ollama returned an unexpectedly large response.")
        except (socket.timeout, TimeoutError) as error:
            raise OllamaError("Ollama did not respond before the local request timed out.") from error
        except (OSError, http.client.HTTPException) as error:
            raise OllamaError("Ollama is unavailable at the configured loopback address.") from error
        finally:
            connection.close()

        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise OllamaError("Ollama returned an invalid JSON response.") from error
        if not isinstance(parsed, dict):
            raise OllamaError("Ollama returned an unexpected response format.")
        return parsed

    def list_models(self) -> tuple[str, ...]:
        response = self._request("GET", "/api/tags")
        models = response.get("models")
        if not isinstance(models, list):
            raise OllamaError("Ollama returned an unexpected model-list response.")
        names = tuple(
            model["name"]
            for model in models
            if isinstance(model, dict) and isinstance(model.get("name"), str)
        )
        return names

    def explain_finding(self, finding: Finding, model: str = DEFAULT_MODEL) -> str:
        model = model.strip()
        if not model or len(model) > 128 or any(character.isspace() for character in model):
            raise OllamaError("Enter a valid name for a model installed locally.")
        installed = self.list_models()
        if model not in installed:
            raise OllamaError(f"The local model '{model}' is not installed. No model was downloaded.")
        context = {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "description": finding.description,
            "redacted_evidence": redact_line(finding.evidence)[:240],
            "remediation": finding.remediation,
        }
        prompt = (
            "Explain this static-analysis finding to a developer. State that it is a heuristic, "
            "describe potential impact, suggest a safe way to verify it, and outline remediation. "
            "Do not invent facts or provide executable exploit instructions. Do not output code patches. "
            "The deterministic finding is authoritative; your explanation is untrusted advice.\n\n"
            + json.dumps(context, ensure_ascii=True)
        )
        response = self._request(
            "POST",
            "/api/generate",
            {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {"num_predict": 384},
            },
        )
        text = response.get("response")
        if not isinstance(text, str) or not text.strip():
            raise OllamaError("Ollama returned no explanation text.")
        return text.strip()
