# Security and privacy notes

## Data flow

The scanner reads `.py` files under the directory explicitly selected by the user. It does not
import or execute project code, install project dependencies, or make HTTP/API requests. Selecting
a UNC or network-mounted project directory can still cause ordinary operating-system network file
access. It skips symbolic links, generated directories, oversized files, malformed source, and
files it cannot read. It never writes to the scanned project.

Optional explanations are off unless the user explicitly selects a finding and requests one. In
that case, the application contacts only the configured loopback Ollama endpoint (by default
`127.0.0.1:11434`) and sends a short finding description and redacted evidence line. It does not
send the project, source files, file paths, or reports. This is a local-service boundary, not a
guarantee about software running on the user's device; use a trusted local Ollama installation.

Reports are written only to the destination selected by the user. They contain findings and
relative paths, not source files. Credential-like evidence is redacted before display, prompting, and export. Redaction includes
credential-like assignments, recognized token formats, authorization values, and credentials
embedded in common service URLs. Review reports before sharing them.

## Threat model

SecureLocal AI is intended to provide a convenient first-pass review of Python source on a
developer's device. It aims to avoid accidental source upload and source modification. It does not
protect against a compromised operating system, malicious local services, malicious Python parser
inputs exploiting a Python runtime vulnerability, or disclosure caused by a user sharing an
exported report.

The AST rules are heuristics. They can miss vulnerabilities, report safe code, and cannot establish
whether values are attacker-controlled. They do not replace code review, dependency analysis,
dynamic testing, or a professional security audit. Do not treat a clean scan as proof that code is
secure.

## Reporting a concern

Do not include real credentials or private source code in a report. For a security concern, provide
a concise description of the affected behavior and a minimal reproducible example with secrets
removed.
