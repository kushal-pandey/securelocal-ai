from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from scanner.models import Finding, Severity

SECRET_NAME = re.compile(
    r"(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|client[_-]?secret|"
    r"private[_-]?key|signing[_-]?key|credential|authorization)",
    re.IGNORECASE,
)
PLACEHOLDER_SECRET = re.compile(
    r"(?:your[_ -]|replace[_ -]?me|example|sample|placeholder|dummy|changeme|"
    r"fake[_ -]test(?:[_ -][a-z0-9]+)*|"
    r"<[^>]+>|\*{3,}|x{4,})",
    re.IGNORECASE,
)
ASSIGNMENT_SECRET = re.compile(
    r"""(?i)(?P<prefix>["']?\b[A-Za-z_]\w*["']?\]?\s*[:=]\s*)(?P<quote>['"])(?:\\.|(?!(?P=quote)).)*(?P=quote)"""
)
INLINE_CREDENTIAL = re.compile(
    r"(?i)\b(?:bearer\s+|authorization\s*:\s*(?:basic|bearer)\s+|"
    r"(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|credential)\s*[:=]\s*)"
    r"(['\"]?)[A-Za-z0-9_./+=:-]+\1"
)
URL_CREDENTIAL = re.compile(
    r"(?i)\b(?P<scheme>https?|ftp|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
    r"(?P<credentials>[^/@\s:]+(?::[^/@\s]*)?)@"
)
KNOWN_TOKEN = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16})\b"
)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    confidence: str
    limitations: str


RULES = {
    rule.rule_id: rule
    for rule in (
        Rule(
            "SLA001",
            "Dynamic code execution",
            Severity.HIGH,
            "Calls eval() or exec(), which can execute attacker-controlled Python code.",
            "Avoid dynamic code execution. Use a safe parser for the expected input format and validate values explicitly.",
            "High",
            "A call may be safe when its input is fully trusted; this scanner cannot establish data provenance.",
        ),
        Rule(
            "SLA002",
            "Unsafe pickle deserialization",
            Severity.HIGH,
            "Deserializing untrusted pickle data can execute arbitrary code.",
            "Do not load pickle data from untrusted sources. Prefer a data-only format such as JSON, with schema validation.",
            "High",
            "Risk depends on whether the serialized input can be controlled by an attacker.",
        ),
        Rule(
            "SLA003",
            "Subprocess shell execution",
            Severity.HIGH,
            "A subprocess call enables a system shell, which can make untrusted command input executable.",
            "Avoid shell=True. Pass an argument list to subprocess and validate each argument; use a fixed executable.",
            "High",
            "This rule reports shell=True but cannot determine whether command arguments are attacker-controlled.",
        ),
        Rule(
            "SLA004",
            "Possible hardcoded credential",
            Severity.HIGH,
            "A credential-like variable is assigned a non-placeholder string literal.",
            "Load secrets from a protected secret store or environment configuration. Rotate any real credential committed to source control.",
            "Medium",
            "Heuristic name and literal checks can miss credentials or flag non-secret test values. Evidence is redacted.",
        ),
        Rule(
            "SLA005",
            "Weak cryptographic hash",
            Severity.MEDIUM,
            "MD5 or SHA-1 is used in a hashing call; these algorithms are unsuitable for security-sensitive uses.",
            "For integrity or signatures, use SHA-256 or stronger. For password storage, use a dedicated password-hashing scheme such as scrypt, bcrypt, or Argon2.",
            "Medium",
            "MD5 and SHA-1 can still be appropriate for non-security checksums; intent cannot be inferred statically.",
        ),
        Rule(
            "SLA006",
            "TLS certificate verification disabled",
            Severity.HIGH,
            "A recognized HTTP client call disables TLS certificate verification.",
            "Keep certificate verification enabled. If using a private CA, configure its trusted certificate bundle rather than disabling verification.",
            "High",
            "Only recognized requests/httpx calls using verify=False are reported; custom clients may use other options.",
        ),
        Rule(
            "SLA007",
            "Possible SQL injection",
            Severity.HIGH,
            "SQL-looking text is dynamically combined or formatted before being passed to an execute method.",
            "Use parameterized queries for values. Do not build SQL by concatenating, interpolating, or formatting untrusted input.",
            "Medium",
            "This AST heuristic cannot prove input is untrusted or understand every database API. Review the call context.",
        ),
    )
}


def redact_line(line: str) -> str:
    def redact_assignment(match: re.Match[str]) -> str:
        prefix = match.group("prefix")
        if not SECRET_NAME.search(prefix):
            return match.group(0)
        quote = match.group("quote")
        return f"{prefix}{quote}[REDACTED]{quote}"

    redacted = ASSIGNMENT_SECRET.sub(redact_assignment, line)
    redacted = INLINE_CREDENTIAL.sub("[REDACTED CREDENTIAL]", redacted)
    redacted = URL_CREDENTIAL.sub(
        lambda match: f"{match.group('scheme')}://[REDACTED]@",
        redacted,
    )
    return KNOWN_TOKEN.sub("[REDACTED CREDENTIAL]", redacted)


def _attribute_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _root_name(node: ast.AST) -> str:
    current = node
    while isinstance(current, ast.Attribute):
        current = current.value
    return current.id if isinstance(current, ast.Name) else ""


def _targets(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for item in node.elts for name in _targets(item)]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    return []


def _literal_secret(value: str) -> bool:
    return len(value.strip()) >= 8 and not PLACEHOLDER_SECRET.search(value)


def _sql_like_text(node: ast.AST, source: str) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        text = node.value
    elif isinstance(node, ast.JoinedStr):
        text = "".join(
            value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else " "
            for value in node.values
        )
    else:
        text = source
    return bool(re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b", text, re.I))


def _dynamic_sql_argument(node: ast.AST, source: str) -> bool:
    if isinstance(node, ast.JoinedStr):
        return _sql_like_text(node, source) and any(
            isinstance(value, ast.FormattedValue) for value in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _sql_like_text(node.left, source) or _sql_like_text(node.right, source)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format" and (node.args or node.keywords):
            return _sql_like_text(node.func.value, source)
    return False


class _RuleVisitor(ast.NodeVisitor):
    def __init__(self, source: str, relative_path: str) -> None:
        self.source_lines = source.splitlines()
        self.relative_path = relative_path
        self.findings: list[Finding] = []
        self.pickle_modules: set[str] = {"pickle"}
        self.pickle_functions: set[str] = set()
        self.pickle_unpickler_classes: set[str] = set()
        self.hashlib_modules: set[str] = {"hashlib"}
        self.hash_functions: set[str] = set()
        self.hash_new_functions: set[str] = set()
        self.http_modules: set[str] = {"requests", "httpx"}
        self.http_session_names: set[str] = set()
        self.subprocess_modules: set[str] = {"subprocess"}
        self.subprocess_functions: set[str] = set()
        self._collect_import_aliases()

    def _collect_import_aliases(self) -> None:
        try:
            tree = ast.parse("\n".join(self.source_lines))
        except SyntaxError:
            return
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "pickle":
                        self.pickle_modules.add(alias.asname or "pickle")
                    elif alias.name == "hashlib":
                        self.hashlib_modules.add(alias.asname or "hashlib")
                    elif alias.name in {"requests", "httpx"}:
                        self.http_modules.add(alias.asname or alias.name)
                    elif alias.name == "subprocess":
                        self.subprocess_modules.add(alias.asname or "subprocess")
            elif isinstance(node, ast.ImportFrom):
                if node.module == "pickle":
                    self.pickle_functions.update(
                        alias.asname or alias.name
                        for alias in node.names
                        if alias.name in {"load", "loads"}
                    )
                    self.pickle_unpickler_classes.update(
                        alias.asname or alias.name
                        for alias in node.names
                        if alias.name == "Unpickler"
                    )
                elif node.module == "hashlib":
                    self.hash_functions.update(
                        alias.asname or alias.name
                        for alias in node.names
                        if alias.name in {"md5", "sha1", "new"}
                    )
                    self.hash_new_functions.update(
                        alias.asname or alias.name
                        for alias in node.names
                        if alias.name == "new"
                    )
                elif node.module == "subprocess":
                    self.subprocess_functions.update(
                        alias.asname or alias.name
                        for alias in node.names
                        if alias.name in {"run", "call", "Popen", "check_call", "check_output"}
                    )
        for node in ast.walk(tree):
            value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
            if (
                not isinstance(value, ast.Call)
                or not isinstance(value.func, ast.Attribute)
                or value.func.attr not in {"Session", "Client"}
                or _root_name(value.func) not in self.http_modules
            ):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                self.http_session_names.update(_targets(target))

    def _finding(self, rule_id: str, node: ast.AST, *, evidence: str | None = None) -> None:
        rule = RULES[rule_id]
        line_number = max(1, getattr(node, "lineno", 1))
        raw_line_at_location = (
            self.source_lines[line_number - 1]
            if line_number <= len(self.source_lines)
            else ""
        )
        byte_column = max(0, getattr(node, "col_offset", 0))
        try:
            column = len(raw_line_at_location.encode("utf-8")[:byte_column].decode("utf-8")) + 1
        except UnicodeDecodeError:
            column = byte_column + 1
        raw_line = (
            evidence
            if evidence is not None
            else raw_line_at_location
            if raw_line_at_location
            else rule.title
        )
        self.findings.append(
            Finding(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                file_path=self.relative_path,
                line=line_number,
                column=column,
                evidence=redact_line(raw_line.strip())[:240],
                description=rule.description,
                remediation=rule.remediation,
                confidence=rule.confidence,
                limitations=rule.limitations,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        function_name = _attribute_name(node.func)
        short_name = function_name.rsplit(".", 1)[-1]
        root_name = _root_name(node.func)

        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            self._finding("SLA001", node)
        if (
            isinstance(node.func, ast.Attribute)
            and short_name in {"load", "loads"}
            and root_name in self.pickle_modules
        ) or (
            isinstance(node.func, ast.Name) and node.func.id in self.pickle_functions
        ):
            self._finding("SLA002", node)
        if (
            isinstance(node.func, ast.Attribute)
            and short_name == "load"
            and isinstance(node.func.value, ast.Call)
            and (
                isinstance(node.func.value.func, ast.Attribute)
                and node.func.value.func.attr == "Unpickler"
                and _root_name(node.func.value.func) in self.pickle_modules
                or isinstance(node.func.value.func, ast.Name)
                and node.func.value.func.id in self.pickle_unpickler_classes
            )
        ):
            self._finding("SLA002", node)

        if isinstance(node.func, ast.Name) and node.func.id in self.subprocess_functions:
            subprocess_call = True
        else:
            subprocess_call = root_name in self.subprocess_modules and short_name in {
                "run",
                "call",
                "Popen",
                "check_call",
                "check_output",
            }
        if subprocess_call and any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            self._finding("SLA003", node)

        if (
            isinstance(node.func, ast.Attribute)
            and root_name in self.hashlib_modules
            and short_name in {"md5", "sha1"}
        ) or (
            isinstance(node.func, ast.Name)
            and node.func.id in self.hash_functions
            and node.func.id in {"md5", "sha1"}
        ):
            self._finding("SLA005", node)
        if (
            isinstance(node.func, ast.Attribute)
            and root_name in self.hashlib_modules
            and short_name == "new"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and node.args[0].value.lower() in {"md5", "sha1"}
        ):
            self._finding("SLA005", node)
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in self.hash_new_functions
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and node.args[0].value.lower() in {"md5", "sha1"}
        ):
            self._finding("SLA005", node)

        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        is_http_client = root_name in self.http_modules
        if isinstance(receiver, ast.Name) and receiver.id in self.http_session_names:
            is_http_client = True
        if isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Attribute):
            is_http_client = is_http_client or (
                receiver.func.attr in {"Session", "Client"}
                and _root_name(receiver.func) in self.http_modules
            )
        if (
            is_http_client
            and short_name
            in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "request",
                "head",
                "options",
                "Session",
                "Client",
            }
            and any(
                keyword.arg == "verify"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in node.keywords
            )
        ):
            self._finding("SLA006", node)

        if (
            short_name in {"execute", "executemany"}
            and node.args
            and _dynamic_sql_argument(node.args[0], ast.get_source_segment("\n".join(self.source_lines), node.args[0]) or "")
        ):
            self._finding("SLA007", node)

        if (
            function_name in {"os.system", "os.popen"}
            and node.args
            and not isinstance(node.args[0], ast.Constant)
        ):
            self._finding(
                "SLA003",
                node,
                evidence=self.source_lines[max(0, node.lineno - 1)],
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            names = [name for target in node.targets for name in _targets(target)]
            if any(SECRET_NAME.search(name) for name in names) and _literal_secret(node.value.value):
                self._finding("SLA004", node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            if any(SECRET_NAME.search(name) for name in _targets(node.target)) and _literal_secret(
                node.value.value
            ):
                self._finding("SLA004", node)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            if any(SECRET_NAME.search(name) for name in _targets(node.target)) and _literal_secret(
                node.value.value
            ):
                self._finding("SLA004", node)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values):
            if (
                isinstance(key, ast.Constant)
                and isinstance(key.value, str)
                and SECRET_NAME.search(key.value)
                and isinstance(value, ast.Constant)
                and isinstance(value.value, str)
                and _literal_secret(value.value)
            ):
                self._finding("SLA004", key)
        self.generic_visit(node)


def analyze_source(source: str, relative_path: str) -> tuple[Finding, ...]:
    tree = ast.parse(source, filename=relative_path)
    visitor = _RuleVisitor(source, relative_path)
    visitor.visit(tree)
    return tuple(
        sorted(
            visitor.findings,
            key=lambda finding: (
                finding.line,
                finding.column,
                finding.rule_id,
                finding.title,
            ),
        )
    )
