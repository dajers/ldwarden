from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from app.analysis import AnalysisResult, BaseAnalyzer
from app.core.models import Finding
from app.core.source import SourceFile, SourceTree
from app.crypto import looks_like_placeholder, mask_value

SECRET_NAME_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|credential|authorization|bearer|client[_-]?secret|x[_-]?api[_-]?key)"
)
PASSWORD_NAME_RE = re.compile(r"(?i)(password|passwd|pwd|db[_-]?pass|legacy.*pass)")
API_KEY_NAME_RE = re.compile(r"(?i)(api[_-]?key|apikey|x[_-]?api[_-]?key|access[_-]?key)")
TOKEN_NAME_RE = re.compile(r"(?i)(token|secret|credential|authorization|bearer)")

ASSIGN_LITERAL_RE = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?::\s*[A-Za-z_][A-Za-z0-9_<>?., \[\]]*)?\s*"
    r"(?:=|:=)\s*(?P<q>[\"'])(?P<value>[^\"'\n]{4,})(?P=q)"
)
ELVIS_RE = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*System\.getenv\([^)]*\)\s*\?:\s*"
    r"(?P<q>[\"'])(?P<value>[^\"'\n]{4,})(?P=q)"
)
YAML_KEY_RE = re.compile(
    r"^\s*(?:-\s*)?[\"']?(?P<name>[A-Za-z0-9_.-]+)[\"']?\s*:\s*(?P<value>.+?)\s*$"
)
VAL_RE = re.compile(
    r"^\s*(?:(?:private|public|internal|protected|const|override)\s+)*val\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=]+)?=\s*(?P<expr>.+?)\s*$"
)
SET_BEARER_RE = re.compile(r"setBearerAuth\s*\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)")
HEADER_USE_RE = re.compile(
    r"\.(?:header|add|set|put)\s*\(\s*"
    r"(?P<header>\"(?:Authorization|X-Api-Key|X-Auth-Token|X-Import-Password|X-API-Token)\"|"
    r"HttpHeaders\.(?:AUTHORIZATION|AUTHORIZATION_HEADER))\s*,\s*"
    r"(?P<value>[A-Za-z_][A-Za-z0-9_]*|\"[^\"]*\")"
)
STRING_LITERAL_RE = re.compile(r"\"(?P<value>(?:\\.|[^\"\\\n]){4,})\"")
BEARER_LITERAL_RE = re.compile(r"(?i)\bBearer\s+(?P<value>[A-Za-z0-9._~+/\-]{16,}=*)")

KNOWN_FORMATS: list[tuple[str, re.Pattern, str, str]] = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "api-key", "HIGH"),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "api-key", "HIGH"),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "api-key", "HIGH"),
    ("stripe-key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"), "api-key", "HIGH"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "api-key", "MEDIUM"),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "token",
        "MEDIUM",
    ),
]
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
)
PRIVATE_KEY_END_RE = re.compile(r"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
CONNECTION_STRING_RE = re.compile(
    r"(?i)\b(?:mongodb|postgres|postgresql|mysql|mariadb|redis|amqp|amqps)://"
    r"[^:\s/@]+:[^@\s/]+@[^\s\"']+"
)
CONNECTION_PASSWORD_RE = re.compile(r"(?i)(?:password|passwd|pwd)\s*=\s*[^;&\s]{4,}")

CLASS_PRIORITY = {
    "private-key": 100,
    "password": 95,
    "connection-string": 92,
    "api-key": 90,
    "configuration-token": 85,
    "secret-fallback": 80,
    "recoverable-token": 75,
    "token": 60,
    "generic-secret": 50,
}
CLASS_SEVERITY = {
    "private-key": "CRITICAL",
    "password": "HIGH",
    "connection-string": "HIGH",
    "api-key": "MEDIUM",
    "configuration-token": "HIGH",
    "secret-fallback": "LOW",
    "recoverable-token": "MEDIUM",
    "token": "MEDIUM",
    "generic-secret": "MEDIUM",
}
CLASS_CWE = {
    "private-key": "CWE-321",
    "password": "CWE-798",
    "connection-string": "CWE-798",
    "api-key": "CWE-798",
    "configuration-token": "CWE-798",
    "secret-fallback": "CWE-798",
    "recoverable-token": "CWE-798",
    "token": "CWE-798",
    "generic-secret": "CWE-798",
}
CLASS_REMEDIATION = {
    "private-key": "Отзовите и перевыпустите ключ, удалите его из истории Git и храните в секретном хранилище.",
    "password": "Вынесите пароль в переменные окружения или Vault и смените скомпрометированное значение.",
    "connection-string": "Уберите пароль из строки подключения, используйте переменные окружения и ротацию credentials.",
    "api-key": "Передавайте ключ через настройки окружения или секретное хранилище, не храните его в коде.",
    "configuration-token": "Задайте свойство через переменную окружения без встроенного значения и перевыпустите токен.",
    "secret-fallback": "Удалите fallback-значение: при отсутствии переменной интеграция должна отключаться.",
    "recoverable-token": "Соберите токен из переменных окружения или секрета, не склеивайте его из литералов в коде.",
    "token": "Вынесите токен в секретное хранилище и перевыпустите его.",
    "generic-secret": "Вынесите значение в секретное хранилище и перевыпустите его.",
}


@dataclass
class Candidate:
    path: str
    line: int
    class_name: str
    value: str
    name: str = ""
    evidence: str = ""
    end_line: int | None = None
    confidence: float = 0.8
    rule_id: str = ""
    detection: str = ""

    @property
    def priority(self) -> int:
        return CLASS_PRIORITY.get(self.class_name, 0)

    def to_finding(self) -> Finding:
        severity = CLASS_SEVERITY.get(self.class_name, "MEDIUM")
        masked = mask_value(self.value)
        description = _description(self.class_name, self.name, self.path)
        message = f"{description} Значение замаскировано: {masked}."
        return Finding(
            category="SECRET",
            class_name=self.class_name,
            path=self.path,
            line=self.line,
            end_line=self.end_line,
            severity=severity,
            message=message,
            description=description,
            remediation=CLASS_REMEDIATION.get(self.class_name, CLASS_REMEDIATION["generic-secret"]),
            cwe=CLASS_CWE.get(self.class_name),
            rule_id=self.rule_id or f"secret-{self.class_name}",
            evidence=self.evidence or f"{self.name} = \"{masked}\"",
            confidence=self.confidence,
            detector="secret-scanner",
            extra={"detection": self.detection, "variable": self.name},
        )


def _description(class_name: str, name: str, path: str) -> str:
    suffix = f" (`{name}`)" if name else ""
    base = {
        "password": "В коде оставлен пароль в открытом виде",
        "api-key": "В коде оставлен API-ключ в открытом виде",
        "configuration-token": "В конфигурации оставлен токен в открытом виде",
        "secret-fallback": "Для секрета задано встроенное значение по умолчанию (fallback)",
        "recoverable-token": "Токен собирается из строковых литералов в коде и может быть восстановлен",
        "private-key": "В репозитории находится приватный ключ",
        "connection-string": "Строка подключения содержит пароль в открытом виде",
        "token": "В коде оставлен токен в открытом виде",
        "generic-secret": "В коде оставлен секрет в открытом виде",
    }[class_name]
    return f"{base}{suffix} — `{path}`."


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _clean_value(value: str) -> str:
    return value.strip().strip("\"'")


def _is_ignored_value(value: str) -> bool:
    value = _clean_value(value)
    if not value:
        return True
    if looks_like_placeholder(value):
        return True
    lowered = value.lower()
    if lowered in {"true", "false", "null", "none", "undefined", "bearer", "basic"}:
        return True
    if value.startswith(("${", "$", "{{", "env(", "System.getenv", "process.env")):
        return True
    if value.startswith(("/", "./", "../", "~/")):
        return True
    if re.match(r"^[A-Z][A-Z0-9_]+$", value) and not re.search(r"[a-z0-9]", value):
        return True
    if re.match(r"^(?:https?|ftp)://", value) and "@" not in value:
        return True
    if " " in value and not value.lower().startswith("bearer "):
        return True
    if re.match(r"^[a-z]+(?:\.[a-z]+)+$", value) and value.count(".") >= 2:
        return True
    return False


def _passes_entropy(class_name: str, value: str) -> bool:
    text = re.sub(r"(?i)^bearer\s+", "", _clean_value(value))
    entropy = shannon_entropy(text)
    length = len(text)
    if class_name in ("password", "secret-fallback"):
        return length >= 6 and entropy >= 1.8
    if class_name in ("api-key", "configuration-token"):
        return length >= 8 and entropy >= 2.2
    if class_name == "recoverable-token":
        return length >= 12 and entropy >= 2.8
    if class_name in ("private-key", "connection-string"):
        return True
    return length >= 16 and entropy >= 3.0


def _name_class(name: str, path: str) -> str:
    if PASSWORD_NAME_RE.search(name):
        return "password"
    if API_KEY_NAME_RE.search(name):
        return "api-key"
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in {".yml", ".yaml", ".properties", ".json", ".env", ".toml", ".conf", ".ini"}:
        return "configuration-token"
    return "token"


def _header_class(header: str) -> str:
    lowered = header.lower()
    if "api-key" in lowered or "apikey" in lowered:
        return "api-key"
    if "import-password" in lowered:
        return "password"
    return "configuration-token"


class SecretAnalyzer(BaseAnalyzer):
    name = "secrets"
    title = "Поиск секретов"

    def __init__(self, scan_docs: bool = True):
        self.scan_docs = scan_docs

    def analyze(self, tree: SourceTree) -> AnalysisResult:
        candidates: list[Candidate] = []
        scanned = 0
        warnings: list[str] = []
        for source_file in tree.files:
            if source_file.language in {"unknown"}:
                continue
            if source_file.language == "markdown" and not self.scan_docs:
                continue
            scanned += 1
            try:
                candidates.extend(self._scan_file(source_file))
            except Exception as exc:
                warnings.append(f"{source_file.rel_path}: ошибка анализа секретов: {exc}")
        findings = self._dedupe(candidates)
        return self._result(
            findings,
            scanned,
            by_class=_count(findings, "class_name"),
            by_severity=_count(findings, "severity"),
            warnings=warnings,
        )


    def _scan_file(self, source_file: SourceFile) -> list[Candidate]:
        text = source_file.text
        if not text:
            return []
        lines = text.splitlines()
        path = source_file.rel_path
        language = source_file.language
        found: list[Candidate] = []

        found.extend(self._elvis_candidates(path, lines))
        found.extend(self._folded_candidates(path, lines))
        found.extend(self._yaml_candidates(path, lines, language))
        found.extend(self._assignment_candidates(path, lines, language))
        found.extend(self._known_format_candidates(path, text))
        found.extend(self._private_key_candidates(path, lines))
        found.extend(self._connection_string_candidates(path, lines))
        found.extend(self._bearer_candidates(path, lines))
        found.extend(self._header_usage_candidates(path, lines))
        return found

    def _assignment_candidates(self, path: str, lines: list[str], language: str) -> list[Candidate]:
        result: list[Candidate] = []
        for index, line in enumerate(lines, 1):
            if "=" not in line:
                continue
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "/*")):
                continue
            for match in ASSIGN_LITERAL_RE.finditer(line):
                name = match.group("name")
                value = match.group("value")
                if not SECRET_NAME_RE.search(name):
                    continue
                if _is_ignored_value(value) or not _passes_entropy(_name_class(name, path), value):
                    continue
                class_name = _name_class(name, path)

                if language == "markdown" and "=" not in line:
                    continue
                result.append(
                    Candidate(
                        path=path,
                        line=index,
                        class_name=class_name,
                        value=value,
                        name=name,
                        evidence=f'{name} = "{mask_value(value)}"',
                        confidence=0.85 if class_name != "token" else 0.65,
                        rule_id=f"secret-{class_name}",
                        detection="assignment",
                    )
                )
        return result

    def _yaml_candidates(self, path: str, lines: list[str], language: str) -> list[Candidate]:
        if language not in {"yaml", "properties", "dotenv", "config", "json", "toml"}:
            return []
        result: list[Candidate] = []
        stack: list[tuple[int, str]] = []
        for index, line in enumerate(lines, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip(" "))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            match = YAML_KEY_RE.match(line)
            if not match:
                continue
            name = match.group("name")
            raw_value = match.group("value").strip()

            raw_value = re.sub(r"\s+#.*$", "", raw_value).strip()
            if raw_value.startswith(("'", '"')) and raw_value[-1:] == raw_value[0]:
                raw_value = raw_value[1:-1]
            stack.append((indent, name))
            key_path = ".".join(part for _, part in stack)
            if not SECRET_NAME_RE.search(name) and not raw_value.lower().startswith("bearer "):
                continue
            if _is_ignored_value(raw_value):
                continue
            class_name = "configuration-token" if TOKEN_NAME_RE.search(name) else _name_class(name, path)
            if raw_value.lower().startswith("bearer "):
                class_name = "configuration-token"
                value = raw_value[7:].strip()
            else:
                value = raw_value
            if not _passes_entropy(class_name, value):
                continue
            result.append(
                Candidate(
                    path=path,
                    line=index,
                    class_name=class_name,
                    value=value,
                    name=key_path,
                    evidence=f"{key_path}: \"{mask_value(raw_value)}\"",
                    confidence=0.9,
                    rule_id=f"secret-{class_name}",
                    detection="yaml-key",
                )
            )
        return result

    def _elvis_candidates(self, path: str, lines: list[str]) -> list[Candidate]:
        result: list[Candidate] = []
        for index, line in enumerate(lines, 1):
            for match in ELVIS_RE.finditer(line):
                value = match.group("value")
                if _is_ignored_value(value):
                    continue
                name = match.group("name")
                result.append(
                    Candidate(
                        path=path,
                        line=index,
                        class_name="secret-fallback",
                        value=value,
                        name=name,
                        evidence=f'{name} = System.getenv(...) ?: "{mask_value(value)}"',
                        confidence=0.9,
                        rule_id="secret-secret-fallback",
                        detection="elvis-fallback",
                    )
                )
        return result

    def _folded_candidates(self, path: str, lines: list[str]) -> list[Candidate]:
        resolved: dict[str, tuple[str, int, list[str]]] = {}
        result: list[Candidate] = []
        auth_vars: dict[str, int] = {}
        for index, line in enumerate(lines, 1):
            for match in SET_BEARER_RE.finditer(line):
                auth_vars[match.group("name")] = index
            for match in HEADER_USE_RE.finditer(line):
                value = match.group("value").strip('"')
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", value):
                    auth_vars[value] = index
            match = VAL_RE.match(line)
            if not match:
                continue
            name = match.group("name")
            expr = match.group("expr").strip()
            parts = [part.strip() for part in re.split(r"\s+\+\s+", expr) if part.strip()]
            values: list[str] = []
            sources: list[str] = []
            resolvable = True
            for part in parts:
                literal = re.fullmatch(r"\"((?:\\.|[^\"\\])*)\"", part)
                if literal:
                    values.append(literal.group(1))
                    sources.append(name)
                    continue
                if part in resolved:
                    value, _start, _parts = resolved[part]
                    values.append(value)
                    sources.extend(_parts)
                    continue
                if re.match(r"^(?:System\.getenv|System\.getProperty|providers\.|System\.getenv)", part):
                    resolvable = False
                    continue
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part):

                    resolvable = False
                    continue
                resolvable = False
            if resolvable and values:
                value = "".join(values)
                start = min((resolved[p][1] for p in parts if p in resolved), default=index)
                resolved[name] = (value, start, sources or [name])
            elif not resolvable:
                resolved.pop(name, None)

        for name, (value, start, _sources) in resolved.items():
            usage_line = auth_vars.get(name)
            if usage_line is None:
                continue
            if len(value) < 12 or shannon_entropy(value) < 2.8:
                continue
            if _is_ignored_value(value):
                continue
            result.append(
                Candidate(
                    path=path,
                    line=min(start, usage_line),
                    end_line=max(start, usage_line),
                    class_name="recoverable-token",
                    value=value,
                    name=name,
                    evidence=(
                        f"{' + '.join(_sources)} → auth header; "
                        f"восстановленное значение: {mask_value(value)}"
                    ),
                    confidence=0.85,
                    rule_id="secret-recoverable-token",
                    detection="folded-token",
                )
            )
        return result

    def _known_format_candidates(self, path: str, text: str) -> list[Candidate]:
        result: list[Candidate] = []
        for rule_id, pattern, class_name, severity in KNOWN_FORMATS:
            for match in pattern.finditer(text):
                value = match.group(0)
                if _is_ignored_value(value):
                    continue
                line = text.count("\n", 0, match.start()) + 1
                result.append(
                    Candidate(
                        path=path,
                        line=line,
                        class_name=class_name,
                        value=value,
                        name=rule_id,
                        evidence=f"{rule_id}: {mask_value(value)}",
                        confidence=0.95,
                        rule_id=f"secret-{rule_id}",
                        detection="known-format",
                    )
                )
        return result

    def _private_key_candidates(self, path: str, lines: list[str]) -> list[Candidate]:
        result: list[Candidate] = []
        for index, line in enumerate(lines, 1):
            match = PRIVATE_KEY_RE.search(line)
            if not match:
                continue
            end = index
            for probe in range(index, min(len(lines), index + 14) + 1):
                if PRIVATE_KEY_END_RE.search(lines[probe - 1]):
                    end = probe
                    break
            result.append(
                Candidate(
                    path=path,
                    line=index,
                    end_line=end,
                    class_name="private-key",
                    value=match.group(0),
                    name="private-key",
                    evidence="-----BEGIN PRIVATE KEY----- [содержимое скрыто]",
                    confidence=0.99,
                    rule_id="secret-private-key",
                    detection="private-key-block",
                )
            )
        return result

    def _connection_string_candidates(self, path: str, lines: list[str]) -> list[Candidate]:
        result: list[Candidate] = []
        for index, line in enumerate(lines, 1):
            for match in CONNECTION_STRING_RE.finditer(line):
                value = match.group(0)
                if _is_ignored_value(value):
                    continue
                result.append(
                    Candidate(
                        path=path,
                        line=index,
                        class_name="connection-string",
                        value=value,
                        name="connection-string",
                        evidence=f"connection string: {mask_value(value)}",
                        confidence=0.9,
                        rule_id="secret-connection-string",
                        detection="connection-string",
                    )
                )
            for match in CONNECTION_PASSWORD_RE.finditer(line):
                value = match.group(0)
                if "REDACTED" in value.upper() or "***" in value:
                    continue
                result.append(
                    Candidate(
                        path=path,
                        line=index,
                        class_name="connection-string",
                        value=value,
                        name="connection-password",
                        evidence=f"connection password: {mask_value(value)}",
                        confidence=0.7,
                        rule_id="secret-connection-string",
                        detection="connection-password",
                    )
                )
        return result

    def _bearer_candidates(self, path: str, lines: list[str]) -> list[Candidate]:
        result: list[Candidate] = []
        for index, line in enumerate(lines, 1):
            if "Bearer" not in line and "bearer" not in line:
                continue
            for match in BEARER_LITERAL_RE.finditer(line):
                value = match.group("value")
                if _is_ignored_value(value):
                    continue
                result.append(
                    Candidate(
                        path=path,
                        line=index,
                        class_name="configuration-token",
                        value=value,
                        name="Bearer",
                        evidence=f"Bearer {mask_value(value)}",
                        confidence=0.85,
                        rule_id="secret-configuration-token",
                        detection="bearer-literal",
                    )
                )
        return result

    def _header_usage_candidates(self, path: str, lines: list[str]) -> list[Candidate]:
        """Classify a literal passed directly into an auth header."""
        result: list[Candidate] = []
        for index, line in enumerate(lines, 1):
            for match in HEADER_USE_RE.finditer(line):
                header = match.group("header")
                value = match.group("value")
                if not value.startswith('"'):
                    continue
                literal = value.strip('"')
                if _is_ignored_value(literal):
                    continue
                class_name = _header_class(header)
                if not _passes_entropy(class_name, literal):
                    continue
                result.append(
                    Candidate(
                        path=path,
                        line=index,
                        class_name=class_name,
                        value=literal,
                        name=header.strip('"'),
                        evidence=f"{header}: {mask_value(literal)}",
                        confidence=0.8,
                        rule_id=f"secret-{class_name}",
                        detection="header-literal",
                    )
                )
        return result

    def _dedupe(self, candidates: list[Candidate]) -> list[Finding]:


        best: dict[tuple[str, int], Candidate] = {}
        for candidate in candidates:
            key = (candidate.path, candidate.line)
            current = best.get(key)
            if current is None or candidate.priority > current.priority:
                best[key] = candidate
            elif candidate.priority == current.priority and candidate.confidence > current.confidence:
                best[key] = candidate
        findings: list[Finding] = []
        folded_ranges = [
            c
            for c in best.values()
            if c.class_name == "recoverable-token" and c.end_line and c.end_line > c.line
        ]
        for candidate in best.values():

            covered = any(
                other is not candidate
                and other.path == candidate.path
                and other.line <= candidate.line <= (other.end_line or other.line)
                and other.class_name == "recoverable-token"
                for other in folded_ranges
            )
            if covered and candidate.class_name != "recoverable-token":
                continue
            findings.append(candidate.to_finding())
        return findings


def _count(findings: list[Finding], attribute: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for finding in findings:
        key = str(getattr(finding, attribute))
        result[key] = result.get(key, 0) + 1
    return dict(sorted(result.items(), key=lambda item: (-item[1], item[0])))
