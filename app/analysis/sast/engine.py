from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.analysis import AnalysisResult, BaseAnalyzer
from app.analysis.sast.kt import (
    Annotation,
    KClass,
    KFile,
    KFunction,
    KotlinIndex,
    strip_comments_only,
)
from app.core.models import Finding
from app.core.source import SourceTree

MAPPING_METHODS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
    "RequestMapping": "ANY",
}

SENSITIVE_FIELD_RE = re.compile(
    r"(?i)\b(customer_id|customerid|owner_id|ownerid|counter_note|work_note|ticket_code|"
    r"frame_tag|pickup_slot|email|phone|address|card|iban|credit|account|export)\b"
)
SQL_KEYWORD_RE = re.compile(r"(?i)\b(select|insert|update|delete|merge|call)\b")
SQL_SINK_RE = re.compile(
    r"(?i)\b(queryForList|queryForObject|queryForMap|queryForRowSet|batchUpdate|"
    r"executeQuery|executeUpdate|execute|update|query|prepareStatement|createQuery|"
    r"createNativeQuery|createSQLQuery)\s*\("
)
INTERPOLATION_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")
AUTH_CHECK_RE = re.compile(
    r"(?i)\b(principal|authentication|securitycontext|hasRole|hasAuthority|preAuthorize|"
    r"secured|rolesallowed)\b"
)

TLS_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    (
        "hostname-verifier-true",
        re.compile(r"HostnameVerifier\s*\{[^}]{0,300}?->\s*true\b", re.S),
        "MEDIUM",
        "Верификатор имени хоста принимает любое имя (`HostnameVerifier { _, _ -> true }`).",
    ),
    (
        "hostname-verifier-set",
        re.compile(
            r"setHostnameVerifier\s*\([^)]*(?:ALLOW_ALL|NoopHostnameVerifier|->\s*true)",
            re.S,
        ),
        "MEDIUM",
        "У соединения отключена проверка имени хоста.",
    ),
    (
        "trust-manager-empty",
        re.compile(r"checkServerTrusted\s*\([^)]*\)\s*(?:throws[^{]*)?\{\s*\}", re.S),
        "HIGH",
        "TrustManager не проверяет цепочку сертификатов.",
    ),
    (
        "trust-all",
        re.compile(
            r"(?i)\b(trustAllCerts|TrustAllCerts|InsecureTrustManagerFactory|"
            r"ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier)\b"
        ),
        "HIGH",
        "В коде используется доверие всем сертификатам/хостам.",
    ),
    (
        "verify-false",
        re.compile(r"(?i)\b(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)\b"),
        "MEDIUM",
        "Проверка TLS-сертификата отключена.",
    ),
]

CORS_WILDCARD_PATTERNS = [
    re.compile(r"allowedOriginPatterns\s*=\s*listOf\s*\(\s*\"\*\""),
    re.compile(r"allowedOrigins\s*=\s*(?:listOf|arrayOf|setOf)\s*\(\s*\"\*\""),
    re.compile(r"addAllowedOriginPattern?\s*\(\s*\"\*\""),
    re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']"),
    re.compile(r"origin\s*:\s*[\"']\*[\"']"),
]
CORS_CREDENTIALS_PATTERNS = [
    re.compile(r"allowCredentials\s*=\s*true"),
    re.compile(r"setAllowCredentials\s*\(\s*true"),
    re.compile(r"allow_credentials\s*=\s*True"),
    re.compile(r"credentials\s*:\s*true"),
]


@dataclass
class Route:
    method: str
    path: str
    file: KFile
    klass: KClass
    function: KFunction
    path_variables: dict[str, str] = field(default_factory=dict)


@dataclass
class SecurityRule:
    method: str
    pattern: str
    action: str
    roles: str
    line: int
    file: str
    order: int = 0


class SASTAnalyzer(BaseAnalyzer):
    name = "sast"
    title = "Статический анализ Kotlin/Spring Boot"

    def __init__(
        self,
        *,
        sql_injection: bool = True,
        tls: bool = True,
        cors: bool = True,
        route_auth: bool = True,
        object_auth: bool = True,
    ):
        self.enable_sql_injection = sql_injection
        self.enable_tls = tls
        self.enable_cors = cors
        self.enable_route_auth = route_auth
        self.enable_object_auth = object_auth

    def analyze(self, tree: SourceTree) -> AnalysisResult:
        index = KotlinIndex(tree)
        findings: list[Finding] = []
        warnings: list[str] = []
        routes = build_routes(index)
        rules = build_security_rules(index)
        if self.enable_sql_injection:
            findings.extend(detect_sql_injection(index, routes))
        if self.enable_tls:
            findings.extend(detect_tls(index))
        if self.enable_cors:
            findings.extend(detect_cors(index))
        if self.enable_route_auth:
            findings.extend(detect_route_authorization(routes, rules))
        if self.enable_object_auth:
            findings.extend(detect_object_authorization(index, routes, rules))
        if not rules and any(route for route in routes):
            warnings.append("Не найдены правила authorizeHttpRequests: проверка маршрутов ограничена")

        unique: dict[str, Finding] = {}
        for finding in findings:
            unique.setdefault(finding.fingerprint, finding)
        return self._result(
            list(unique.values()),
            len(index.files),
            kotlin_files=len(index.files),
            classes=len(index.classes),
            routes=len(routes),
            security_rules=len(rules),
            warnings=warnings,
        )


def _annotation_route(annotation: Annotation) -> tuple[str, list[str]]:
    name = annotation.simple_name
    method = MAPPING_METHODS.get(name, "ANY")
    paths = annotation.string_args()
    if name == "RequestMapping":
        methods = re.findall(r"RequestMethod\.([A-Z]+)", annotation.args or "")
        method = methods[0] if methods else "ANY"
    if not paths:
        paths = [""]
    return method, paths


def _join_path(base: str, sub: str) -> str:
    path = "/".join(part.strip("/") for part in (base or "", sub or "") if part and part.strip("/"))
    return "/" + path if path else "/"


def _path_variables(function: KFunction) -> dict[str, str]:
    result: dict[str, str] = {}
    for param in function.params:
        annotation = param.annotation("PathVariable")
        if annotation is None:
            continue
        strings = annotation.string_args()
        name = strings[0] if strings else param.name
        result[param.name] = name
    return result


def build_routes(index: KotlinIndex) -> list[Route]:
    routes: list[Route] = []
    for file in index.files:
        for klass in file.classes:
            if klass.annotation("RestController", "Controller") is None:
                continue
            base_paths = [""]
            request_mapping = klass.annotation("RequestMapping")
            if request_mapping is not None:
                base_paths = request_mapping.string_args() or [""]
            for function in klass.functions:
                for annotation in function.annotations:
                    if annotation.simple_name not in MAPPING_METHODS:
                        continue
                    method, sub_paths = _annotation_route(annotation)
                    for base in base_paths:
                        for sub in sub_paths:
                            routes.append(
                                Route(
                                    method=method,
                                    path=_join_path(base, sub),
                                    file=file,
                                    klass=klass,
                                    function=function,
                                    path_variables=_path_variables(function),
                                )
                            )

    seen: set[tuple[str, str, str, int]] = set()
    unique: list[Route] = []
    for route in routes:
        key = (route.method, route.path, route.file.rel_path, route.function.start_line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(route)
    return unique


REQUEST_MATCHER_RE = re.compile(
    r"requestMatchers\s*\((?P<args>(?:[^()]|\([^()]*\))*)\)\s*\.\s*"
    r"(?P<action>permitAll|authenticated|denyAll|hasRole|hasAuthority|hasAnyRole)\s*"
    r"\((?P<roles>[^)]*)\)",
    re.S,
)
ANY_REQUEST_RE = re.compile(
    r"anyRequest\s*\(\s*\)\s*\.\s*(?P<action>permitAll|authenticated|denyAll)\s*\([^)]*\)",
    re.S,
)
HTTP_METHOD_RE = re.compile(r"\b(?:HttpMethod\.)?(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")


def build_security_rules(index: KotlinIndex) -> list[SecurityRule]:
    rules: list[SecurityRule] = []
    order = 0
    for file in index.files:
        text = strip_comments_only(file.text)
        if "authorizeHttpRequests" not in text and "authorizeRequests" not in text:
            continue
        entries: list[tuple[int, SecurityRule]] = []
        for match in REQUEST_MATCHER_RE.finditer(text):
            args = match.group("args")
            action = match.group("action")
            roles = match.group("roles") or ""
            paths = re.findall(r'"([^"]*)"', args)
            method_match = HTTP_METHOD_RE.search(args.split('"', 1)[0]) if '"' in args else None
            method = method_match.group(1) if method_match else "ANY"
            line = text.count("\n", 0, match.start()) + 1
            if not paths:
                paths = ["/**"]
            for path in paths:
                entries.append(
                    (
                        match.start(),
                        SecurityRule(
                            method=method,
                            pattern=path or "/**",
                            action=action,
                            roles=roles,
                            line=line,
                            file=file.rel_path,
                        ),
                    )
                )
        for match in ANY_REQUEST_RE.finditer(text):
            entries.append(
                (
                    match.start(),
                    SecurityRule(
                        method="ANY",
                        pattern="/**",
                        action=match.group("action"),
                        roles="",
                        line=text.count("\n", 0, match.start()) + 1,
                        file=file.rel_path,
                    ),
                )
            )
        for _offset, rule in sorted(entries, key=lambda item: item[0]):
            rule.order = order
            order += 1
            rules.append(rule)
    return rules


def route_matches(pattern: str, path: str) -> bool:
    pattern = pattern or "/**"
    path = path or "/"
    if not pattern.startswith("/"):
        pattern = "/" + pattern
    if pattern == path:
        return True
    regex = re.escape(pattern)
    regex = regex.replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    regex = re.sub(r"\\\{[^}]+\\\}", r"[^/]+", regex)
    try:
        return re.fullmatch(regex, path) is not None
    except re.error:
        return False


def first_matching_rule(rules: list[SecurityRule], method: str, path: str) -> SecurityRule | None:
    for rule in rules:
        if rule.method != "ANY" and method != "ANY" and rule.method != method:
            continue
        if route_matches(rule.pattern, path):
            return rule
    return None


def _sql_literals(body: str) -> list[tuple[int, int, str]]:
    """Return (start, end, value) for triple and normal string literals."""
    clean = strip_comments_only(body)
    result: list[tuple[int, int, str]] = []
    occupied: list[tuple[int, int]] = []
    for match in re.finditer(r'"""(.*?)"""', clean, re.S):
        result.append((match.start(), match.end(), match.group(1)))
        occupied.append((match.start(), match.end()))
    for match in re.finditer(r'"((?:[^"\\]|\\.)*)"', clean):
        if any(start <= match.start() < end for start, end in occupied):
            continue
        result.append((match.start(), match.end(), match.group(1)))
    return result


def detect_sql_injection(index: KotlinIndex, routes: list[Route]) -> list[Finding]:
    findings: list[Finding] = []
    route_by_function: dict[tuple[str, int], list[Route]] = {}
    for route in routes:
        route_by_function.setdefault((route.file.rel_path, route.function.start_line), []).append(route)
    for file, function in index.all_functions():
        body = function.body
        if not body:
            continue
        for start, end, value in _sql_literals(body):
            if not SQL_KEYWORD_RE.search(value):
                continue
            prefix = body[max(0, start - 300) : start]
            sink_match = None
            for candidate in SQL_SINK_RE.finditer(prefix):
                sink_match = candidate
            if sink_match is None:
                continue
            suffix = body[end : end + 150]
            interpolated = [m.group(1) for m in INTERPOLATION_RE.finditer(value)]
            concat_vars = []
            prefix_concat = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*$", prefix)
            suffix_concat = re.match(r"\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)", suffix)
            if prefix_concat:
                concat_vars.append(prefix_concat.group(1))
            if suffix_concat:
                concat_vars.append(suffix_concat.group(1))
            variables = list(dict.fromkeys(interpolated + concat_vars))
            if not variables:
                continue
            tainted = {param.name for param in function.params}
            for _ in range(2):
                for local_match in re.finditer(
                    r"\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)",
                    body,
                ):
                    if local_match.group(2) in tainted:
                        tainted.add(local_match.group(1))
            literal_vars = {
                m.group(1)
                for m in re.finditer(r'\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"', body)
            }
            suspicious = [var for var in variables if var not in literal_vars]
            if not suspicious:
                continue
            tainted_hit = [var for var in suspicious if var in tainted]
            sql_line = file.text.count("\n", 0, function.body_start + start) + 1
            sql_end_line = sql_line + value.count("\n")
            first_line = min(function.start_line, sql_line)
            end_line = max(first_line, sql_end_line)
            sink_name = sink_match.group(1)
            finding = Finding(
                category="SAST",
                class_name="sql-injection",
                path=file.rel_path,
                line=first_line,
                end_line=end_line,
                severity="HIGH",
                message=(
                    "SQL-инъекция: в SQL-запрос подставляется "
                    + ", ".join(f"`{var}`" for var in suspicious)
                    + f" (sink `{sink_name}`)."
                ),
                description=(
                    f"Параметр(ы) {', '.join(suspicious)} попадают в SQL-строку без параметризации "
                    f"в {file.rel_path}:{sql_line}. Это позволяет изменить логику запроса."
                ),
                remediation=(
                    "Используйте параметризованный запрос с плейсхолдерами `?` и передавайте "
                    "значения отдельными аргументами JDBC."
                ),
                cwe="CWE-89",
                rule_id="sast-sql-injection",
                evidence=_compact_sql(value),
                confidence=0.9 if tainted_hit else 0.7,
                detector="sast-sql",
                extra={
                    "sink": sink_name,
                    "variables": suspicious,
                    "tainted": tainted_hit,
                    "routes": [
                        f"{route.method} {route.path}"
                        for route in route_by_function.get((file.rel_path, function.start_line), [])
                    ],
                },
            )
            findings.append(finding)
    return _dedupe(findings)


def _compact_sql(value: str) -> str:
    text = re.sub(r"\s+", " ", value).strip()
    return text[:200] + ("…" if len(text) > 200 else "")


def detect_tls(index: KotlinIndex) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for file in index.files:
        text = strip_comments_only(file.text)
        for rule_id, pattern, severity, description in TLS_PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                end_line = line + match.group(0).count("\n")
                if (file.rel_path, line) in seen:
                    continue
                seen.add((file.rel_path, line))
                findings.append(
                    Finding(
                        category="SAST",
                        class_name="tls-verification",
                        path=file.rel_path,
                        line=line,
                        end_line=end_line,
                        severity=severity,
                        message=description,
                        description=(
                            f"{description} Проверка сертификата/имени хоста ослаблена "
                            f"в {file.rel_path}:{line}."
                        ),
                        remediation=(
                            "Используйте штатный HostnameVerifier и стандартный TrustManager; "
                            "не отключайте проверку сертификатов."
                        ),
                        cwe="CWE-295",
                        rule_id=f"sast-tls-{rule_id}",
                        evidence=re.sub(r"\s+", " ", match.group(0))[:200],
                        confidence=0.9,
                        detector="sast-tls",
                    )
                )
    return findings


def detect_cors(index: KotlinIndex) -> list[Finding]:
    findings: list[Finding] = []
    for file in index.files:
        text = strip_comments_only(file.text)
        origin_lines: list[int] = []
        credentials_lines: list[int] = []
        for pattern in CORS_WILDCARD_PATTERNS:
            for match in pattern.finditer(text):
                origin_lines.append(text.count("\n", 0, match.start()) + 1)
        for pattern in CORS_CREDENTIALS_PATTERNS:
            for match in pattern.finditer(text):
                credentials_lines.append(text.count("\n", 0, match.start()) + 1)
        if not origin_lines or not credentials_lines:
            continue
        line = min(origin_lines + credentials_lines)
        end_line = max(origin_lines + credentials_lines)
        registration = re.search(r'registerCorsConfiguration\(\s*"([^"]+)"', text)
        registration_path = registration.group(1) if registration else ""
        sensitive = bool(
            re.search(r"(?i)(customer|private|admin|account|summary|order|ticket)", registration_path)
        )
        findings.append(
            Finding(
                category="SAST",
                class_name="credentialed-cors",
                path=file.rel_path,
                line=line,
                end_line=end_line,
                severity="MEDIUM",
                message=(
                    "CORS разрешает любой origin (`*`) и передачу credentials"
                    + (f" для `{registration_path}`" if registration_path else "")
                    + "."
                ),
                description=(
                    "Одновременно включены `allowedOrigins = \"*\"` и `allowCredentials = true`. "
                    "Любой сайт может выполнить credentialed-запрос и прочитать приватные данные."
                ),
                remediation=(
                    "Разрешите только доверенный origin клиентского интерфейса или отключите "
                    "credentialed CORS для приватного маршрута."
                ),
                cwe="CWE-942",
                rule_id="sast-credentialed-cors",
                evidence=f"allowedOrigins=*; allowCredentials=true; route={registration_path or 'n/a'}",
                confidence=0.95 if sensitive else 0.8,
                detector="sast-cors",
                extra={
                    "origin_lines": origin_lines,
                    "credentials_lines": credentials_lines,
                    "registration_path": registration_path,
                },
            )
        )
    return findings


def _has_method_security(function: KFunction) -> bool:
    for annotation in function.annotations:
        if annotation.simple_name in {"PreAuthorize", "Secured", "RolesAllowed"}:
            return True
    return bool(re.search(r"(?i)\b(hasRole|hasAuthority|PreAuthorize)\b", function.body))


def _handler_is_sensitive(route: Route) -> bool:
    body = route.function.body
    if not body:
        return False
    if _has_method_security(route.function):
        return False
    if re.search(r"(?i)\b(principal|authentication)\b", body):
        return False
    return bool(SENSITIVE_FIELD_RE.search(body))


def detect_route_authorization(routes: list[Route], rules: list[SecurityRule]) -> list[Finding]:
    grouped: dict[tuple[str, int], dict] = {}
    for route in routes:
        rule = first_matching_rule(rules, route.method, route.path)
        if rule is None or rule.action != "permitAll":
            continue
        if not _handler_is_sensitive(route):
            continue
        key = (rule.file, rule.line)
        entry = grouped.setdefault(
            key,
            {
                "rule": rule,
                "routes": [],
                "alternates": [],
            },
        )
        entry["routes"].append(route)
        alternate = {
            "path": route.file.rel_path,
            "line": route.function.start_line,
            "endLine": route.function.start_line,
            "reason": "Обработчик маршрута без проверки роли",
        }
        if alternate not in entry["alternates"]:
            entry["alternates"].append(alternate)

    findings: list[Finding] = []
    for entry in grouped.values():
        rule: SecurityRule = entry["rule"]
        routes: list[Route] = entry["routes"]
        route_text = ", ".join(f"{route.method} {route.path}" for route in routes)
        first_route = routes[0]
        findings.append(
            Finding(
                category="SAST",
                class_name="route-authorization",
                path=rule.file,
                line=rule.line,
                end_line=rule.line,
                severity="HIGH",
                message=f"Маршрут {route_text} открыт через permitAll без проверки роли.",
                description=(
                    f"Правило `{rule.pattern}` с `permitAll()` открывает {route_text}. "
                    f"Обработчик {first_route.file.rel_path}:{first_route.function.start_line} "
                    "возвращает данные клиентов/выдачи без отдельной проверки роли."
                ),
                remediation=(
                    "Замените permitAll() на hasRole(\"MECHANIC\") (или другую требуемую роль) "
                    "и проверьте доступ для гостя, клиента и мастера."
                ),
                cwe="CWE-862",
                rule_id="sast-route-authorization",
                evidence=f"{rule.action}: {rule.pattern} ({rule.file}:{rule.line})",
                confidence=0.9,
                detector="sast-authz",
                alternate_locations=entry["alternates"],
                extra={
                    "route": route_text,
                    "security_action": rule.action,
                    "roles": rule.roles,
                },
            )
        )
    return findings


OWNER_COLUMN_RE = re.compile(r"(?i)\b(customer_id|owner_id|user_id|account_id|created_by)\b")
ID_COLUMN_RE = re.compile(r"(?i)\b([a-z_]*id)\b")


def _split_sql(value: str) -> tuple[str, str, str]:
    lowered = value.lower()
    from_index = lowered.find(" from ")
    where_index = lowered.find(" where ")
    select_part = value[: from_index] if from_index >= 0 else value
    where_part = ""
    if where_index >= 0:
        where_part = value[where_index + len(" where ") :]
        if " order by " in where_part.lower():
            where_part = where_part[: where_part.lower().find(" order by ")]
    return select_part, where_part, value


def _target_has_owner_predicate(where_part: str) -> bool:
    return bool(
        re.search(
            r"(?i)\b(customer_id|owner_id|user_id|account_id|created_by)\s*=\s*\?",
            where_part,
        )
    )


def _target_uses_principal(function: KFunction, klass: KClass) -> bool:
    if AUTH_CHECK_RE.search(function.body or ""):
        return True
    for param in function.params:
        if re.search(r"(?i)(principal|authentication|customerId|ownerId|userId)", param.name):
            return True
        if re.search(r"(?i)(Principal|Authentication)", param.type):
            return True
    return False


def _analyze_idor_target(target: KFunction, target_class: KClass) -> tuple[str, int, str] | None:
    if _target_uses_principal(target, target_class):
        return None
    for start, end, value in _sql_literals(target.body or ""):
        if not SQL_KEYWORD_RE.search(value) or "select" not in value.lower():
            continue
        select_part, where_part, _ = _split_sql(value)
        if not OWNER_COLUMN_RE.search(select_part):
            continue
        if _target_has_owner_predicate(where_part):
            continue
        if not where_part:
            continue

        if not re.search(r"(?i)\b([a-z_]*id)\s*=\s*\?", value):
            continue

        return value, start, where_part
    return None


def detect_object_authorization(
    index: KotlinIndex, routes: list[Route], rules: list[SecurityRule]
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for route in routes:
        if not route.path_variables:
            continue
        rule = first_matching_rule(rules, route.method, route.path)
        if rule is None or rule.action == "permitAll":
            continue
        if _has_method_security(route.function):
            continue
        if AUTH_CHECK_RE.search(route.function.body or "") and re.search(
            r"(?i)(customer|owner|principal)", route.function.body or ""
        ):
            continue
        for param in route.function.params:
            path_annotation = param.annotation("PathVariable")
            if path_annotation is None:
                continue
            for call in re.finditer(
                r"(?P<recv>[A-Za-z_][A-Za-z0-9_]*)\.(?P<method>[A-Za-z_][A-Za-z0-9_]*)\(\s*"
                r"(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?(?P<arg>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
                route.function.body or "",
            ):
                if call.group("arg") != param.name:
                    continue
                receiver = call.group("recv")
                method_name = call.group("method")
                receiver_type = ""
                property_info = route.klass.properties.get(receiver)
                if property_info and property_info.type:
                    receiver_type = property_info.type
                if not receiver_type:
                    for ctor_param in route.klass.constructor_params:
                        if ctor_param.name == receiver:
                            receiver_type = ctor_param.type
                            break
                receiver_type = receiver_type.split("<", 1)[0].strip("? ")
                if not receiver_type:
                    continue
                resolved = index.find_method(receiver_type, method_name)
                if not resolved:
                    continue
                target_file, target_class, target_function = resolved
                analysis = _analyze_idor_target(target_function, target_class)
                if analysis is None:
                    continue
                sql_value, sql_offset, _where = analysis
                sql_line = target_file.text.count("\n", 0, target_function.body_start + sql_offset) + 1
                key = (target_file.rel_path, target_function.start_line)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        category="SAST",
                        class_name="object-authorization",
                        path=target_file.rel_path,
                        line=target_function.start_line,
                        end_line=max(target_function.start_line, sql_line),
                        severity="HIGH",
                        message=(
                            f"IDOR: {route.method} {route.path} читает запись по ID "
                            f"`{param.name}` без проверки владельца."
                        ),
                        description=(
                            f"Маршрут {route.method} {route.path} требует входа, но "
                            f"{target_file.rel_path}:{target_function.start_line} выбирает запись "
                            "по одному ID и не фильтрует по владельцу (customer_id), поэтому "
                            "клиент может прочитать чужую заявку."
                        ),
                        remediation=(
                            "Добавьте в запрос условие по owner-полю и передавайте идентификатор "
                            "из Principal; для чужой и отсутствующей записи возвращайте одинаковый ответ."
                        ),
                        cwe="CWE-639",
                        rule_id="sast-object-authorization",
                        evidence=_compact_sql(sql_value),
                        confidence=0.9,
                        detector="sast-idor",
                        alternate_locations=[
                            {
                                "path": route.file.rel_path,
                                "line": route.function.start_line,
                                "endLine": max(route.function.start_line, route.function.end_line),
                                "reason": "Точка входа без проверки владельца",
                            }
                        ],
                        extra={
                            "route": f"{route.method} {route.path}",
                            "receiver": f"{receiver_type}.{method_name}",
                            "path_variable": param.name,
                        },
                    )
                )
    return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.fingerprint, finding)
    return list(unique.values())
