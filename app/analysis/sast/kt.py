from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from app.core.source import SourceFile, SourceTree

ANNOTATION_RE = re.compile(
    r"@(?P<name>[A-Za-z_][A-Za-z0-9_.]*)"
    r"(?:\s*\((?P<args>(?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\))?",
    re.S,
)
CLASS_RE = re.compile(
    r"\b(?:(?:private|public|internal|protected|abstract|open|final|data|sealed|enum|"
    r"annotation|value|inner|companion|external)\s+)*(?:class|interface|object)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
FUN_RE = re.compile(
    r"\bfun\s+(?:<[^>]{0,200}>\s*)?(?:[A-Za-z_][A-Za-z0-9_.]*\.)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
PROPERTY_RE = re.compile(
    r"^\s*(?:(?:private|public|internal|protected|override|lateinit|const|"
    r"@\w+(?:\([^)]*\))?)\s+)*(?:val|var)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?::\s*(?P<type>[^=\n]+?))?\s*(?:=\s*(?P<value>.+?))?\s*$"
)


@dataclass
class Annotation:
    name: str
    args: str = ""
    line: int = 1

    @property
    def simple_name(self) -> str:
        return self.name.rsplit(".", 1)[-1]

    def string_args(self) -> list[str]:
        return re.findall(r'"([^"]*)"', self.args or "")

    def has(self, *names: str) -> bool:
        return self.simple_name in names


@dataclass
class KParameter:
    name: str
    type: str = ""
    annotations: list[Annotation] = field(default_factory=list)
    modifier: str = ""

    def annotation(self, *names: str) -> Annotation | None:
        for item in self.annotations:
            if item.simple_name in names:
                return item
        return None


@dataclass
class KProperty:
    name: str
    type: str = ""
    value: str = ""
    line: int = 1
    from_constructor: bool = False


@dataclass
class KFunction:
    name: str
    start_line: int
    end_line: int
    params: list[KParameter]
    annotations: list[Annotation]
    body: str
    body_start: int
    body_end: int
    class_name: str = ""
    is_expression: bool = False
    return_type: str = ""


@dataclass
class KClass:
    name: str
    start_line: int
    end_line: int
    annotations: list[Annotation]
    functions: list[KFunction] = field(default_factory=list)
    properties: dict[str, KProperty] = field(default_factory=dict)
    constructor_params: list[KParameter] = field(default_factory=list)
    body: str = ""

    def annotation(self, *names: str) -> Annotation | None:
        for item in self.annotations:
            if item.simple_name in names:
                return item
        return None


@dataclass
class KFile:
    rel_path: str
    text: str
    lines: list[str]
    package: str = ""
    imports: list[str] = field(default_factory=list)
    classes: list[KClass] = field(default_factory=list)
    functions: list[KFunction] = field(default_factory=list)
    sanitized: str = ""

    def class_by_name(self, name: str) -> KClass | None:
        for item in self.classes:
            if item.name == name:
                return item
        return None


@dataclass
class ClassRef:
    file: KFile
    klass: KClass


class KotlinIndex:
    def __init__(self, tree: SourceTree):
        self.tree = tree
        self.files: list[KFile] = []
        self.classes: dict[str, ClassRef] = {}
        for source_file in tree.files:
            if source_file.language != "kotlin":
                continue
            try:
                parsed = parse_kotlin_file(source_file)
            except Exception:
                continue
            self.files.append(parsed)
            for klass in parsed.classes:
                self.classes.setdefault(klass.name, ClassRef(parsed, klass))

    def all_functions(self) -> list[tuple[KFile, KFunction]]:
        result: list[tuple[KFile, KFunction]] = []
        for item in self.files:
            result.extend((item, function) for function in item.functions)
            for klass in item.classes:
                result.extend((item, function) for function in klass.functions)
        return result

    def find_class(self, name: str) -> ClassRef | None:
        simple = name.rsplit(".", 1)[-1].strip("?")
        return self.classes.get(simple)

    def find_method(self, class_name: str, method_name: str) -> tuple[KFile, KClass, KFunction] | None:
        reference = self.find_class(class_name)
        if not reference:
            return None
        for function in reference.klass.functions:
            if function.name == method_name:
                return reference.file, reference.klass, function
        return None


def strip_comments_and_strings(text: str) -> str:
    """Blank comments and string bodies, preserving offsets and newlines."""
    out = list(text)
    length = len(text)
    i = 0
    while i < length:
        char = text[i]
        nxt = text[i + 1] if i + 1 < length else ""
        if char == "/" and nxt == "/":
            while i < length and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if char == "/" and nxt == "*":
            depth = 1
            out[i] = out[i + 1] = " "
            i += 2
            while i < length and depth > 0:
                if text.startswith("/*", i):
                    depth += 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if text.startswith("*/", i):
                    depth -= 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        if text.startswith('"""', i):
            out[i] = out[i + 1] = out[i + 2] = " "
            i += 3
            while i < length and not text.startswith('"""', i):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            if i < length:
                out[i] = out[i + 1] = out[i + 2] = " "
                i += 3
            continue
        if char in {'"', "'"}:
            quote = char
            out[i] = " "
            i += 1
            while i < length:
                if text[i] == "\\":
                    out[i] = " "
                    if i + 1 < length:
                        out[i + 1] = " "
                    i += 2
                    continue
                if text[i] == quote:
                    out[i] = " "
                    i += 1
                    break
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def strip_comments_only(text: str) -> str:
    """Blank comments but keep string contents so literals can be inspected."""
    out = list(text)
    length = len(text)
    i = 0
    in_string: str | None = None
    triple = False
    while i < length:
        if in_string:
            if triple:
                if text.startswith('"""', i):
                    in_string = None
                    triple = False
                    i += 3
                    continue
            else:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == in_string:
                    in_string = None
            i += 1
            continue
        if text.startswith('"""', i):
            in_string = '"'
            triple = True
            i += 3
            continue
        if text[i] in {'"', "'"}:
            in_string = text[i]
            i += 1
            continue
        if text.startswith("//", i):
            while i < length and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if text.startswith("/*", i):
            depth = 1
            out[i] = out[i + 1] = " "
            i += 2
            while i < length and depth > 0:
                if text.startswith("/*", i):
                    depth += 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if text.startswith("*/", i):
                    depth -= 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _match_pair(sanitized: str, open_index: int, open_char: str, close_char: str) -> int:
    depth = 0
    for index in range(open_index, len(sanitized)):
        char = sanitized[index]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _split_top_level(text: str, separator: str = ",") -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    in_string: str | None = None
    i = 0
    while i < len(text):
        char = text[i]
        if in_string:
            if char == "\\":
                i += 2
                continue
            if char == in_string:
                in_string = None
            i += 1
            continue
        if char in {'"', "'"}:
            in_string = char
        elif char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(0, depth - 1)
        elif char == separator and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return [part for part in (p.strip() for p in parts) if part]


def _annotations_from_block(block: str, base_line: int) -> list[Annotation]:
    result: list[Annotation] = []
    for match in ANNOTATION_RE.finditer(block):
        line = base_line + block.count("\n", 0, match.start())
        result.append(
            Annotation(
                name=match.group("name"),
                args=(match.group("args") or "").strip(),
                line=line,
            )
        )
    return result


def annotations_before(lines: list[str], line_index: int) -> list[Annotation]:
    """Collect annotations directly above a declaration (1-based line index).

    The scan stops at the previous declaration, so a method does not inherit
    the annotations of its class and the next method does not inherit the
    annotations of its predecessor.
    """
    first_line = max(1, line_index - 12)
    before = lines[first_line - 1 : line_index - 1]
    joined = "\n".join(before)
    start_offset = 0
    for pattern in (
        re.compile(r"(?m)^\s*(?:package|import)\b.*$"),
        re.compile(
            r"(?m)^\s*(?:(?:private|public|internal|protected|abstract|open|final|data|sealed|"
            r"enum|annotation|value|inner|companion)\s+)*(?:class|interface|object|fun|val|var)\b.*$"
        ),
        re.compile(r"(?m)^\s*\}\s*$"),
    ):
        last = None
        for match in pattern.finditer(joined):
            last = match
        if last is not None and last.end() >= start_offset:
            start_offset = last.end()
            while start_offset < len(joined) and joined[start_offset] == "\n":
                start_offset += 1
    block = joined[start_offset:]
    base_line = first_line + joined[:start_offset].count("\n")
    return _annotations_from_block(block, base_line)


def parse_parameters(text: str, line: int) -> list[KParameter]:
    params: list[KParameter] = []
    for part in _split_top_level(text):
        annotations: list[Annotation] = []
        for match in ANNOTATION_RE.finditer(part):
            annotations.append(Annotation(match.group("name"), (match.group("args") or "").strip(), line))
        cleaned = ANNOTATION_RE.sub("", part).strip()
        cleaned = re.sub(r"^(?:vararg|val|var|crossinline|noinline)\s+", "", cleaned).strip()
        cleaned = cleaned.split("=", 1)[0].strip()
        if ":" not in cleaned:
            continue
        name_part, type_part = cleaned.rsplit(":", 1)
        name = name_part.strip().split()[-1] if name_part.strip() else ""
        name = name.lstrip("*").strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            continue
        type_text = type_part.strip()
        original = part.strip()
        modifier = ""
        if re.search(r"\bval\b", original):
            modifier = "val"
        elif re.search(r"\bvar\b", original):
            modifier = "var"
        else:
            for candidate in ("private", "public", "internal", "protected"):
                if re.search(rf"\b{candidate}\b", original):
                    modifier = candidate
                    break
        params.append(
            KParameter(
                name=name,
                type=type_text,
                annotations=annotations,
                modifier=modifier,
            )
        )
    return params


def _expression_end(text: str, sanitized: str, start: int) -> int:
    depth = 0
    i = start
    length = len(text)
    while i < length:
        char = sanitized[i]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == ";" and depth == 0:
            return i
        elif char == "\n" and depth == 0:
            before = sanitized[start:i].rstrip()
            if before.endswith(("=", "+", ",", ".", "(", "[", "&&", "||", "?:", "->")):
                i += 1
                continue
            return i
        i += 1
    return length


def parse_function(text: str, sanitized: str, lines: list[str], match: re.Match, class_name: str = "") -> KFunction | None:
    name = match.group("name")
    open_paren = sanitized.find("(", match.end() - 1)
    if open_paren < 0:
        return None
    close_paren = _match_pair(sanitized, open_paren, "(", ")")
    if close_paren < 0:
        return None
    params = parse_parameters(text[open_paren + 1 : close_paren], _line_of(text, open_paren))
    start_line = _line_of(text, match.start())
    index = close_paren + 1
    while index < len(sanitized) and sanitized[index] in " \t\r\n":
        index += 1
    return_type = ""
    if index < len(sanitized) and sanitized[index] == ":":
        type_start = index + 1
        probe = type_start
        while probe < len(sanitized) and sanitized[probe] in " \t\r\n":
            probe += 1
        type_start = probe
        depth = 0
        while probe < len(sanitized):
            char = sanitized[probe]
            if char in "(<[":
                depth += 1
            elif char in ")>]":
                depth = max(0, depth - 1)
            elif char in "={ " and depth == 0:
                break
            elif char == "\n" and depth == 0:
                break
            probe += 1
        return_type = text[type_start:probe].strip()
        index = probe
        while index < len(sanitized) and sanitized[index] in " \t\r\n":
            index += 1
    body_start = index
    body_end = index
    is_expression = False
    if index < len(sanitized) and sanitized[index] == "{":
        close = _match_pair(sanitized, index, "{", "}")
        if close < 0:
            return None
        body_start, body_end = index + 1, close
        end_line = _line_of(text, close)
    elif index < len(sanitized) and sanitized[index] == "=":
        is_expression = True
        body_start = index + 1
        while body_start < len(sanitized) and sanitized[body_start] in " \t\r\n":
            body_start += 1
        end = _expression_end(text, sanitized, body_start)
        body_end = end
        end_line = _line_of(text, end)
    else:
        return None
    return KFunction(
        name=name,
        start_line=start_line,
        end_line=end_line,
        params=params,
        annotations=annotations_before(lines, start_line),
        body=text[body_start:body_end],
        body_start=body_start,
        body_end=body_end,
        class_name=class_name,
        is_expression=is_expression,
        return_type=return_type,
    )


def parse_kotlin_file(source_file: SourceFile) -> KFile:
    text = source_file.text
    lines = text.splitlines()
    sanitized = strip_comments_and_strings(text)
    parsed = KFile(rel_path=source_file.rel_path, text=text, lines=lines, sanitized=sanitized)
    package_match = re.search(r"^\s*package\s+([A-Za-z0-9_.]+)", text, re.M)
    if package_match:
        parsed.package = package_match.group(1)
    parsed.imports = re.findall(r"^\s*import\s+([A-Za-z0-9_.*]+)", text, re.M)

    class_ranges: list[tuple[int, int]] = []
    for match in CLASS_RE.finditer(sanitized):
        name = match.group("name")
        if name in {"Companion"}:
            continue
        header_end = sanitized.find("{", match.end())
        if header_end < 0:
            continue

        between = sanitized[match.end() : header_end]
        if re.search(r"\b(?:class|interface|object|fun)\b", between):
            continue
        close = _match_pair(sanitized, header_end, "{", "}")
        if close < 0:
            continue
        start_line = _line_of(text, match.start())
        end_line = _line_of(text, close)
        class_ranges.append((match.start(), close))
        klass = KClass(
            name=name,
            start_line=start_line,
            end_line=end_line,
            annotations=annotations_before(lines, start_line),
            body=text[header_end + 1 : close],
        )

        open_paren = sanitized.find("(", match.end(), header_end)
        if open_paren >= 0:
            close_paren = _match_pair(sanitized, open_paren, "(", ")")
            if 0 <= close_paren < header_end:
                klass.constructor_params = parse_parameters(
                    text[open_paren + 1 : close_paren], _line_of(text, open_paren)
                )
                for param in klass.constructor_params:
                    if param.modifier in {"val", "var"}:
                        klass.properties[param.name] = KProperty(
                            name=param.name,
                            type=param.type,
                            line=_line_of(text, open_paren),
                            from_constructor=True,
                        )

        depth = 0
        for offset, line_text in enumerate(klass.body.splitlines(), start_line + 1):
            stripped = line_text.strip()
            if depth == 0 and stripped and not stripped.startswith("@"):
                prop_match = PROPERTY_RE.match(line_text)
                if prop_match:
                    prop_name = prop_match.group("name")
                    prop_type = (prop_match.group("type") or "").strip()
                    klass.properties.setdefault(
                        prop_name,
                        KProperty(
                            name=prop_name,
                            type=prop_type,
                            value=(prop_match.group("value") or "").strip(),
                            line=offset,
                        ),
                    )
            depth += line_text.count("{") - line_text.count("}")
            depth = max(0, depth)

        for fun_match in FUN_RE.finditer(sanitized, header_end, close):
            function = parse_function(text, sanitized, lines, fun_match, class_name=name)
            if function:
                klass.functions.append(function)
        parsed.classes.append(klass)


    for fun_match in FUN_RE.finditer(sanitized):
        offset = fun_match.start()
        if any(start <= offset <= end for start, end in class_ranges):
            continue
        function = parse_function(text, sanitized, lines, fun_match, class_name="")
        if function:
            parsed.functions.append(function)
    return parsed
