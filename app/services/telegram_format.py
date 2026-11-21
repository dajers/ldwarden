"""Преобразование Markdown-отчёта в Telegram MarkdownV2.

Telegram не понимает классический Markdown (`#`, `**`, таблицы), поэтому перед
отправкой текст аккуратно переводится в MarkdownV2: заголовки становятся жирными,
маркированные списки — точками, таблицы — строками, а все служебные символы
экранируются, чтобы Telegram не ругался «can't parse entities».
"""

from __future__ import annotations

import re

V2_SPECIAL = set("_*[]()~`>#+-=|{}.!\\")

_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_BULLET = re.compile(r"^[-*+]\s+(.*)$")
_NUMBERED = re.compile(r"^(\d+)[.)]\s+(.*)$")
_RULE = re.compile(r"^[-*_]{3,}$")
_TABLE_SEPARATOR = re.compile(r"^:?-{2,}:?$")
_INLINE = re.compile(
    r"(`[^`]+`|\*\*[^*]+\*\*|__[^_]+__|\*[^*]+\*|_[^_]+_|\[[^\]]+\]\([^)]+\))"
)
_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def escape(text: str) -> str:
    return "".join("\\" + ch if ch in V2_SPECIAL else ch for ch in text)


def _inline(text: str) -> str:
    parts: list[str] = []
    position = 0
    for match in _INLINE.finditer(text):
        parts.append(escape(text[position : match.start()]))
        token = match.group(0)
        if token.startswith("`"):
            inner = token[1:-1].replace("\\", "\\\\").replace("`", "\\`")
            parts.append("`" + inner + "`")
        elif token.startswith("**") or token.startswith("__"):
            parts.append("*" + _inline(token[2:-2]) + "*")
        elif token.startswith("["):
            label, url = _LINK.match(token).groups()
            parts.append("[" + _inline(label) + "](" + url.replace("\\", "\\\\").replace(")", "\\)") + ")")
        elif token.startswith("*") or token.startswith("_"):
            parts.append("_" + _inline(token[1:-1]) + "_")
        position = match.end()
    parts.append(escape(text[position:]))
    return "".join(parts)


def to_telegram_markdown(markdown: str) -> str:
    """Переводит Markdown в Telegram MarkdownV2."""
    lines: list[str] = []
    in_code = False
    code: list[str] = []

    for raw in str(markdown or "").splitlines():
        line = raw.rstrip()
        stripped = line.strip()

        if stripped.startswith("```"):
            if not in_code:
                in_code = True
                code = []
                lines.append("```")
            else:
                in_code = False
                lines.extend(code)
                lines.append("```")
            continue

        if in_code:
            code.append(line.replace("\\", "\\\\").replace("`", "\\`"))
            continue

        if not stripped:
            lines.append("")
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            cells = [cell.strip() for cell in stripped.strip("|").split("|")]
            if cells and all(_TABLE_SEPARATOR.fullmatch(cell) for cell in cells if cell):
                continue
            visible = [cell for cell in cells if cell]
            if visible:
                lines.append("• " + " — ".join(_inline(cell) for cell in visible))
            continue

        heading = _HEADING.match(stripped)
        if heading:
            lines.append("*" + _inline(heading.group(2).strip()) + "*")
            continue

        if _RULE.fullmatch(stripped):
            lines.append("———")
            continue

        bullet = _BULLET.match(stripped)
        if bullet:
            lines.append("• " + _inline(bullet.group(1)))
            continue

        numbered = _NUMBERED.match(stripped)
        if numbered:
            lines.append(numbered.group(1) + "\\. " + _inline(numbered.group(2)))
            continue

        if stripped.startswith(">"):
            lines.append(">" + _inline(stripped[1:].lstrip()))
            continue

        lines.append(_inline(stripped))

    return "\n".join(lines)


def split_markdown(markdown: str, size: int = 3000) -> list[str]:
    """Режет Markdown на куски, не разрывая строки (кроме совсем длинных)."""
    chunks: list[str] = []
    current: list[str] = []

    def flush() -> None:
        if current:
            chunks.append("\n".join(current))
            current.clear()

    for line in str(markdown or "").splitlines():
        if len(line) > size:
            flush()
            for start in range(0, len(line), size):
                chunks.append(line[start : start + size])
            continue
        if sum(len(item) + 1 for item in current) + len(line) + 1 > size:
            flush()
        current.append(line)
    flush()
    return chunks or [""]
