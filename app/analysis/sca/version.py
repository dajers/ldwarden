from __future__ import annotations

import re

_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*$")


def parse_version(value: str | None) -> list[int] | None:
    if not value:
        return None
    text = str(value).strip()
    if not _VERSION_RE.match(text):
        return None
    return [int(part) for part in text.split(".")]


def normalize_version(value: str | None) -> list[int] | None:
    parsed = parse_version(value)
    if parsed is None:
        return None
    while len(parsed) > 1 and parsed[-1] == 0:
        parsed.pop()
    return parsed


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1.  Raises ValueError for non-numeric versions."""
    a = normalize_version(left)
    b = normalize_version(right)
    if a is None or b is None:
        raise ValueError(f"Некорректная версия: {left!r} / {right!r}")
    length = max(len(a), len(b))
    a = a + [0] * (length - len(a))
    b = b + [0] * (length - len(b))
    for x, y in zip(a, b):
        if x < y:
            return -1
        if x > y:
            return 1
    return 0


def version_in_range(version: str, interval: dict) -> bool:
    parsed = parse_version(version)
    if parsed is None:
        return False
    lower = interval.get("lower")
    upper = interval.get("upper")
    if lower is not None:
        cmp_lower = compare_versions(version, lower)
        if cmp_lower < 0 or (cmp_lower == 0 and not interval.get("lowerInclusive", False)):
            return False
    if upper is not None:
        cmp_upper = compare_versions(version, upper)
        if cmp_upper > 0 or (cmp_upper == 0 and not interval.get("upperInclusive", False)):
            return False
    return True


def version_in_ranges(version: str, ranges: list[dict]) -> bool:
    return any(version_in_range(version, interval) for interval in ranges or [])


def format_range(interval: dict) -> str:
    lower = interval.get("lower")
    upper = interval.get("upper")
    left = "[" if interval.get("lowerInclusive") else "("
    right = "]" if interval.get("upperInclusive") else ")"
    left_value = lower if lower is not None else "−∞"
    right_value = upper if upper is not None else "+∞"
    if lower is None:
        left = "("
    return f"{left}{left_value}, {right_value}{right}"


def format_ranges(ranges: list[dict]) -> str:
    return ", ".join(format_range(item) for item in ranges or [])
