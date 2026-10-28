"""Conservative numeric version-range matching helpers for NVD data."""

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class VersionBound:
    value: str
    inclusive: bool


@dataclass(frozen=True)
class VersionRange:
    start: VersionBound | None = None
    end: VersionBound | None = None


def _parts(version: str) -> tuple[int, ...] | None:
    """Accept dotted numeric versions only; reject suffixes instead of guessing."""
    if not re.fullmatch(r"\d+(?:\.\d+)*", version.strip()):
        return None
    return tuple(int(part) for part in version.strip().split("."))


def _compare(left: str, right: str) -> int | None:
    a, b = _parts(left), _parts(right)
    if a is None or b is None:
        return None
    size = max(len(a), len(b))
    a += (0,) * (size - len(a))
    b += (0,) * (size - len(b))
    return (a > b) - (a < b)


def match_version(installed: str, version_range: VersionRange) -> str:
    """Return potential_match, not_affected, or uncertain."""
    if _parts(installed) is None:
        return "uncertain"
    if version_range.start:
        result = _compare(installed, version_range.start.value)
        if result is None:
            return "uncertain"
        if result < 0 or (result == 0 and not version_range.start.inclusive):
            return "not_affected"
    if version_range.end:
        result = _compare(installed, version_range.end.value)
        if result is None:
            return "uncertain"
        if result > 0 or (result == 0 and not version_range.end.inclusive):
            return "not_affected"
    if version_range.start is None and version_range.end is None:
        return "uncertain"
    return "potential_match"


def nvd_range(match: dict[str, Any]) -> VersionRange | None:
    """Translate NVD 2.0 CPE match bounds into the local numeric matcher."""
    start = match.get("versionStartIncluding")
    start_ex = match.get("versionStartExcluding")
    end = match.get("versionEndIncluding")
    end_ex = match.get("versionEndExcluding")
    if start and start_ex or end and end_ex:
        return None
    # A concrete version in the CPE criterion is an exact version when no
    # explicit range fields are supplied. Wildcards without bounds are unknown.
    criteria = match.get("criteria", "")
    pieces = criteria.split(":")
    cpe_version = pieces[5] if len(pieces) > 5 else "*"
    if not any((start, start_ex, end, end_ex)):
        if cpe_version not in ("*", "-"):
            start = end = cpe_version
            return VersionRange(VersionBound(start, True), VersionBound(end, True))
        return None
    return VersionRange(
        VersionBound(start or start_ex, bool(start)) if (start or start_ex) else None,
        VersionBound(end or end_ex, bool(end)) if (end or end_ex) else None,
    )


def cpe_vendor_product(criteria: str) -> tuple[str, str] | None:
    """Read vendor/product fields from a well-formed CPE 2.3 formatted string."""
    fields = criteria.split(":")
    if len(fields) < 6 or fields[0] != "cpe" or fields[1] != "2.3":
        return None
    return fields[3].casefold(), fields[4].casefold()
