"""Shared report data structures."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Software:
    name: str
    version: str | None
    source: str


@dataclass
class Observation:
    check: str
    status: str  # pass, finding, unknown, or info
    summary: str
    evidence: str
    remediation: str | None = None


@dataclass
class Finding:
    cve_id: str
    product: str
    installed_version: str
    match_status: str  # potential_match or uncertain
    cvss_version: str | None
    cvss_source: str | None
    cvss_score: float | None
    severity: str | None
    summary: str
    source_url: str
    evidence: str
    remediation: str | None = None


@dataclass
class Assessment:
    assessed_at: str
    hostname: str
    operating_system: str
    software: list[Software] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
