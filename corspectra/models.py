"""Typed domain models shared by scanners, analyzers, and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

CORS_HEADER_NAMES = (
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
    "vary",
)


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


@dataclass(slots=True)
class ResponseRecord:
    endpoint: str
    method: str
    origin: str | None
    status_code: int
    headers: dict[str, str]
    content_type: str = ""
    content_length: int = 0
    body_hash: str = ""
    body_preview: str = ""
    redirect_location: str | None = None
    elapsed_ms: float = 0.0
    requested_method: str | None = None
    requested_headers: list[str] = field(default_factory=list)

    @property
    def cors_headers(self) -> dict[str, str]:
        return {k: v for k, v in self.headers.items() if k.lower() in CORS_HEADER_NAMES}


@dataclass(slots=True)
class Finding:
    finding_id: str
    title: str
    severity: Severity
    confidence: str
    endpoint: str
    method: str
    origin_tested: str | None
    observed_headers: dict[str, str]
    expected_behavior: str
    evidence: str
    reason: str
    impact: str
    remediation: str
    references: list[str] = field(default_factory=list)
    score: int = 0


@dataclass(slots=True)
class ScanStatistics:
    targets: int = 1
    endpoints: int = 0
    requests: int = 0
    origins_tested: int = 0
    errors: int = 0


@dataclass(slots=True)
class ScanResult:
    target: str
    endpoints: list[str] = field(default_factory=list)
    responses: list[ResponseRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    statistics: ScanStatistics = field(default_factory=ScanStatistics)
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    completed_at: str | None = None
    version: str = "1.0.0"

    def finish(self) -> None:
        self.completed_at = datetime.now(UTC).isoformat()
        self.statistics.endpoints = len(self.endpoints)
        self.statistics.requests = len(self.responses)
        self.statistics.errors = len(self.errors)
        self.statistics.origins_tested = len({r.origin for r in self.responses if r.origin})

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for finding in data["findings"]:
            finding["severity"] = Severity(finding["severity"]).name
        return data
