"""Core data types shared by checks, the runner and the API."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Status(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"
    SKIP = "skip"
    ERROR = "error"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_SEVERITY_RANK = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def worst_severity(severities: list[Severity]) -> Severity:
    return max(severities, key=_SEVERITY_RANK.index, default=Severity.INFO)


@dataclass
class Outcome:
    """What a check function returns. The runner turns it into a CheckResult."""

    status: Status
    summary: str
    details: Any = None
    recommendation: str | None = None
    # Overrides the severity declared on the check, e.g. a "weak" finding
    # that is less severe than a missing control.
    severity: Severity | None = None
    references: list[str] = field(default_factory=list)


def passed(summary: str, **kw: Any) -> Outcome:
    return Outcome(Status.PASS, summary, **kw)


def warned(summary: str, **kw: Any) -> Outcome:
    return Outcome(Status.WARN, summary, **kw)


def failed(summary: str, **kw: Any) -> Outcome:
    return Outcome(Status.FAIL, summary, **kw)


def info(summary: str, **kw: Any) -> Outcome:
    return Outcome(Status.INFO, summary, **kw)


def errored(summary: str, **kw: Any) -> Outcome:
    return Outcome(Status.ERROR, summary, **kw)


class SkipCheck(Exception):
    """Raise inside a check when a precondition is not met (e.g. no TLS)."""


class CheckResult(BaseModel):
    id: str
    title: str
    category: str
    status: Status
    severity: Severity
    summary: str
    details: Any = None
    recommendation: str | None = None
    references: list[str] = Field(default_factory=list)
    duration_ms: int = 0
    # The owner accepted this finding for the target; it no longer affects the grade.
    accepted: bool = False
