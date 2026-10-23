"""Turns check results into a score (0-100) and a grade (A+ ... F).

Every failed check deducts points depending on its severity, a warning
deducts half. Like SSL Labs, single serious findings cap the grade no matter
how good the rest looks: an expired certificate is an F even if all headers
are perfect.
"""

from __future__ import annotations

from collections import Counter

from pydantic import BaseModel

from ..i18n import _
from .models import CheckResult, Severity, Status
from .registry import CATEGORIES

DEDUCTION: dict[Severity, float] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}
WARN_FACTOR = 0.5

GRADES: list[tuple[int, str]] = [(97, "A+"), (90, "A"), (80, "B"), (65, "C"), (50, "D"), (0, "F")]
GRADE_ORDER = [grade for _threshold, grade in GRADES]

# Worst grade a single failed check of this severity allows.
CAPS: dict[Severity, str] = {Severity.CRITICAL: "F", Severity.HIGH: "C"}


class CategoryScore(BaseModel):
    label: str
    score: int
    counts: dict[str, int]


class Rating(BaseModel):
    score: int
    grade: str
    caps: list[str]
    counts: dict[str, int]
    categories: dict[str, CategoryScore]


def deduction(result: CheckResult) -> float:
    if result.accepted:
        return 0.0
    if result.status == Status.FAIL:
        return DEDUCTION[result.severity]
    if result.status == Status.WARN:
        return DEDUCTION[result.severity] * WARN_FACTOR
    return 0.0


def grade_for(score: float) -> str:
    for threshold, grade in GRADES:
        if score >= threshold:
            return grade
    return "F"


def worse(a: str, b: str) -> str:
    return a if GRADE_ORDER.index(a) >= GRADE_ORDER.index(b) else b


def compute_rating(results: list[CheckResult]) -> Rating:
    score = max(0.0, 100.0 - sum(deduction(r) for r in results))
    grade = grade_for(score)

    caps = []
    for r in results:
        cap = CAPS.get(r.severity) if r.status == Status.FAIL and not r.accepted else None
        if cap:
            caps.append(_("{check}: grade capped at {grade}", check=r.title, grade=cap))
            grade = worse(grade, cap)

    categories = {}
    for key, label in CATEGORIES.items():
        in_cat = [r for r in results if r.category == key]
        if not in_cat:
            continue
        cat_score = max(0.0, 100.0 - sum(deduction(r) for r in in_cat))
        categories[key] = CategoryScore(
            label=_(label),
            score=round(cat_score),
            counts=dict(Counter("accepted" if r.accepted else r.status.value for r in in_cat)),
        )

    # Accepted findings are counted separately, not as failures/warnings.
    counts = dict(Counter("accepted" if r.accepted else r.status.value for r in results))
    return Rating(score=round(score), grade=grade, caps=caps, counts=counts, categories=categories)
