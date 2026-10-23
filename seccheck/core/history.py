"""Comparison of two scans of the same target."""

from __future__ import annotations

from typing import Any

from .scoring import GRADE_ORDER

PROBLEM = {"fail", "warn"}


def _is_problem(result: dict[str, Any]) -> bool:
    return result["status"] in PROBLEM and not result.get("accepted")


def _brief(result: dict[str, Any]) -> dict[str, Any]:
    return {k: result[k] for k in ("id", "title", "status", "severity", "summary")}


def diff_scans(
    previous: dict[str, Any] | None, results: list[dict[str, Any]], rating: dict[str, Any]
) -> dict[str, Any]:
    """New and resolved problems plus the grade change.

    ``previous`` is a stored scan (with results and rating) or None for the
    first scan of a target, in which case every problem counts as new.
    """
    before = {r["id"]: r for r in (previous or {}).get("results", [])}
    now = {r["id"]: r for r in results}
    new = [_brief(r) for r in results if _is_problem(r) and not (r["id"] in before and _is_problem(before[r["id"]]))]
    resolved = [
        _brief(r)
        for r in (previous or {}).get("results", [])
        if _is_problem(r) and not (r["id"] in now and _is_problem(now[r["id"]]))
    ]
    grade_before = previous["rating"]["grade"] if previous else None
    return {
        "first_scan": previous is None,
        "grade_before": grade_before,
        "score_before": previous["rating"]["score"] if previous else None,
        "grade_after": rating["grade"],
        "score_after": rating["score"],
        "grade_worse": grade_before is not None
        and GRADE_ORDER.index(rating["grade"]) > GRADE_ORDER.index(grade_before),
        "new": new,
        "resolved": resolved,
    }
