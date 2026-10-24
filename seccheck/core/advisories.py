"""Known vulnerabilities for a detected version, from GitHub security advisories.

Projects fill in the advisory fields very differently, e.g.

    Nextcloud:   vulnerable ">= 32.0.0, >= 33.0.0"   patched "32.0.12, 33.0.6"   (one entry per branch)
    Vaultwarden: vulnerable "≤ 1.36.0"               patched "1.37.0"
    Immich:      vulnerable "v3.2.2"                 patched "v3.2.4"

so matching relies mostly on the patched versions of the release branch the
installed version belongs to, and uses the vulnerable range as a filter.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from .. import config
from ..i18n import N_, _
from .models import Outcome, Severity, errored, failed, passed, worst_severity
from .versions import _cached, compare_versions, github_paginated, parse_version

Version = tuple[int, ...]
PackageFilter = Callable[[dict[str, Any]], bool]

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
}
_SEVERITY_LABEL = {
    "critical": N_("critical"),
    "high": N_("high"),
    "medium": N_("medium"),
    "moderate": N_("medium"),
    "low": N_("low"),
}
_CONSTRAINT = re.compile(r"(>=|<=|≥|≤|>|<|==|=)?\s*v?(\d+(?:\.\d+)*)")
MAX_PAGES = 10


def _constraints(text: str) -> list[tuple[str, Version]]:
    out = []
    for part in text.split(","):
        m = _CONSTRAINT.search(part.strip())
        if m:
            op = {"≥": ">=", "≤": "<=", "==": "=", None: "="}.get(m.group(1), m.group(1))
            out.append((op, parse_version(m.group(2))))
    return out


def in_range(version: Version, text: str | None) -> bool | None:
    """None if the range cannot be parsed."""
    constraints = _constraints(text or "")
    if not constraints:
        return None

    def ok(op: str, bound: Version) -> bool:
        c = compare_versions(version, bound)
        return {">=": c >= 0, ">": c > 0, "<=": c <= 0, "<": c < 0, "=": c == 0}[op]

    # A list of lower bounds only (">= 32.0.0, >= 33.0.0") enumerates affected
    # branches, so it means "any of", not "all of".
    if all(op in (">=", ">") for op, _bound in constraints):
        return any(ok(op, b) for op, b in constraints)
    return all(ok(op, b) for op, b in constraints)


def _patched(text: str | None) -> list[Version]:
    return [v for v in (parse_version(p) for p in re.split(r"[,\s]+", text or "") if p) if v]


def is_affected(version: Version, vulnerable: str | None, patched: str | None) -> bool | None:
    """Whether ``version`` is affected by one advisory entry. None = undecidable."""
    matches_range = in_range(version, vulnerable)
    if matches_range is False:
        return False
    fixes = _patched(patched)
    if not fixes:
        return matches_range
    # Use the fix of the installed release branch: same major.minor if there is
    # one, else same major.
    for width in (2, 1):
        branch = [f for f in fixes if f[:width] == version[:width]]
        if branch:
            return compare_versions(version, min(branch)) < 0
    # No fix in this branch: affected if the branch is older than every fixed
    # branch and the range says so (e.g. "< 12.0" fixed in 12.0).
    if compare_versions(version, min(fixes)) < 0:
        return bool(matches_range)
    return False


@dataclass(frozen=True)
class Advisory:
    ghsa_id: str
    cve_id: str | None
    severity: str
    summary: str
    url: str
    patched: str


async def fetch_advisories(repo: str) -> list[dict[str, Any]]:
    async def load() -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=15, headers={"User-Agent": config.USER_AGENT}) as client:
            url = f"https://api.github.com/repos/{repo}/security-advisories?state=published&per_page=100"
            return await github_paginated(client, url, max_pages=MAX_PAGES)

    return await _cached(f"advisories:{repo}", load)


def matching(advisories: list[dict[str, Any]], version: str, package: PackageFilter) -> list[Advisory]:
    current = parse_version(version)
    found = []
    for adv in advisories:
        if adv.get("withdrawn_at"):
            continue
        for vuln in adv.get("vulnerabilities") or []:
            if not package(vuln.get("package") or {}):
                continue
            if is_affected(current, vuln.get("vulnerable_version_range"), vuln.get("patched_versions")):
                found.append(
                    Advisory(
                        ghsa_id=adv["ghsa_id"],
                        cve_id=adv.get("cve_id"),
                        severity=str(adv.get("severity") or "medium").lower(),
                        summary=str(adv.get("summary") or "").strip(),
                        url=adv.get("html_url") or f"https://github.com/advisories/{adv['ghsa_id']}",
                        patched=str(vuln.get("patched_versions") or "").strip(),
                    )
                )
                break
    return found


async def assess_advisories(repo: str, version: str, *, name: str, package: PackageFilter) -> Outcome:
    try:
        advisories = await fetch_advisories(repo)
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        return errored(_("Security advisories for {name} unavailable ({error}).", name=name, error=exc))

    found = matching(advisories, version, package)
    if not found:
        return passed(
            _(
                "No known vulnerabilities for {name} {version} ({count} advisories checked).",
                name=name,
                version=version,
                count=len(advisories),
            )
        )

    rank = list(_SEVERITY)
    found.sort(key=lambda a: rank.index(a.severity) if a.severity in rank else len(rank))
    severity = worst_severity([_SEVERITY.get(a.severity, Severity.MEDIUM) for a in found])
    details = []
    for a in found:
        label = _(_SEVERITY_LABEL[a.severity]) if a.severity in _SEVERITY_LABEL else a.severity
        line = f"{a.cve_id or a.ghsa_id} [{label}] {a.summary}"
        if a.patched:
            line += " – " + _("fixed in {versions}", versions=a.patched)
        details.append(line)
    return failed(
        _(
            "{name} {version} is affected by {count} known vulnerabilities.",
            name=name,
            version=version,
            count=len(found),
        ),
        details=details,
        severity=severity,
        recommendation=_("Update {name} to a version that fixes all of them.", name=name),
        references=[a.url for a in found[:5]],
    )
