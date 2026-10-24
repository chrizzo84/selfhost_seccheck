"""Version lookups (endoflife.date, GitHub/Gitea releases) and their assessment."""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from datetime import date
from typing import Any

import httpx

from .. import config
from ..i18n import _
from .models import Outcome, Severity, errored, failed, passed, warned

_CACHE_TTL = 6 * 3600
_cache: dict[str, tuple[float, Any]] = {}
_locks: dict[str, asyncio.Lock] = {}


async def _cached(key: str, load: Callable[[], Awaitable[Any]]) -> Any:
    """Result of ``load()``, cached for _CACHE_TTL and fetched once even when requested concurrently."""
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and now - hit[0] < _CACHE_TTL:
        return hit[1]
    async with _locks.setdefault(key, asyncio.Lock()):
        hit = _cache.get(key)
        if hit and now - hit[0] < _CACHE_TTL:
            return hit[1]
        data = await load()
        _cache[key] = (time.monotonic(), data)
        return data


async def _get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    async def load() -> Any:
        async with httpx.AsyncClient(
            timeout=10, headers={"User-Agent": config.USER_AGENT, **(headers or {})}
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()

    return await _cached(url, load)


def github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"
    return headers


async def github_paginated(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_pages: int = 10,
    more: Callable[[list[Any]], bool] | None = None,
) -> list[Any]:
    """All items of a GitHub list endpoint, following the ``Link: rel="next"`` header.

    Some endpoints (e.g. repository security advisories) paginate with cursors
    and ignore ``page=``. ``more(batch)`` can stop early, e.g. once a page
    sorted by update time reaches items that are already known.
    """
    items: list[Any] = []
    next_url: str | None = url
    for _page in range(max_pages):
        if not next_url:
            break
        resp = await client.get(next_url, headers=github_headers())
        resp.raise_for_status()
        batch = resp.json()
        items.extend(batch)
        if more is not None and not more(batch):
            break
        next_url = resp.links.get("next", {}).get("url")
    return items


async def eol_cycles(product: str) -> list[dict[str, Any]]:
    return await _get_json(f"https://endoflife.date/api/{product}.json")


async def github_latest(repo: str) -> str:
    data = await _get_json(f"https://api.github.com/repos/{repo}/releases/latest", github_headers())
    return str(data["tag_name"]).lstrip("v")


async def github_releases(repo: str) -> list[tuple[str, date]]:
    """Published, non-prerelease releases as (version, publish date), newest first."""
    data = await _get_json(f"https://api.github.com/repos/{repo}/releases?per_page=100", github_headers())
    releases = []
    for rel in data:
        if rel.get("draft") or rel.get("prerelease") or not rel.get("published_at"):
            continue
        releases.append((str(rel["tag_name"]).lstrip("v"), date.fromisoformat(rel["published_at"][:10])))
    return releases


async def gitea_latest(base_url: str, repo: str) -> str:
    data = await _get_json(f"{base_url.rstrip('/')}/api/v1/repos/{repo}/releases/latest")
    return str(data["tag_name"]).lstrip("v")


def parse_version(value: str) -> tuple[int, ...]:
    """'31.0.5' -> (31, 0, 5); '9.0.3+gitea-1.22.0' -> (9, 0, 3)."""
    core = re.split(r"[+\s]", value.strip().lstrip("vV"), maxsplit=1)[0]
    core = core.split("-", 1)[0]
    return tuple(int(p) for p in re.findall(r"\d+", core)[:4])


def compare_versions(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """-1, 0 or 1; missing components count as 0, so (1, 2) == (1, 2, 0)."""
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def _is_prefix(prefix: tuple[int, ...], version: tuple[int, ...]) -> bool:
    return version[: len(prefix)] == prefix


def _eol_date(value: Any) -> date | bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None
    return None


async def assess_eol(product: str, version: str, *, name: str, extended_support: bool = False) -> Outcome:
    """Assess a version against endoflife.date release cycles."""
    try:
        cycles = await eol_cycles(product)
    except (httpx.HTTPError, ValueError) as exc:
        return errored(
            _("{name} {version} detected, release data unavailable ({error}).", name=name, version=version, error=exc)
        )

    current = parse_version(version)
    ref = f"https://endoflife.date/{product}"
    cycle = next((c for c in cycles if _is_prefix(parse_version(str(c["cycle"])), current)), None)
    details: dict[str, Any] = {_("Installed version"): version}

    if cycle is None:
        newest = max((parse_version(str(c["cycle"])) for c in cycles), default=())
        if current > newest:
            return passed(
                _("{name} {version} is newer than all known releases.", name=name, version=version), details=details
            )
        return failed(
            _("{name} {version} no longer belongs to a supported release branch.", name=name, version=version),
            details=details,
            recommendation=_("Update to a current {name} version as soon as possible.", name=name),
            severity=Severity.HIGH,
            references=[ref],
        )

    branch = str(cycle["cycle"])
    latest = str(cycle.get("latest") or "")
    eol = _eol_date(cycle.get("eol"))
    details[_("Release branch")] = branch
    if latest:
        details[_("Latest version in branch")] = latest
    if isinstance(eol, date):
        details[_("End of support")] = eol.isoformat()

    today = date.today()
    if eol is True or (isinstance(eol, date) and eol <= today):
        if extended_support:
            return warned(
                _(
                    "{name} {branch} is end-of-life, but the instance reports Enterprise Extended Support.",
                    name=name,
                    branch=branch,
                ),
                details=details,
                severity=Severity.MEDIUM,
                references=[ref],
            )
        if isinstance(eol, date):
            summary = _(
                "{name} {branch} has not received security updates since {date}.",
                name=name,
                branch=branch,
                date=eol.isoformat(),
            )
        else:
            summary = _("{name} {branch} no longer receives security updates.", name=name, branch=branch)
        return failed(
            summary,
            details=details,
            recommendation=_("Update to a supported {name} release branch.", name=name),
            severity=Severity.HIGH,
            references=[ref],
        )

    if latest and current < parse_version(latest):
        return failed(
            _(
                "Update available: {version} → {latest}. Patch releases often contain security fixes.",
                version=version,
                latest=latest,
            ),
            details=details,
            recommendation=_("Update {name} to {latest}.", name=name, latest=latest),
            severity=Severity.MEDIUM,
            references=[ref],
        )

    if isinstance(eol, date) and (eol - today).days <= 60:
        return warned(
            _(
                "{name} {version} is up to date, but support for {branch} ends on {date}.",
                name=name,
                version=version,
                branch=branch,
                date=eol.isoformat(),
            ),
            details=details,
            recommendation=_("Plan the upgrade to the next release branch."),
            severity=Severity.LOW,
            references=[ref],
        )

    return passed(_("{name} {version} is up to date and supported.", name=name, version=version), details=details)


BRANCH_MAINTAINED_DAYS = 183


def assess_branches(
    name: str,
    version: str,
    releases: list[tuple[str, date]],
    *,
    reference: str | None = None,
    today: date | None = None,
) -> Outcome:
    """Assess a version for projects that maintain several release branches (e.g. LTS + STS).

    A branch is major.minor. Being behind within the own branch is a finding;
    being on an older branch is fine as long as that branch still gets releases.
    """
    current = parse_version(version)
    refs = [reference] if reference else []
    parsed = [(parse_version(v), v, d) for v, d in releases if parse_version(v)]
    if not current or not parsed:
        return errored(_("Version {version!r} or the release list cannot be evaluated.", version=version))
    newest = max(parsed)
    branch = [p for p in parsed if p[0][:2] == current[:2]]
    details: dict[str, Any] = {_("Installed version"): version, _("Latest version"): newest[1]}

    if branch:
        branch_latest = max(branch)
        details[_("Latest in branch {branch}", branch=".".join(map(str, current[:2])))] = branch_latest[1]
        if current < branch_latest[0]:
            return failed(
                _(
                    "Update available in your release branch: {version} → {latest}.",
                    version=version,
                    latest=branch_latest[1],
                ),
                details=details,
                recommendation=_("Update {name} to {latest}.", name=name, latest=branch_latest[1]),
                severity=Severity.MEDIUM,
                references=refs,
            )
    if current >= newest[0]:
        return passed(_("{name} {version} is the current version.", name=name, version=version), details=details)

    last_release = max((released for _v, _s, released in branch), default=None)
    age = ((today or date.today()) - last_release).days if last_release else None
    if age is not None and age <= BRANCH_MAINTAINED_DAYS:
        details[_("Last release in branch")] = last_release.isoformat()
        return passed(
            _(
                "{name} {version} is current in its release branch, which is still maintained "
                "(newest version overall: {latest}).",
                name=name,
                version=version,
                latest=newest[1],
            ),
            details=details,
        )
    return failed(
        _(
            "{name} {version} belongs to a release branch without recent updates; the newest version is {latest}.",
            name=name,
            version=version,
            latest=newest[1],
        ),
        details=details,
        recommendation=_("Update to a maintained branch, e.g. {latest}.", latest=newest[1]),
        severity=Severity.HIGH,
        references=refs,
    )


def assess_latest(name: str, version: str, latest: str, *, reference: str | None = None) -> Outcome:
    """Assess a version against the newest upstream release."""
    current, newest = parse_version(version), parse_version(latest)
    details = {_("Installed version"): version, _("Latest version"): latest}
    refs = [reference] if reference else []
    if not current:
        return errored(_("Could not read version {version!r}.", version=version), details=details)
    if current >= newest:
        return passed(_("{name} {version} is the current version.", name=name, version=version), details=details)
    if current[:2] != newest[:2]:
        return failed(
            _(
                "{name} {version} is outdated, the current version is {latest}. Older release branches "
                "usually no longer receive security updates.",
                name=name,
                version=version,
                latest=latest,
            ),
            details=details,
            recommendation=_("Update {name} to {latest}.", name=name, latest=latest),
            severity=Severity.HIGH,
            references=refs,
        )
    return failed(
        _("Update available: {version} → {latest}.", version=version, latest=latest),
        details=details,
        recommendation=_("Update {name} to {latest}.", name=name, latest=latest),
        severity=Severity.MEDIUM,
        references=refs,
    )
