"""Is a version affected? Pure version logic on normalized vulnerability entries.

An entry is what one source says about one vulnerability (see sources.py):

    {"id", "aliases", "summary", "description", "severity", "cvss",
     "published", "modified", "url", "ranges"}

``ranges`` is a list of

    {"type": "span", "from": "1.2", "from_incl": true, "to": "1.4", "to_incl": false}
    {"type": "exact", "versions": ["1.3.0", "1.3.1"]}
    {"type": "ghsa", "vulnerable": ">= 32.0.0, >= 33.0.0", "patched": "32.0.12, 33.0.6"}

A missing bound in a span means "unbounded". The free-text GitHub repository
advisory ranges are evaluated by core.advisories.is_affected.
"""

from __future__ import annotations

from typing import Any, Literal

from ..core.advisories import is_affected
from ..core.versions import compare_versions, parse_version
from .catalog import SOURCE_PRIORITY

Status = Literal["affected", "not_affected", "unknown"]
SEVERITIES = ("critical", "high", "medium", "low", "unknown")


def _in_span(version: tuple[int, ...], span: dict[str, Any]) -> bool | None:
    low, high = span.get("from"), span.get("to")
    if low and low != "0":
        bound = parse_version(low)
        if not bound:
            return None
        c = compare_versions(version, bound)
        if c < 0 or (c == 0 and not span.get("from_incl", True)):
            return False
    if high:
        bound = parse_version(high)
        if not bound:
            return None
        c = compare_versions(version, bound)
        if c > 0 or (c == 0 and not span.get("to_incl", False)):
            return False
    return True


def evaluate(version: tuple[int, ...], ranges: list[dict[str, Any]]) -> tuple[bool | None, str | None]:
    """(affected, fixed in) for one entry. affected is None when no range can be evaluated."""
    decided = False
    for item in ranges:
        kind = item.get("type")
        if kind == "ghsa":
            result = is_affected(version, item.get("vulnerable"), item.get("patched"))
            fixed = item.get("patched") or None
        elif kind == "span":
            result = _in_span(version, item)
            fixed = None if item.get("to_incl") else item.get("to")
        elif kind == "exact":
            parsed = [parse_version(v) for v in item.get("versions") or []]
            parsed = [p for p in parsed if p]
            result = any(compare_versions(version, p) == 0 for p in parsed) if parsed else None
            fixed = None
        else:
            continue
        if result is None:
            continue
        decided = True
        if result:
            return True, fixed
    return (False if decided else None), None


def assess(version: str | None, sources: dict[str, dict[str, Any]]) -> tuple[Status, str | None]:
    """Whether ``version`` is affected, using the most trusted source that has usable ranges.

    ``sources`` maps a source key ("osv:Go:…", "ghsa:owner/repo", "nvd:vendor:product")
    to that source's entry.
    """
    parsed = parse_version(version or "")
    if not parsed:
        return "unknown", None
    for kind in SOURCE_PRIORITY:
        decided = False
        for key, entry in sources.items():
            if not key.startswith(kind + ":"):
                continue
            affected, fixed = evaluate(parsed, entry.get("ranges") or [])
            if affected:
                return "affected", fixed
            decided = decided or affected is False
        if decided:
            return "not_affected", None
    return "unknown", None


def _first(sources: dict[str, dict[str, Any]], field: str, order: tuple[str, ...]) -> Any:
    for kind in order:
        for key, entry in sources.items():
            if key.startswith(kind + ":") and entry.get(field) not in (None, "", "unknown"):
                return entry[field]
    return None


def merge(vuln_id: str, sources: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """One record for the feed from the entries of all sources.

    Texts and severity prefer the project's own advisory (ghsa), then OSV, then
    NVD; the CVSS score prefers the NVD's.
    """
    text_order = ("ghsa", "osv", "nvd")
    ids = {vuln_id}
    for entry in sources.values():
        ids.add(entry["id"])
        ids.update(entry.get("aliases") or [])
    ids.discard(vuln_id)
    published = [e["published"] for e in sources.values() if e.get("published")]
    modified = [e["modified"] for e in sources.values() if e.get("modified")]
    description = _first(sources, "description", ("nvd", "osv", "ghsa")) or ""
    summary = _first(sources, "summary", text_order) or _first_sentence(description)
    urls = []
    for kind in text_order:
        urls.extend(e["url"] for k, e in sources.items() if k.startswith(kind + ":") and e.get("url"))
    return {
        "id": vuln_id,
        "aliases": sorted(i for i in ids if i.startswith(("CVE-", "GHSA-"))),
        "summary": summary,
        "description": description,
        "severity": _first(sources, "severity", text_order) or "unknown",
        "cvss": _first(sources, "cvss", ("nvd", "ghsa", "osv")),
        "published": min(published) if published else None,
        "modified": max(modified) if modified else None,
        "urls": list(dict.fromkeys(urls)),
    }


def _first_sentence(text: str, limit: int = 200) -> str:
    text = " ".join(text.split())
    end = text.find(". ")
    sentence = text[: end + 1] if 0 < end < limit else text
    return sentence if len(sentence) <= limit else sentence[: limit - 1].rstrip() + "…"


def severity_rank(severity: str) -> int:
    """0 = critical … 4 = unknown."""
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES) - 1
