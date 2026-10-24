"""Fetchers for vulnerability data, normalized to the entry format of matching.py.

All sources are public and free. Rate limits:

    GitHub  60 requests/hour without GITHUB_TOKEN (shared with scans)
    NVD     5 requests per 30 s without NVD_API_KEY, 50 with one
    OSV, CISA KEV, FIRST EPSS: no practical limit for this use
"""

from __future__ import annotations

import asyncio
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from .. import config
from ..core.versions import github_paginated

Entry = dict[str, Any]

OSV_URL = "https://api.osv.dev/v1/query"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

# The NVD accepts at most 120 days between lastModStartDate and lastModEndDate.
NVD_MAX_WINDOW = timedelta(days=119)
NVD_PAGE_SIZE = 2000
EPSS_BATCH = 100
GHSA_MAX_PAGES = 30
DESCRIPTION_LIMIT = 1500

_SEVERITY = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=60, headers={"User-Agent": config.USER_AGENT})


def _iso(value: Any) -> str | None:
    """All sources use UTC; keep "YYYY-MM-DDTHH:MM:SSZ" so strings sort chronologically."""
    match = re.match(r"\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2})?", str(value or ""))
    if not match:
        return None
    text = match.group(0)
    return (text if "T" in text else text + "T00:00:00") + "Z"


def _severity(value: Any) -> str:
    return _SEVERITY.get(str(value or "").strip().lower(), "unknown")


def _score(value: Any) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if score > 0 else None


def _description(text: Any) -> str:
    text = str(text or "").strip()
    return text if len(text) <= DESCRIPTION_LIMIT else text[: DESCRIPTION_LIMIT - 1].rstrip() + "…"


def _span(low: str | None, high: str | None, *, from_incl: bool = True, to_incl: bool = False) -> dict[str, Any]:
    return {"type": "span", "from": low, "from_incl": from_incl, "to": high, "to_incl": to_incl}


# --- GitHub repository security advisories ---------------------------------------


def normalize_ghsa(adv: dict[str, Any], packages: tuple[str, ...] = ()) -> Entry | None:
    vulns = adv.get("vulnerabilities") or []
    if packages:
        vulns = [v for v in vulns if str((v.get("package") or {}).get("name") or "").lower() in packages]
        if not vulns:
            return None  # another product of the same repository
    cve = adv.get("cve_id")
    severities = adv.get("cvss_severities") or {}
    cvss = _score((adv.get("cvss") or {}).get("score"))
    for version in ("cvss_v4", "cvss_v3"):
        cvss = cvss or _score((severities.get(version) or {}).get("score"))
    return {
        "id": cve or adv["ghsa_id"],
        "aliases": [adv["ghsa_id"]] if cve else [],
        "summary": str(adv.get("summary") or "").strip(),
        "description": "",
        "severity": _severity(adv.get("severity")),
        "cvss": cvss,
        "published": _iso(adv.get("published_at")),
        "modified": _iso(adv.get("updated_at")),
        "url": adv.get("html_url") or f"https://github.com/advisories/{adv['ghsa_id']}",
        "ranges": [
            {"type": "ghsa", "vulnerable": v.get("vulnerable_version_range"), "patched": v.get("patched_versions")}
            for v in vulns
        ],
        "withdrawn": bool(adv.get("withdrawn_at")),
    }


async def fetch_ghsa(client: httpx.AsyncClient, repo: str, packages: tuple[str, ...], since: str | None) -> list[Entry]:
    """Advisories updated since ``since`` (all of them on the first sync)."""
    url = (
        f"https://api.github.com/repos/{repo}/security-advisories"
        "?state=published&sort=updated&direction=desc&per_page=100"
    )

    def more(batch: list[dict[str, Any]]) -> bool:
        # Sorted by update time: stop at the first page that reaches known items.
        return since is None or all((_iso(a.get("updated_at")) or "") >= since for a in batch)

    items = await github_paginated(client, url, max_pages=GHSA_MAX_PAGES, more=more)
    entries = []
    for adv in items:
        if since is not None and (_iso(adv.get("updated_at")) or "") < since:
            continue
        entry = normalize_ghsa(adv, packages)
        if entry:
            entries.append(entry)
    return entries


# --- OSV ------------------------------------------------------------------------


def normalize_osv(vuln: dict[str, Any], ecosystem: str, package: str) -> Entry:
    aliases = [str(a) for a in vuln.get("aliases") or []]
    cves = sorted(a for a in aliases if a.startswith("CVE-"))
    vuln_id = vuln["id"] if vuln["id"].startswith("CVE-") else (cves[0] if cves else vuln["id"])
    ranges: list[dict[str, Any]] = []
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or pkg.get("name") != package:
            continue
        for rng in affected.get("ranges") or []:
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue  # GIT ranges are commit hashes
            start: str | None = None
            open_range = False
            for event in rng.get("events") or []:
                if "introduced" in event:
                    start, open_range = str(event["introduced"]), True
                elif "fixed" in event:
                    ranges.append(_span(start, str(event["fixed"])))
                    start, open_range = None, False
                elif "last_affected" in event:
                    ranges.append(_span(start, str(event["last_affected"]), to_incl=True))
                    start, open_range = None, False
            if open_range:
                ranges.append(_span(start, None))
        if affected.get("versions"):
            ranges.append({"type": "exact", "versions": [str(v) for v in affected["versions"]]})
    return {
        "id": vuln_id,
        "aliases": sorted({vuln["id"], *aliases} - {vuln_id}),
        "summary": str(vuln.get("summary") or "").strip(),
        "description": _description(vuln.get("details")),
        "severity": _severity((vuln.get("database_specific") or {}).get("severity")),
        "cvss": None,
        "published": _iso(vuln.get("published")),
        "modified": _iso(vuln.get("modified")),
        "url": f"https://osv.dev/vulnerability/{vuln['id']}",
        "ranges": ranges,
        "withdrawn": bool(vuln.get("withdrawn")),
    }


def _combine(a: Entry, b: Entry) -> Entry:
    """Two OSV records of one vulnerability (e.g. GHSA-… and GO-…): union of the ranges."""
    out = dict(a)
    for key, value in b.items():
        if out.get(key) in (None, "", "unknown", []):
            out[key] = value
    out["ranges"] = a["ranges"] + [r for r in b["ranges"] if r not in a["ranges"]]
    out["aliases"] = sorted(set(a["aliases"]) | set(b["aliases"]))
    out["withdrawn"] = a["withdrawn"] and b["withdrawn"]
    return out


async def fetch_osv(client: httpx.AsyncClient, ref: str) -> list[Entry]:
    """All vulnerabilities of an OSV package (the API has no "changed since")."""
    ecosystem, package = ref.split(":", 1)
    query: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": package}}
    entries: dict[str, Entry] = {}
    for _page in range(50):
        resp = await client.post(OSV_URL, json=query)
        resp.raise_for_status()
        data = resp.json()
        for vuln in data.get("vulns") or []:
            entry = normalize_osv(vuln, ecosystem, package)
            entries[entry["id"]] = _combine(entries[entry["id"]], entry) if entry["id"] in entries else entry
        token = data.get("next_page_token")
        if not token:
            break
        query["page_token"] = token
    return list(entries.values())


# --- NVD ------------------------------------------------------------------------

_nvd_lock = asyncio.Lock()
_nvd_last = 0.0


def _nvd_delay() -> float:
    return 0.7 if config.NVD_API_KEY else 6.5


async def _nvd_get(client: httpx.AsyncClient, params: dict[str, Any]) -> dict[str, Any]:
    global _nvd_last
    headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
    async with _nvd_lock:
        for attempt in range(4):
            wait = _nvd_last + _nvd_delay() - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                resp = await client.get(NVD_URL, params=params, headers=headers)
            except httpx.TimeoutException:
                _nvd_last = time.monotonic()
                if attempt == 3:
                    raise
                continue
            _nvd_last = time.monotonic()
            # The NVD answers 403/429 when throttling and 503 when overloaded.
            if resp.status_code in (403, 429, 502, 503, 504) and attempt < 3:
                await asyncio.sleep(_nvd_delay() * (attempt + 2))
                continue
            resp.raise_for_status()
            return resp.json()
    raise httpx.HTTPError("NVD unavailable")  # pragma: no cover - loop always returns or raises


def _nvd_metric(metrics: dict[str, Any]) -> tuple[str, float | None]:
    for name in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(name) or []
        if not items:
            continue
        item = next((m for m in items if m.get("type") == "Primary"), items[0])
        data = item.get("cvssData") or {}
        return _severity(data.get("baseSeverity") or item.get("baseSeverity")), _score(data.get("baseScore"))
    return "unknown", None


def normalize_nvd(item: dict[str, Any], cpe: str) -> Entry:
    cve = item["cve"]
    prefix = f"cpe:2.3:a:{cpe}:".lower()
    ranges: list[dict[str, Any]] = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = str(match.get("criteria") or "")
                if not match.get("vulnerable") or not criteria.lower().startswith(prefix):
                    continue
                version = criteria.split(":")[5] if criteria.count(":") >= 5 else "*"
                if version == "*":
                    start_excl = match.get("versionStartExcluding")
                    end_incl = match.get("versionEndIncluding")
                    ranges.append(
                        _span(
                            match.get("versionStartIncluding") or start_excl,
                            end_incl or match.get("versionEndExcluding"),
                            from_incl=start_excl is None,
                            to_incl=end_incl is not None,
                        )
                    )
                elif version not in ("-", ""):
                    ranges.append({"type": "exact", "versions": [version.replace("\\", "")]})
    description = next((d["value"] for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    severity, score = _nvd_metric(cve.get("metrics") or {})
    return {
        "id": cve["id"],
        "aliases": [],
        "summary": "",
        "description": _description(description),
        "severity": severity,
        "cvss": score,
        "published": _iso(cve.get("published")),
        "modified": _iso(cve.get("lastModified")),
        "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
        "ranges": ranges,
        "withdrawn": cve.get("vulnStatus") == "Rejected",
    }


def _nvd_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


async def fetch_nvd(client: httpx.AsyncClient, cpe: str, since: str | None) -> list[Entry]:
    """CVEs whose CPE configuration names ``vendor:product``, modified since ``since``."""
    params: dict[str, Any] = {"virtualMatchString": f"cpe:2.3:a:{cpe}", "resultsPerPage": NVD_PAGE_SIZE}
    now = datetime.now(UTC)
    if since:
        start = datetime.fromisoformat(since.replace("Z", "+00:00")) - timedelta(hours=1)
        if now - start < NVD_MAX_WINDOW:
            params["lastModStartDate"] = _nvd_time(start)
            params["lastModEndDate"] = _nvd_time(now)
        # else: too long ago for an incremental query, fetch everything again
    entries = []
    index = 0
    while True:
        data = await _nvd_get(client, {**params, "startIndex": index})
        batch = data.get("vulnerabilities") or []
        entries.extend(normalize_nvd(item, cpe) for item in batch)
        index += len(batch)
        if not batch or index >= int(data.get("totalResults") or 0):
            return entries


# --- CISA KEV and EPSS ------------------------------------------------------------


async def fetch_kev(client: httpx.AsyncClient) -> dict[str, dict[str, Any]]:
    """CISA's catalog of vulnerabilities known to be exploited in the wild."""
    resp = await client.get(KEV_URL)
    resp.raise_for_status()
    out = {}
    for item in resp.json().get("vulnerabilities") or []:
        out[item["cveID"]] = {
            "date_added": item.get("dateAdded"),
            "due_date": item.get("dueDate"),
            "ransomware": str(item.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "name": item.get("vulnerabilityName") or "",
        }
    return out


async def fetch_epss(client: httpx.AsyncClient, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """FIRST EPSS: probability of exploitation in the next 30 days, and its percentile."""
    out: dict[str, tuple[float, float]] = {}
    for i in range(0, len(cve_ids), EPSS_BATCH):
        batch = cve_ids[i : i + EPSS_BATCH]
        resp = await client.get(EPSS_URL, params={"cve": ",".join(batch), "limit": EPSS_BATCH})
        resp.raise_for_status()
        for row in resp.json().get("data") or []:
            out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    return out
