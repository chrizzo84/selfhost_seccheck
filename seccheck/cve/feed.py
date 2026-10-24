"""CVE feed: sync the sources, match subjects, alert on changes, answer feed queries.

A subject is something with a product and a version: a scanned instance
("target:3", version from its last scan) or a watchlist entry ("watch:1",
version entered by hand). Only products that some subject uses are synced.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from .. import config, notify
from ..i18n import language
from ..store import Store
from . import sources
from .catalog import PRODUCTS, Product, Source, get_product, product_for
from .matching import assess, severity_rank

log = logging.getLogger(__name__)

POLL_SECONDS = 60
# CISA updates the KEV catalog and FIRST the EPSS scores once a day.
DAILY = timedelta(hours=20)
LAST_FULL_SYNC = "cve_last_full_sync"


@dataclass(frozen=True)
class Subject:
    key: str
    kind: str  # "target" | "watch"
    ref: int
    name: str
    product: Product
    version: str | None
    url: str | None = None

    def public(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "kind": self.kind,
            "id": self.ref,
            "name": self.name,
            "url": self.url,
            "product": self.product.id,
            "product_name": self.product.name,
            "version": self.version,
            "possible": self.product.backports,
        }


def subjects(store: Store) -> list[Subject]:
    out = []
    for t in store.cve_targets():
        product = get_product(t["product"]) or product_for(t["app"])
        if product is None:
            continue
        out.append(
            Subject(
                key=f"target:{t['id']}",
                kind="target",
                ref=t["id"],
                name=t["label"] or t["url"],
                product=product,
                version=t["version"],
                url=t["url"],
            )
        )
    for w in store.list_watch():
        product = get_product(w["product"])
        if product is None:
            continue
        out.append(
            Subject(
                key=f"watch:{w['id']}",
                kind="watch",
                ref=w["id"],
                name=w["label"] or product.name,
                product=product,
                version=w["version"],
            )
        )
    return out


def monitored(subject_list: list[Subject]) -> list[Product]:
    ids = {s.product.id for s in subject_list}
    return [p for p in PRODUCTS if p.id in ids]


# --- sync -------------------------------------------------------------------------


@dataclass
class SyncState:
    running: bool = False
    started_at: str | None = None
    current: str | None = None


state = SyncState()
_lock = asyncio.Lock()
_wake = asyncio.Event()


def request_sync() -> None:
    """Ask the background loop to sync new products and re-evaluate soon."""
    _wake.set()


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _older_than(value: str | None, age: timedelta) -> bool:
    if not value:
        return True
    return datetime.now(UTC) - datetime.fromisoformat(value.replace("Z", "+00:00")) >= age


async def _fetch(client: httpx.AsyncClient, source: Source, since: str | None) -> list[dict[str, Any]]:
    if source.kind == "ghsa":
        return await sources.fetch_ghsa(client, source.ref, source.packages, since)
    if source.kind == "osv":
        return await sources.fetch_osv(client, source.ref)
    return await sources.fetch_nvd(client, source.ref, since)


def _error(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code} ({exc.request.url.host})"
    text = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    if isinstance(exc, httpx.RequestError):
        with contextlib.suppress(RuntimeError):
            text += f" ({exc.request.url.host})"
    return text[:300]


async def sync(store: Store, *, full: bool = True, notify_changes: bool = True) -> dict[str, Any]:
    """Fetch new data for all monitored products, then evaluate subjects and alert.

    ``full=False`` only syncs sources that were never synced successfully (a
    product that just appeared) and re-evaluates; the periodic run is full.
    """
    async with _lock:
        state.running, state.started_at = True, _now()
        try:
            return await _sync(store, full=full, notify_changes=notify_changes)
        finally:
            state.running, state.current = False, None


async def _sync(store: Store, *, full: bool, notify_changes: bool) -> dict[str, Any]:
    subject_list = await asyncio.to_thread(subjects, store)
    products = monitored(subject_list)
    known = await asyncio.to_thread(store.cve_sync_state)
    silent: set[str] = set()
    fetched = errors = new = 0
    async with sources.make_client() as client:
        for product in products:
            for source in product.sources:
                key = f"{product.id}|{source.key}"
                since = (known.get(key) or {}).get("synced_at")
                if since and not full:
                    continue
                state.current = product.name
                started = _now()
                try:
                    entries = await _fetch(client, source, since)
                except (httpx.HTTPError, ValueError, KeyError) as exc:
                    log.warning("CVE sync of %s from %s failed: %s", product.id, source.key, exc)
                    await asyncio.to_thread(store.set_cve_sync, key, synced_at=since, error=_error(exc))
                    errors += 1
                    continue
                new += await asyncio.to_thread(
                    store.cve_upsert, product.id, source.key, entries, replace=source.kind == "osv"
                )
                await asyncio.to_thread(store.set_cve_sync, key, synced_at=started, error=None)
                fetched += 1
                if since is None:
                    # Everything a first sync finds is old news, not an alert.
                    silent.add(product.id)

        if products:
            state.current = "CISA KEV / EPSS"
            errors += await _sync_exploitation(store, client, known, force=fetched > 0)
    if full:
        await asyncio.to_thread(store.set_setting, LAST_FULL_SYNC, _now())
    alerts = await evaluate(store, silent=silent, notify_changes=notify_changes)
    return {"sources": fetched, "errors": errors, "new": new, "alerts": alerts}


async def _sync_exploitation(
    store: Store, client: httpx.AsyncClient, known: dict[str, dict[str, Any]], *, force: bool
) -> int:
    errors = 0
    if _older_than((known.get("kev") or {}).get("synced_at"), DAILY):
        started = _now()
        try:
            catalog = await sources.fetch_kev(client)
            await asyncio.to_thread(store.set_cve_kev, catalog)
            await asyncio.to_thread(store.set_cve_sync, "kev", synced_at=started, error=None)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            await asyncio.to_thread(store.set_cve_sync, "kev", synced_at=None, error=_error(exc))
            errors += 1

    ids = await asyncio.to_thread(store.cve_ids)
    scored = await asyncio.to_thread(store.cve_epss)
    if _older_than((known.get("epss") or {}).get("synced_at"), DAILY):
        wanted = ids
    else:
        wanted = [i for i in ids if i not in scored] if force else []
    if wanted:
        started = _now()
        try:
            scores = await sources.fetch_epss(client, wanted)
            await asyncio.to_thread(store.set_cve_epss, scores)
            if len(wanted) == len(ids):
                await asyncio.to_thread(store.set_cve_sync, "epss", synced_at=started, error=None)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            await asyncio.to_thread(store.set_cve_sync, "epss", synced_at=None, error=_error(exc))
            errors += 1
    return errors


# --- matching & alerts ------------------------------------------------------------


def _affecting(subject: Subject, vulns: list[dict[str, Any]]) -> dict[str, tuple[dict[str, Any], str | None]]:
    """vuln id -> (vuln row, fixed in) for every vulnerability affecting the subject."""
    out = {}
    for vuln in vulns:
        if vuln["product"] != subject.product.id:
            continue
        status, fixed = assess(subject.version, vuln["sources"])
        if status == "affected":
            out[vuln["id"]] = (vuln, fixed)
    return out


def _alert_item(vuln: dict[str, Any], fixed: str | None, kev: dict[str, Any]) -> dict[str, Any]:
    data = vuln["data"]
    return {
        "id": vuln["id"],
        "severity": data["severity"],
        "cvss": data["cvss"],
        "summary": data["summary"],
        "kev": vuln["id"] in kev,
        "fixed": fixed,
    }


def _evaluate(store: Store, silent: set[str]) -> list[tuple[Subject, list[dict[str, Any]], list[dict[str, Any]]]]:
    subject_list = subjects(store)
    vulns = store.cve_vulns([p.id for p in monitored(subject_list)])
    kev = store.cve_kev()
    settings = notify.load_settings(store)["cve"]
    threshold = severity_rank(settings["min_severity"])
    alerts = []
    for subject in subject_list:
        if not subject.version:
            continue
        current = _affecting(subject, vulns)
        before = store.cve_subject(subject.key)
        known = store.cve_matches(subject.key)
        store.set_cve_matches(
            subject.key,
            subject.product.id,
            subject.version,
            {vid: {"severity": v["data"]["severity"], "kev": vid in kev} for vid, (v, _fixed) in current.items()},
        )
        # A new subject, a changed version or a first sync is a baseline: the
        # matches are shown on the page, but are not news.
        if (
            before is None
            or (before["product"], before["version"]) != (subject.product.id, subject.version)
            or subject.product.id in silent
        ):
            continue
        new, exploited = [], []
        for vid, (vuln, fixed) in current.items():
            item = _alert_item(vuln, fixed, kev)
            if vid not in known:
                if item["kev"] or severity_rank(item["severity"]) <= threshold:
                    new.append(item)
            elif item["kev"] and not known[vid]["kev"]:
                exploited.append(item)
        if new or exploited:
            new.sort(key=lambda i: (not i["kev"], severity_rank(i["severity"])))
            alerts.append((subject, new, exploited))
    store.prune_cve_subjects({s.key for s in subject_list})
    return alerts


async def evaluate(store: Store, *, silent: set[str] | None = None, notify_changes: bool = True) -> int:
    """Update the stored matches of all subjects and send alerts. Returns the number of alerts."""
    alerts = await asyncio.to_thread(_evaluate, store, silent or set())
    settings = await asyncio.to_thread(notify.load_settings, store)
    if not notify_changes or not settings["cve"]["enabled"]:
        return 0
    with language(settings["language"]):
        for subject, new, exploited in alerts:
            title, body, priority = notify.compose_cve(subject.public(), new, exploited, settings["public_url"])
            try:
                await notify.send(settings, title, body, priority)
            except Exception:
                log.exception("CVE alert for %s failed", subject.key)
    return len(alerts)


# --- background loop --------------------------------------------------------------


def backfill_versions(store: Store) -> int:
    """Versions for targets scanned before the CVE feed existed, from their last stored scan."""
    count = 0
    for target in store.cve_targets():
        if target["version"]:
            continue
        scan = store.latest_scan(target["id"])
        detect = next((r for r in (scan or {}).get("results", []) if r["id"] == f"{target['app']}.detect"), None)
        details = detect.get("details") if detect and detect["status"] == "info" else None
        # The detail keys are translated; "Version" is the same in every shipped language.
        version = details.get("Version") if isinstance(details, dict) else None
        if not version or version == "?":
            continue
        name = details.get("Product") or details.get("Produkt")
        product = product_for(target["app"], str(name) if name else None)
        store.set_target_software(target["id"], product.id if product else None, str(version))
        count += 1
    return count


def _full_sync_due(store: Store) -> bool:
    if config.CVE_SYNC_HOURS <= 0:
        return False
    return _older_than(store.get_setting(LAST_FULL_SYNC), timedelta(hours=config.CVE_SYNC_HOURS))


async def cve_loop(store: Store, stop: asyncio.Event) -> None:
    """Full sync every CVE_SYNC_HOURS; new products and changed versions within a minute."""
    try:
        await asyncio.to_thread(backfill_versions, store)
    except Exception:
        log.exception("Could not take over versions from stored scans")
    first = True
    while not stop.is_set():
        woken = _wake.is_set()
        _wake.clear()
        try:
            full = await asyncio.to_thread(_full_sync_due, store)
            if full or woken or first:
                await sync(store, full=full)
        except Exception:
            log.exception("CVE sync failed")
        first = False
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(_wait(stop), POLL_SECONDS)


async def _wait(stop: asyncio.Event) -> None:
    stop_task = asyncio.ensure_future(stop.wait())
    wake_task = asyncio.ensure_future(_wake.wait())
    try:
        await asyncio.wait({stop_task, wake_task}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        stop_task.cancel()
        wake_task.cancel()


# --- queries for the API ----------------------------------------------------------


def _status(store: Store) -> dict[str, Any]:
    known = store.cve_sync_state()
    synced = [row["synced_at"] for key, row in known.items() if "|" in key and row["synced_at"]]
    errors = [
        {
            "source": key.split("|", 1)[-1],
            "product": key.split("|", 1)[0] if "|" in key else None,
            "error": row["error"],
        }
        for key, row in sorted(known.items())
        if row["error"]
    ]
    return {
        "running": state.running,
        "current": state.current,
        "last_sync": max(synced) if synced else None,
        "interval_hours": config.CVE_SYNC_HOURS,
        "nvd_api_key": bool(config.NVD_API_KEY),
        "errors": errors,
        "synced_products": sorted(
            {key.split("|", 1)[0] for key, row in known.items() if "|" in key and row["synced_at"]}
        ),
    }


def overview(store: Store) -> dict[str, Any]:
    subject_list = subjects(store)
    products = monitored(subject_list)
    vulns = store.cve_vulns([p.id for p in products])
    kev = store.cve_kev()
    out = []
    for subject in subject_list:
        current = _affecting(subject, vulns)
        counts = {s: 0 for s in ("critical", "high", "medium", "low", "unknown")}
        for vuln, _fixed in current.values():
            counts[vuln["data"]["severity"] if vuln["data"]["severity"] in counts else "unknown"] += 1
        out.append(
            {
                **subject.public(),
                "affected": len(current),
                "counts": counts,
                "kev": sum(1 for vid in current if vid in kev),
            }
        )
    per_product = {p.id: 0 for p in products}
    for vuln in vulns:
        per_product[vuln["product"]] = per_product.get(vuln["product"], 0) + 1
    return {
        "subjects": out,
        "products": [
            {
                "id": p.id,
                "name": p.name,
                "app": p.app,
                "monitored": p.id in per_product,
                "vulns": per_product.get(p.id, 0),
            }
            for p in sorted(PRODUCTS, key=lambda p: p.name.lower())
        ],
        "status": _status(store),
    }


def feed(
    store: Store,
    *,
    product: str | None = None,
    subject: str | None = None,
    min_severity: str | None = None,
    affected_only: bool = False,
    kev_only: bool = False,
    query: str = "",
    offset: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    subject_list = subjects(store)
    if subject:
        subject_list = [s for s in subject_list if s.key == subject]
        affected_only = True
    products = [p.id for p in monitored(subject_list)]
    if product:
        products = [p for p in products if p == product]
    vulns = store.cve_vulns(products)
    kev = store.cve_kev()
    epss = store.cve_epss()
    names = {p.id: p.name for p in PRODUCTS}
    threshold = severity_rank(min_severity) if min_severity else None
    needle = query.strip().lower()

    items = []
    for vuln in vulns:
        data = vuln["data"]
        if threshold is not None and severity_rank(data["severity"]) > threshold:
            continue
        if kev_only and vuln["id"] not in kev:
            continue
        if needle and not any(
            needle in str(v).lower() for v in (vuln["id"], data["summary"], data["description"], *data["aliases"])
        ):
            continue
        affects = []
        for s in subject_list:
            if s.product.id != vuln["product"]:
                continue
            status, fixed = assess(s.version, vuln["sources"])
            if status == "affected":
                affects.append(
                    {
                        "key": s.key,
                        "name": s.name,
                        "version": s.version,
                        "fixed": fixed,
                        "possible": s.product.backports,
                    }
                )
        if affected_only and not affects:
            continue
        items.append(
            {
                **data,
                "product": vuln["product"],
                "product_name": names.get(vuln["product"], vuln["product"]),
                "first_seen": vuln["first_seen"],
                "sources": sorted({key.split(":", 1)[0] for key in vuln["sources"]}),
                "kev": kev.get(vuln["id"]),
                "epss": epss.get(vuln["id"]),
                "affects": affects,
            }
        )
    items.sort(key=lambda i: i["published"] or i["first_seen"], reverse=True)
    return {"total": len(items), "offset": offset, "items": items[offset : offset + limit]}
