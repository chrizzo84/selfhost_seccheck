"""Scans with persistence: load accepted risks, store the result, compare, notify."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Any

from .core.fixes import build_fixes
from .core.history import diff_scans
from .core.models import CheckResult
from .core.registry import AppProfile
from .core.runner import run_scan
from .core.scoring import compute_rating
from .core.target import Target
from .notify import notify_scan
from .store import Store

log = logging.getLogger(__name__)


async def scan_and_record(
    store: Store, app: AppProfile, target: Target, *, trigger: str = "manual"
) -> AsyncIterator[dict[str, Any]]:
    """Like run_scan, but persists the scan and adds target/scan ids and a diff to the events."""
    row = await asyncio.to_thread(store.get_or_create_target, app.id, target.url())
    accepted = frozenset(row["accepted"])
    started_at = ""
    order: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    async for event in run_scan(app, target, accepted=accepted):
        if event["type"] == "start":
            started_at = event["started_at"]
            order = {c["id"]: i for i, c in enumerate(event["checks"])}
            event["target_id"] = row["id"]
            event["accepted"] = sorted(accepted)
        elif event["type"] == "result":
            results.append(event["result"])
        elif event["type"] == "done":
            # Stored in display order, not completion order.
            results.sort(key=lambda r: order.get(r["id"], len(order)))
            previous = await asyncio.to_thread(store.latest_scan, row["id"])
            scan_id = await asyncio.to_thread(
                store.add_scan,
                row["id"],
                trigger=trigger,
                started_at=started_at,
                finished_at=event["finished_at"],
                rating=event["rating"],
                results=results,
                fixes=event["fixes"],
            )
            event["scan_id"] = scan_id
            event["target_id"] = row["id"]
            event["diff"] = diff_scans(previous, results, event["rating"])
            if trigger == "schedule" and row["notify"]:
                scan = await asyncio.to_thread(store.get_scan, scan_id)
                if scan:
                    try:
                        await notify_scan(store, row, scan)
                    except Exception:
                        log.exception("Notification for target %s failed", row["id"])
        yield event


def rerate_latest(store: Store, target_id: int) -> dict[str, Any] | None:
    """Apply the target's current accepted risks to its latest stored scan."""
    target = store.get_target(target_id)
    scan = store.latest_scan(target_id) if target else None
    if not target or not scan:
        return None
    accepted = set(target["accepted"])
    results = []
    for raw in scan["results"]:
        result = CheckResult(**raw)
        result.accepted = result.id in accepted and result.status.value in ("fail", "warn")
        results.append(result)
    rating = compute_rating(results).model_dump(mode="json")
    dumped = [r.model_dump(mode="json") for r in results]
    fixes = build_fixes(results)
    store.update_scan(scan["id"], rating=rating, results=dumped, fixes=fixes)
    return {"scan_id": scan["id"], "rating": rating, "results": dumped, "fixes": fixes}
