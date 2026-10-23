"""Auto-detection: which app answers at a URL?"""

from __future__ import annotations

import asyncio
import logging

from .context import ScanContext, make_client
from .registry import AppProfile, Detection, all_apps, all_detectors, get_app
from .target import Target

log = logging.getLogger(__name__)


async def _run(app_id: str, ctx: ScanContext) -> tuple[str, Detection] | None:
    detect = all_detectors()[app_id]
    try:
        found = await asyncio.wait_for(detect(ctx), 15)
    except Exception:  # detectors should not raise, but one bug must not stop the others
        log.exception("Detector for %s crashed", app_id)
        return None
    return (app_id, found) if found else None


async def detect_apps(target: Target) -> list[tuple[AppProfile, Detection]]:
    """All apps whose detector recognises the target.

    Apps that ban on unauthenticated requests (they declare no_probe_paths)
    are checked first. If one of them answers, the other detectors are not run
    at all, because their probes could count as failed logins there.
    """
    detectors = all_detectors()
    sensitive = [a.id for a in all_apps() if a.no_probe_paths and a.id in detectors]
    others = [app_id for app_id in detectors if app_id not in sensitive]
    generic = get_app("generic")
    assert generic is not None

    found: list[tuple[str, Detection]] = []
    async with make_client() as client:
        for group in (sensitive, others):
            # Each app gets its own context so its no_probe_paths apply.
            results = await asyncio.gather(
                *(_run(app_id, ScanContext(target, get_app(app_id) or generic, client)) for app_id in group)
            )
            found.extend(r for r in results if r)
            if found:
                break

    order = {a.id: i for i, a in enumerate(all_apps())}
    found.sort(key=lambda item: order.get(item[0], 999))
    return [(get_app(app_id), detection) for app_id, detection in found]  # type: ignore[misc]
