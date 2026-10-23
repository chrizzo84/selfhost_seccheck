"""Background loop that runs scheduled scans inside the web server process."""

from __future__ import annotations

import asyncio
import contextlib
import logging

from .core.registry import get_app
from .core.target import TargetError, ensure_allowed, parse_target
from .i18n import language
from .notify import load_settings
from .service import scan_and_record
from .store import Store

log = logging.getLogger(__name__)

POLL_SECONDS = 60


async def run_due_scans(store: Store) -> int:
    """Scan every target whose schedule is due, one after another. Returns the count."""
    count = 0
    settings = await asyncio.to_thread(load_settings, store)
    for target in await asyncio.to_thread(store.due_targets):
        app = get_app(target["app"])
        if app is None:
            log.warning("Skipping target %s: unknown app %s", target["id"], target["app"])
            continue
        try:
            parsed = parse_target(target["url"])
            await ensure_allowed(parsed)
        except TargetError as exc:
            log.warning("Skipping target %s: %s", target["id"], exc)
            continue
        log.info("Scheduled scan of %s (%s)", target["url"], app.id)
        # Results and notifications use the language from the notification settings.
        with language(settings["language"]):
            async for _event in scan_and_record(store, app, parsed, trigger="schedule"):
                pass
        count += 1
    return count


async def scheduler_loop(store: Store, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await run_due_scans(store)
        except Exception:
            log.exception("Scheduled scan run failed")
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), POLL_SECONDS)
