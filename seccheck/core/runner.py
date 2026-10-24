"""Runs all checks of an app profile concurrently and streams the results."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from .. import config
from ..i18n import _
from .context import BlockedPath, FetchError, ScanContext, make_client
from .fixes import build_fixes
from .models import CheckResult, Outcome, SkipCheck, Status
from .registry import CATEGORIES, AppProfile, CheckSpec, Detection, checks_for, get_detector
from .scoring import compute_rating
from .target import Target

log = logging.getLogger(__name__)


async def _run_check(
    spec: CheckSpec, ctx: ScanContext, sem: asyncio.Semaphore, accepted: frozenset[str]
) -> CheckResult:
    async with sem:
        started = time.monotonic()
        timeout = spec.timeout or config.CHECK_TIMEOUT
        try:
            outcome = await asyncio.wait_for(spec.func(ctx), timeout)
        except (SkipCheck, BlockedPath) as exc:
            outcome = Outcome(Status.SKIP, str(exc))
        except TimeoutError:
            outcome = Outcome(Status.ERROR, _("Timed out after {seconds} s.", seconds=round(timeout)))
        except FetchError as exc:
            outcome = Outcome(Status.ERROR, _("Request failed: {error}", error=exc))
        except Exception as exc:  # a buggy check must not break the scan
            log.exception("Check %s crashed", spec.id)
            outcome = Outcome(Status.ERROR, _("Internal error: {error}", error=f"{type(exc).__name__}: {exc}"))
        duration = int((time.monotonic() - started) * 1000)

    return CheckResult(
        id=spec.id,
        title=_(spec.title),
        category=spec.category,
        status=outcome.status,
        severity=outcome.severity or spec.severity,
        summary=outcome.summary,
        details=outcome.details,
        recommendation=outcome.recommendation,
        references=outcome.references,
        duration_ms=duration,
        accepted=spec.id in accepted and outcome.status in (Status.FAIL, Status.WARN),
    )


async def _detect(app: AppProfile, ctx: ScanContext) -> Detection | None:
    """Product and version for the CVE feed. The checks have already fetched what
    the detector needs, so this mostly reads from the context's cache."""
    detect = get_detector(app.id)
    if detect is None:
        return None
    try:
        return await asyncio.wait_for(detect(ctx), 15)
    except Exception:  # detectors should not raise; a failure only means "unknown"
        log.debug("Detector for %s failed", app.id, exc_info=True)
        return None


async def run_scan(
    app: AppProfile, target: Target, *, accepted: frozenset[str] = frozenset()
) -> AsyncIterator[dict[str, Any]]:
    """Yields ``start``, one ``result`` per check and a final ``done`` event.

    ``accepted`` holds check ids whose findings the owner accepted as risk.
    """
    specs = checks_for(app)
    started = datetime.now(UTC)
    yield {
        "type": "start",
        "app": {"id": app.id, "name": _(app.name)},
        "target": target.url(),
        "started_at": started.isoformat(),
        "categories": {key: _(label) for key, label in CATEGORIES.items()},
        "checks": [
            {"id": s.id, "title": _(s.title), "category": s.category, "severity": s.severity.value} for s in specs
        ],
    }

    results: list[CheckResult] = []
    async with make_client() as client:
        ctx = ScanContext(target, app, client)
        sem = asyncio.Semaphore(config.CONCURRENCY)
        tasks = [asyncio.create_task(_run_check(spec, ctx, sem, accepted)) for spec in specs]
        try:
            for next_done in asyncio.as_completed(tasks):
                result = await next_done
                results.append(result)
                yield {"type": "result", "result": result.model_dump(mode="json")}
            detection = await _detect(app, ctx)
        finally:
            # Also reached when the client disconnects mid-scan.
            for task in tasks:
                task.cancel()
            ctx.close()

    order = {s.id: i for i, s in enumerate(specs)}
    results.sort(key=lambda r: order[r.id])
    finished = datetime.now(UTC)
    yield {
        "type": "done",
        "finished_at": finished.isoformat(),
        "duration_ms": int((finished - started).total_seconds() * 1000),
        "rating": compute_rating(results).model_dump(mode="json"),
        "fixes": build_fixes(results),
        "detection": {"product": detection.product, "version": detection.version} if detection else None,
    }
