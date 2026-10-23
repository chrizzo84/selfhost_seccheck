"""FastAPI app: JSON API plus the static frontend."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, config, notify
from .core.detect import detect_apps
from .core.history import diff_scans
from .core.registry import CATEGORIES, all_apps, all_checks, checks_for, get_app, load_plugins
from .core.runner import run_scan
from .core.target import Target, TargetError, ensure_allowed, parse_target
from .i18n import LANGUAGES, _, get_language, language
from .scheduler import scheduler_loop
from .service import rerate_latest, scan_and_record
from .store import SCHEDULES, get_store

load_plugins()

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    stop = asyncio.Event()
    task = None
    if config.SCHEDULER_ENABLED:
        task = asyncio.create_task(scheduler_loop(get_store(), stop))
    yield
    stop.set()
    if task:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="SelfHost SecCheck", version=__version__, lifespan=lifespan)


async def _target_or_400(url: str) -> Target:
    try:
        target = parse_target(url)
        await ensure_allowed(target)
    except TargetError as exc:
        raise HTTPException(400, str(exc)) from exc
    return target


def _ndjson(events: AsyncIterator[dict[str, Any]]) -> StreamingResponse:
    async def stream() -> AsyncIterator[str]:
        async for event in events:
            yield json.dumps(event, ensure_ascii=False) + "\n"

    return StreamingResponse(
        stream(),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


# --- catalogue --------------------------------------------------------------


@app.get("/api/apps")
def list_apps() -> list[dict]:
    return [
        {
            "id": a.id,
            "name": _(a.name),
            "short": a.short,
            "color": a.color,
            "description": _(a.description),
            "url_hint": a.url_hint,
            "check_count": len(checks_for(a)),
        }
        for a in all_apps()
    ]


@app.get("/api/apps/{app_id}/checks")
def list_checks(app_id: str) -> list[dict]:
    profile = get_app(app_id)
    if profile is None:
        raise HTTPException(404, _("Unknown application: {app}", app=app_id))
    return [
        {
            "id": s.id,
            "title": _(s.title),
            "category": s.category,
            "severity": s.severity.value,
            "description": _(s.description) if s.description else "",
            "app_specific": s.apps is not None,
        }
        for s in checks_for(profile)
    ]


@app.get("/api/categories")
def list_categories() -> dict[str, str]:
    return {key: _(label) for key, label in CATEGORIES.items()}


@app.get("/api/meta")
def meta() -> dict[str, Any]:
    return {"version": __version__, "language": get_language(), "languages": LANGUAGES}


# --- scanning ---------------------------------------------------------------


class ScanRequest(BaseModel):
    app: str = Field(max_length=64)
    url: str = Field(max_length=2048)
    # Store the scan in the history (and apply the target's accepted risks).
    save: bool = True


@app.post("/api/scan")
async def scan(req: ScanRequest) -> StreamingResponse:
    profile = get_app(req.app)
    if profile is None:
        raise HTTPException(404, _("Unknown application: {app}", app=req.app))
    target = await _target_or_400(req.url)
    if req.save:
        return _ndjson(scan_and_record(get_store(), profile, target))
    return _ndjson(run_scan(profile, target))


class DetectRequest(BaseModel):
    url: str = Field(max_length=2048)


@app.post("/api/detect")
async def detect(req: DetectRequest) -> dict[str, Any]:
    target = await _target_or_400(req.url)
    found = await detect_apps(target)
    return {
        "target": target.url(),
        "apps": [{"id": a.id, "name": _(a.name), "product": d.product, "version": d.version} for a, d in found],
    }


# --- targets & history --------------------------------------------------------


def _target_or_404(target_id: int) -> dict[str, Any]:
    target = get_store().get_target(target_id)
    if target is None:
        raise HTTPException(404, _("Target not found"))
    return target


@app.get("/api/targets")
def list_targets() -> list[dict[str, Any]]:
    names = {a.id: _(a.name) for a in all_apps()}
    targets = get_store().list_targets()
    for t in targets:
        t["app_name"] = names.get(t["app"], t["app"])
    return targets


class TargetUpdate(BaseModel):
    label: str | None = Field(default=None, max_length=200)
    schedule: Literal[tuple(SCHEDULES)] | None = None  # type: ignore[valid-type]
    notify: bool | None = None


@app.patch("/api/targets/{target_id}")
def update_target(target_id: int, update: TargetUpdate) -> dict[str, Any]:
    _target_or_404(target_id)
    return get_store().update_target(target_id, **update.model_dump()) or {}


@app.delete("/api/targets/{target_id}", status_code=204)
def delete_target(target_id: int) -> None:
    _target_or_404(target_id)
    get_store().delete_target(target_id)


@app.get("/api/targets/{target_id}/scans")
def list_scans(target_id: int) -> dict[str, Any]:
    target = _target_or_404(target_id)
    return {"target": target, "scans": get_store().list_scans(target_id)}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int) -> dict[str, Any]:
    store = get_store()
    scan = store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, _("Scan not found"))
    target = store.get_target(scan["target_id"])
    scan["target"] = target
    scan["diff"] = diff_scans(store.previous_scan(scan), scan["results"], scan["rating"])
    profile = get_app(target["app"]) if target else None
    scan["app"] = {"id": profile.id, "name": _(profile.name)} if profile else None
    return scan


@app.put("/api/targets/{target_id}/accepted/{check_id}")
def accept_risk(target_id: int, check_id: str) -> dict[str, Any]:
    target = _target_or_404(target_id)
    if check_id not in {c.id for c in all_checks()}:
        raise HTTPException(404, _("Unknown check: {check}", check=check_id))
    store = get_store()
    store.update_target(target_id, accepted=[*target["accepted"], check_id])
    return rerate_latest(store, target_id) or {}


@app.delete("/api/targets/{target_id}/accepted/{check_id}")
def unaccept_risk(target_id: int, check_id: str) -> dict[str, Any]:
    target = _target_or_404(target_id)
    store = get_store()
    store.update_target(target_id, accepted=[c for c in target["accepted"] if c != check_id])
    return rerate_latest(store, target_id) or {}


# --- settings -------------------------------------------------------------------


@app.get("/api/settings/notifications")
def get_notification_settings() -> dict[str, Any]:
    return notify.masked(notify.load_settings(get_store()))


@app.put("/api/settings/notifications")
def put_notification_settings(settings: dict[str, Any]) -> dict[str, Any]:
    return notify.masked(notify.save_settings(get_store(), settings))


@app.post("/api/settings/notifications/test")
async def test_notifications() -> dict[str, str]:
    settings = await asyncio.to_thread(notify.load_settings, get_store())
    result = await notify.send(
        settings,
        _("SecCheck: test notification"),
        _("If you can read this, notifications are working."),
    )
    if not result:
        raise HTTPException(400, _("No channel is enabled and fully configured."))
    return result


@app.middleware("http")
async def security_headers(request, call_next):  # type: ignore[no-untyped-def]
    # A security scanner should pass its own checks.
    response = await call_next(request)
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    # Revalidate the frontend on every load (cheap thanks to ETags) so updates show up at once.
    response.headers.setdefault("Cache-Control", "no-cache")
    return response


class LanguageMiddleware:
    """Sets the language for the whole request from the Accept-Language header.

    A plain ASGI middleware (not BaseHTTPMiddleware), so the context variable
    is visible to the endpoint, background tasks and streamed responses.
    """

    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        header = dict(scope["headers"]).get(b"accept-language", b"").decode("latin-1")
        with language(header):
            await self.app(scope, receive, send)


# Added last so it wraps everything else.
app.add_middleware(LanguageMiddleware)

app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
