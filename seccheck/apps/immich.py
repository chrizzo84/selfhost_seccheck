"""Immich profile and checks.

All data comes from the public server endpoints the web app reads before
login (/api/server/version, /api/server/config). Immich has no login lockout,
the scanner never sends credentials anyway.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..core.context import ScanContext
from ..core.models import Outcome, Severity, SkipCheck, errored, failed, info, passed, warned
from ..core.registry import AppProfile, Detection, check, detector, register_app
from ..core.versions import assess_latest, github_latest
from ..i18n import _

APP = register_app(
    AppProfile(
        id="immich",
        name="Immich",
        short="IM",
        color="#4250af",
        description="Version, admin account setup.",
        url_hint="https://photos.example.com",
        cors_paths=("api/server/config",),
        order=60,
    )
)
APPS = [APP.id]


async def _version(ctx: ScanContext) -> str:
    data = await ctx.get_json("api/server/version")
    parts = [data.get(k) for k in ("major", "minor", "patch")] if isinstance(data, dict) else []
    if len(parts) != 3 or not all(isinstance(p, int) for p in parts):
        raise SkipCheck(_("No {product} found at this URL ({path}).", product="Immich", path="/api/server/version"))
    return ".".join(map(str, parts))


async def _config(ctx: ScanContext) -> dict[str, Any]:
    data = await ctx.get_json("api/server/config")
    return data if isinstance(data, dict) else {}


@detector(APP.id)
async def identify(ctx: ScanContext) -> Detection | None:
    try:
        return Detection("Immich", await _version(ctx))
    except SkipCheck:
        return None


@check("immich.detect", title="Immich detected", category="app", severity=Severity.INFO, apps=APPS)
async def detect(ctx: ScanContext) -> Outcome:
    """Reads the version from /api/server/version."""
    try:
        version = await _version(ctx)
    except SkipCheck as exc:
        return warned(str(exc))
    return info(_("{product} {version} detected.", product="Immich", version=version), details={_("Version"): version})


@check("immich.version", title="Version up to date", category="app", severity=Severity.HIGH, apps=APPS)
async def version(ctx: ScanContext) -> Outcome:
    """Compares with the latest release on GitHub."""
    current = await _version(ctx)
    try:
        latest = await github_latest("immich-app/immich")
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return errored(
            _("Version {version} detected, latest version not available ({error}).", version=current, error=exc)
        )
    return assess_latest("Immich", current, latest, reference="https://github.com/immich-app/immich/releases")


@check(
    "immich.admin_setup",
    title="Admin account set up",
    category="app",
    severity=Severity.CRITICAL,
    apps=APPS,
)
async def admin_setup(ctx: ScanContext) -> Outcome:
    """As long as no admin exists, anyone can create the admin account from the start page."""
    await _version(ctx)
    config = await _config(ctx)
    if "isInitialized" not in config:
        return info(_("Setup status not publicly available (/api/server/config)."))
    if config["isInitialized"] is False:
        return failed(
            _("There is no admin account yet; anyone can create it from the start page."),
            recommendation=_("Create the admin account immediately or take the instance offline until then."),
        )
    return passed(_("The admin account is set up."))
