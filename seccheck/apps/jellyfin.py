"""Jellyfin profile and checks."""

from __future__ import annotations

from typing import Any

import httpx

from ..core.advisories import assess_advisories
from ..core.context import ScanContext
from ..core.models import Outcome, Severity, SkipCheck, errored, failed, info, passed, warned
from ..core.registry import AppProfile, Detection, check, detector, register_app
from ..core.versions import assess_latest, github_latest
from ..i18n import _

APP = register_app(
    AppProfile(
        id="jellyfin",
        name="Jellyfin",
        short="JF",
        color="#aa5cc3",
        description="Version, setup wizard, public user list.",
        url_hint="https://jellyfin.example.com",
        cors_paths=("System/Info/Public",),
        order=40,
    )
)
APPS = [APP.id]


async def _info(ctx: ScanContext) -> dict[str, Any]:
    data = await ctx.get_json("System/Info/Public")
    if not isinstance(data, dict) or "Version" not in data:
        raise SkipCheck(_("No Jellyfin found at this URL (/System/Info/Public)."))
    return data


@detector(APP.id)
async def identify(ctx: ScanContext) -> Detection | None:
    try:
        data = await _info(ctx)
    except SkipCheck:
        return None
    return Detection(str(data.get("ProductName") or "Jellyfin"), str(data["Version"]))


@check("jellyfin.detect", title="Jellyfin detected", category="app", severity=Severity.INFO, apps=APPS)
async def detect(ctx: ScanContext) -> Outcome:
    """Reads public server information via /System/Info/Public."""
    try:
        data = await _info(ctx)
    except SkipCheck as exc:
        return warned(str(exc))
    details = {
        _("Product"): data.get("ProductName", "Jellyfin"),
        _("Version"): data["Version"],
        _("Server name"): data.get("ServerName", "?"),
        _("Local address"): data.get("LocalAddress") or "–",
    }
    return info(_("{product} {version} detected.", product="Jellyfin", version=data["Version"]), details=details)


@check("jellyfin.version", title="Version up to date", category="app", severity=Severity.HIGH, apps=APPS)
async def version(ctx: ScanContext) -> Outcome:
    """Compares with the latest release on GitHub."""
    current = str((await _info(ctx))["Version"])
    try:
        latest = await github_latest("jellyfin/jellyfin")
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return errored(
            _(
                "Version {version} detected, latest version could not be retrieved ({error}).",
                version=current,
                error=exc,
            )
        )
    return assess_latest("Jellyfin", current, latest, reference="https://github.com/jellyfin/jellyfin/releases")


@check(
    "jellyfin.advisories",
    title="No known vulnerabilities",
    category="app",
    severity=Severity.HIGH,
    apps=APPS,
)
async def advisories(ctx: ScanContext) -> Outcome:
    """Checks the version against the Jellyfin security advisories on GitHub."""
    # Jellyfin leaves the package fields empty, every entry refers to the server.
    return await assess_advisories(
        "jellyfin/jellyfin", str((await _info(ctx))["Version"]), name="Jellyfin", package=lambda pkg: True
    )


@check(
    "jellyfin.wizard",
    title="Setup completed",
    category="app",
    severity=Severity.CRITICAL,
    apps=APPS,
)
async def wizard(ctx: ScanContext) -> Outcome:
    """As long as the setup wizard is open, anyone can create the admin account."""
    data = await _info(ctx)
    if data.get("StartupWizardCompleted") is False:
        return failed(
            _("The setup wizard has not been completed – anyone can create an admin account."),
            recommendation=_("Complete the setup immediately or take the instance offline."),
        )
    return passed(_("The setup wizard has been completed."))


@check(
    "jellyfin.public_users",
    title="User list not public",
    category="app",
    severity=Severity.LOW,
    apps=APPS,
)
async def public_users(ctx: ScanContext) -> Outcome:
    """Publicly listed user names make brute-force attacks easier."""
    await _info(ctx)
    users = await ctx.get_json("Users/Public")
    if isinstance(users, list) and users:
        names = [u.get("Name", "?") for u in users if isinstance(u, dict)]
        return warned(
            _("{count} users are shown publicly on the login page.", count=len(names)),
            details=names,
            recommendation=_("Enable 'Hide this user from login screens' in the user profile."),
        )
    return passed(_("No users are listed publicly."))
