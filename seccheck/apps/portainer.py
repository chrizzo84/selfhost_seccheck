"""Portainer CE profile and checks.

Portainer disables the API five minutes after start when no administrator was
created (HTTP 303, Redirect-Reason: AdminInitTimeout). Only /api/status and
/api/settings/public stay reachable then, so detection uses /api/status.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..core.context import ScanContext
from ..core.models import Outcome, Severity, SkipCheck, errored, failed, info, passed, warned
from ..core.registry import AppProfile, Detection, check, detector, register_app
from ..core.versions import assess_branches, github_releases
from ..i18n import _

APP = register_app(
    AppProfile(
        id="portainer",
        name="Portainer CE",
        short="PT",
        color="#13bef9",
        description="Version, admin account setup.",
        url_hint="https://portainer.example.com",
        cors_paths=("api/settings/public",),
        order=80,
    )
)
APPS = [APP.id]


async def _status(ctx: ScanContext) -> dict[str, Any]:
    data = await ctx.get_json("api/status")
    if not isinstance(data, dict) or "Version" not in data or "InstanceID" not in data:
        raise SkipCheck(_("No {product} found at this URL ({path}).", product="Portainer", path="/api/status"))
    return data


@detector(APP.id)
async def identify(ctx: ScanContext) -> Detection | None:
    try:
        data = await _status(ctx)
    except SkipCheck:
        return None
    return Detection("Portainer", str(data["Version"]))


@check("portainer.detect", title="Portainer detected", category="app", severity=Severity.INFO, apps=APPS)
async def detect(ctx: ScanContext) -> Outcome:
    """Reads the version from /api/status."""
    try:
        data = await _status(ctx)
    except SkipCheck as exc:
        return warned(str(exc))
    return info(
        _("{product} {version} detected.", product="Portainer", version=data["Version"]),
        details={_("Version"): data["Version"]},
    )


@check("portainer.version", title="Version up to date", category="app", severity=Severity.HIGH, apps=APPS)
async def version(ctx: ScanContext) -> Outcome:
    """Compares with the releases on GitHub; Portainer maintains LTS and STS branches in parallel."""
    current = str((await _status(ctx))["Version"])
    try:
        releases = await github_releases("portainer/portainer")
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return errored(_("Version {version} detected, releases not available ({error}).", version=current, error=exc))
    return assess_branches("Portainer", current, releases, reference="https://github.com/portainer/portainer/releases")


@check(
    "portainer.admin_setup",
    title="Admin account set up",
    category="app",
    severity=Severity.CRITICAL,
    apps=APPS,
)
async def admin_setup(ctx: ScanContext) -> Outcome:
    """Without an admin account the first visitor can take over Portainer, and with it Docker on the host."""
    await _status(ctx)
    resp = await ctx.fetch("api/users/admin/check")
    if resp.status == 204:
        return passed(_("The admin account is set up."))
    if resp.status == 303 and resp.headers.get("redirect-reason") == "AdminInitTimeout":
        return warned(
            _(
                "There is no admin account. Portainer locked the setup after the waiting period; "
                "after a restart it is open again."
            ),
            recommendation=_("Restart Portainer and create the admin account immediately."),
            severity=Severity.MEDIUM,
        )
    if resp.status != 404:
        return info(_("Setup status unclear (status {status}).", status=resp.status))
    settings: Any = await ctx.get_json("api/settings/public")
    if isinstance(settings, dict) and settings.get("RequiresSetupToken") is True:
        return warned(
            _(
                "There is no admin account yet. The setup requires the setup token from the "
                "server log, but is reachable from the network."
            ),
            recommendation=_("Create the admin account immediately."),
            severity=Severity.MEDIUM,
        )
    return failed(
        _("There is no admin account yet; anyone can create it and gets access to Docker."),
        recommendation=_(
            "Create the admin account immediately or stop Portainer; the admin password can also "
            "be set at startup with --admin-password-file."
        ),
    )
