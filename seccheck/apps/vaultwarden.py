"""Vaultwarden profile and checks."""

from __future__ import annotations

import httpx

from ..core.advisories import assess_advisories
from ..core.context import ScanContext
from ..core.models import Outcome, Severity, SkipCheck, errored, info, passed, warned
from ..core.registry import AppProfile, Detection, check, detector, register_app
from ..core.versions import assess_latest, github_latest
from ..i18n import _

APP = register_app(
    AppProfile(
        id="vaultwarden",
        name="Vaultwarden",
        short="VW",
        color="#175ddc",
        description="Version, admin panel exposure, web vault.",
        url_hint="https://vault.example.com",
        cors_paths=("api/config",),
        order=30,
    )
)
APPS = [APP.id]


async def _version(ctx: ScanContext) -> str:
    data = await ctx.get_json("api/version")
    if not isinstance(data, str):
        raise SkipCheck(_("No Vaultwarden found at this URL (/api/version)."))
    return data


@detector(APP.id)
async def identify(ctx: ScanContext) -> Detection | None:
    try:
        return Detection("Vaultwarden", await _version(ctx))
    except SkipCheck:
        return None


@check("vaultwarden.detect", title="Vaultwarden detected", category="app", severity=Severity.INFO, apps=APPS)
async def detect(ctx: ScanContext) -> Outcome:
    """Reads the version via /api/version."""
    try:
        version = await _version(ctx)
    except SkipCheck as exc:
        return warned(str(exc))
    return info(
        _("{product} {version} detected.", product="Vaultwarden", version=version), details={_("Version"): version}
    )


@check("vaultwarden.version", title="Version up to date", category="app", severity=Severity.HIGH, apps=APPS)
async def version(ctx: ScanContext) -> Outcome:
    """A password manager should always be up to date."""
    current = await _version(ctx)
    try:
        latest = await github_latest("dani-garcia/vaultwarden")
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return errored(
            _(
                "Version {version} detected, latest version could not be retrieved ({error}).",
                version=current,
                error=exc,
            )
        )
    return assess_latest(
        "Vaultwarden", current, latest, reference="https://github.com/dani-garcia/vaultwarden/releases"
    )


@check(
    "vaultwarden.advisories",
    title="No known vulnerabilities",
    category="app",
    severity=Severity.HIGH,
    apps=APPS,
)
async def advisories(ctx: ScanContext) -> Outcome:
    """Checks the version against the Vaultwarden security advisories on GitHub."""
    return await assess_advisories(
        "dani-garcia/vaultwarden",
        await _version(ctx),
        name="Vaultwarden",
        package=lambda pkg: str(pkg.get("name") or "vaultwarden").lower() == "vaultwarden",
    )


@check(
    "vaultwarden.admin",
    title="Admin panel not public",
    category="app",
    severity=Severity.MEDIUM,
    apps=APPS,
)
async def admin(ctx: ScanContext) -> Outcome:
    """The /admin panel should be disabled or restricted to internal networks via the reverse proxy."""
    await _version(ctx)
    resp = await ctx.try_fetch("admin", follow=True)
    if resp and resp.status == 200 and resp.is_html and "admin" in resp.text.lower():
        return warned(
            _("The admin panel is reachable from the internet."),
            details={"URL": resp.url},
            recommendation=_(
                "Remove ADMIN_TOKEN if the panel is not needed; otherwise restrict /admin to internal IPs "
                "in the reverse proxy and use an Argon2-hashed token."
            ),
        )
    return passed(_("The admin panel is disabled or not reachable."))
