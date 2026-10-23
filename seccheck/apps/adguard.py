"""AdGuard Home profile and checks.

AdGuard Home rate-limits failed logins, but only POST /control/login and
requests that carry Basic-Auth credentials count (internal/home/authhttp.go).
The scanner never sends either, so a plain GET answered with 401 is harmless.
The version is only public while the setup wizard is open or when no web user
is configured at all.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from ..core.context import ScanContext
from ..core.models import Outcome, Severity, SkipCheck, errored, failed, info, passed, warned
from ..core.registry import AppProfile, Detection, check, detector, register_app
from ..core.versions import assess_latest, github_latest
from ..i18n import _

APP = register_app(
    AppProfile(
        id="adguard",
        name="AdGuard Home",
        short="AG",
        color="#68bc71",
        description="Setup wizard, login for the web interface.",
        url_hint="https://adguard.example.com",
        order=100,
    )
)
APPS = [APP.id]

# login.html only has the generic title "Login"; the brand colour and the
# hashed login bundle identify it.
_LOGIN_PAGE = re.compile(r'color="#67B279".*src="login\.[0-9a-f]+\.js"', re.DOTALL)


async def _page(ctx: ScanContext) -> str:
    """'login' or 'install' (setup wizard). login.html redirects to the wizard until setup is done."""

    async def load() -> str | None:
        resp = await ctx.try_fetch("login.html", follow=True)
        if resp is None or resp.status != 200:
            return None
        if "<title>Setup AdGuard Home</title>" in resp.text:
            return "install"
        if _LOGIN_PAGE.search(resp.text):
            return "login"
        return None

    page = await ctx.memo("adguard:page", load)
    if page is None:
        raise SkipCheck(_("No {product} found at this URL ({path}).", product="AdGuard Home", path="/login.html"))
    return page


async def _install_info(ctx: ScanContext) -> dict[str, Any] | None:
    data = await ctx.get_json("control/install/get_addresses")
    return data if isinstance(data, dict) and "interfaces" in data else None


async def _open_status(ctx: ScanContext) -> dict[str, Any] | None:
    """/control/status answers 200 only when no web user is configured."""
    data = await ctx.get_json("control/status")
    return data if isinstance(data, dict) and "version" in data and "running" in data else None


@detector(APP.id)
async def identify(ctx: ScanContext) -> Detection | None:
    try:
        await _page(ctx)
    except SkipCheck:
        return None
    return Detection("AdGuard Home")


@check("adguard.detect", title="AdGuard Home detected", category="app", severity=Severity.INFO, apps=APPS)
async def detect(ctx: ScanContext) -> Outcome:
    """Detects AdGuard Home by its login page or setup wizard."""
    try:
        page = await _page(ctx)
    except SkipCheck as exc:
        return warned(str(exc))
    if page == "install":
        return info(_("AdGuard Home detected (setup wizard)."))
    return info(_("{product} detected (the version is not visible without login).", product="AdGuard Home"))


@check("adguard.version", title="Version up to date", category="app", severity=Severity.HIGH, apps=APPS)
async def version(ctx: ScanContext) -> Outcome:
    """Compares with the latest release on GitHub if the version is visible without login."""
    page = await _page(ctx)
    data = await _install_info(ctx) if page == "install" else await _open_status(ctx)
    current = str(data.get("version") or "") if data else ""
    if not current:
        raise SkipCheck(_("The version is not visible without login."))
    try:
        latest = await github_latest("AdguardTeam/AdGuardHome")
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return errored(
            _("Version {version} detected, latest version not available ({error}).", version=current, error=exc)
        )
    return assess_latest(
        "AdGuard Home", current, latest, reference="https://github.com/AdguardTeam/AdGuardHome/releases"
    )


@check(
    "adguard.setup",
    title="Setup completed",
    category="app",
    severity=Severity.CRITICAL,
    apps=APPS,
)
async def setup(ctx: ScanContext) -> Outcome:
    """While the setup wizard is open, anyone can set the admin access and DNS settings."""
    if await _page(ctx) == "install" and await _install_info(ctx) is not None:
        return failed(
            _("The setup wizard is open; anyone can set the admin account."),
            recommendation=_("Complete the setup immediately; do not expose port 3000 of the wizard to the internet."),
        )
    return passed(_("Setup is completed."))


@check(
    "adguard.auth",
    title="Web interface requires login",
    category="app",
    severity=Severity.CRITICAL,
    apps=APPS,
)
async def auth(ctx: ScanContext) -> Outcome:
    """Without a user in AdGuardHome.yaml, the entire administration is reachable without a password."""
    if await _page(ctx) == "install":
        raise SkipCheck(_("The setup wizard is still open."))
    status = await _open_status(ctx)
    if status is not None:
        return failed(
            _("The management API can be used without login; anyone can change DNS settings."),
            details={_("Version"): status.get("version"), _("Protection enabled"): status.get("protection_enabled")},
            recommendation=_("Create a user with a bcrypt password under 'users' in AdGuardHome.yaml."),
        )
    return passed(_("The management API requires login."))
