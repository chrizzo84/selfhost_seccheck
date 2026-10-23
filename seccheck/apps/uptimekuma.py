"""Uptime Kuma profile and checks.

Uptime Kuma talks to its frontend over Socket.IO; the admin setup state and
the version are only available there (or after login). The checks therefore
use the few plain HTTP endpoints. GET /metrics without credentials is
rejected by express-basic-auth before the login rate limiter is consulted.
"""

from __future__ import annotations

from typing import Any

from ..core.context import ScanContext
from ..core.models import Outcome, Severity, SkipCheck, failed, info, passed, warned
from ..core.registry import AppProfile, Detection, check, detector, register_app
from ..i18n import _

APP = register_app(
    AppProfile(
        id="uptimekuma",
        name="Uptime Kuma",
        short="UK",
        color="#5cdd8b",
        description="Database setup, disabled login.",
        url_hint="https://status.example.com",
        cors_paths=("api/entry-page",),
        order=110,
    )
)
APPS = [APP.id]

_ENTRY_TYPES = {"entryPage", "statusPageMatchedDomain", "setup-database"}


async def _entry(ctx: ScanContext) -> dict[str, Any]:
    data = await ctx.get_json("api/entry-page")
    if not isinstance(data, dict) or data.get("type") not in _ENTRY_TYPES:
        raise SkipCheck(_("No {product} found at this URL ({path}).", product="Uptime Kuma", path="/api/entry-page"))
    return data


@detector(APP.id)
async def identify(ctx: ScanContext) -> Detection | None:
    try:
        await _entry(ctx)
    except SkipCheck:
        return None
    return Detection("Uptime Kuma")


@check("uptimekuma.detect", title="Uptime Kuma detected", category="app", severity=Severity.INFO, apps=APPS)
async def detect(ctx: ScanContext) -> Outcome:
    """Detects Uptime Kuma via /api/entry-page."""
    try:
        data = await _entry(ctx)
    except SkipCheck as exc:
        return warned(str(exc))
    details = {_("Start page"): data.get("entryPage") or data.get("statusPageSlug") or _("Dashboard")}
    return info(
        _("{product} detected (the version is not visible without login).", product="Uptime Kuma"),
        details=details,
    )


@check(
    "uptimekuma.db_setup",
    title="Database set up",
    category="app",
    severity=Severity.CRITICAL,
    apps=APPS,
)
async def db_setup(ctx: ScanContext) -> Outcome:
    """Without a database configuration, Uptime Kuma 2 starts an open setup wizard."""
    await _entry(ctx)
    data = await ctx.get_json("setup-database-info")
    if isinstance(data, dict) and data.get("needSetup") is True:
        return failed(
            _("The database setup is open; anyone can connect the instance to their own database."),
            recommendation=_("Complete the setup immediately and then create the admin account."),
        )
    return passed(_("The database is set up."))


@check(
    "uptimekuma.auth",
    title="Login enabled",
    category="app",
    severity=Severity.CRITICAL,
    apps=APPS,
)
async def auth(ctx: ScanContext) -> Outcome:
    """With 'Disable authentication' the dashboard is open to everyone; detectable via /metrics."""
    entry = await _entry(ctx)
    if entry.get("type") == "setup-database":
        raise SkipCheck(_("The database setup is still open."))
    resp = await ctx.try_fetch("metrics")
    if resp is None:
        raise SkipCheck(_("/metrics not reachable."))
    # Prometheus text format; in setup mode every path returns the HTML shell instead.
    if resp.status == 200 and not resp.is_html and "# HELP " in resp.text:
        return failed(
            _("Login is disabled; dashboard, monitors and metrics are open to everyone."),
            recommendation=_(
                "Re-enable authentication under Settings → Security; run Uptime Kuma only with "
                "login or behind an auth proxy."
            ),
        )
    if resp.status == 401:
        return passed(_("Login is active (/metrics requires credentials)."))
    return info(_("Login status unclear (/metrics: status {status}).", status=resp.status))
