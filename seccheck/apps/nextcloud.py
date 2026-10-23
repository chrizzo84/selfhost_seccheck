"""Nextcloud profile and checks.

Mirrors the most important parts of Nextcloud's own admin security checks
and https://scan.nextcloud.com, using only unauthenticated requests.
"""

from __future__ import annotations

from typing import Any

from ..core.advisories import assess_advisories
from ..core.context import FetchError, ScanContext
from ..core.models import (
    Outcome,
    Severity,
    SkipCheck,
    failed,
    info,
    passed,
    warned,
    worst_severity,
)
from ..core.registry import AppProfile, Detection, check, detector, register_app
from ..core.versions import assess_eol
from ..i18n import _

APP = register_app(
    AppProfile(
        id="nextcloud",
        name="Nextcloud",
        short="NC",
        color="#0082c9",
        description="Version & support, data directory, source code protection, Nextcloud-specific headers.",
        url_hint="https://cloud.example.com",
        cors_paths=("status.php", "ocs/v2.php/cloud/capabilities"),
        order=10,
    )
)
APPS = [APP.id]
HARDENING = "https://docs.nextcloud.com/server/latest/admin_manual/installation/harden_server.html"


async def _status(ctx: ScanContext) -> dict[str, Any] | None:
    async def load() -> dict[str, Any] | None:
        try:
            resp = await ctx.fetch("status.php", follow=True)
            data = resp.json() if resp.status == 200 else None
        except (FetchError, ValueError):
            return None
        if isinstance(data, dict) and "installed" in data and "version" in data:
            return data
        return None

    return await ctx.memo("nextcloud:status", load)


async def _require(ctx: ScanContext) -> dict[str, Any]:
    status = await _status(ctx)
    if status is None:
        raise SkipCheck(_("No Nextcloud found at this URL (status.php is missing)."))
    return status


def _version(status: dict[str, Any]) -> str:
    return str(status.get("versionstring") or status.get("version") or "?")


@detector(APP.id)
async def identify(ctx: ScanContext) -> Detection | None:
    status = await _status(ctx)
    if status is None:
        return None
    return Detection(str(status.get("productname") or "Nextcloud"), _version(status))


@check("nextcloud.detect", title="Nextcloud detected", category="app", severity=Severity.INFO, apps=APPS)
async def detect(ctx: ScanContext) -> Outcome:
    """Reads status.php to detect Nextcloud and its version."""
    status = await _status(ctx)
    if status is None:
        return warned(
            _("status.php returns no Nextcloud data. Is the URL (including subdirectory) correct?"),
            recommendation=_("Enter the URL under which the Nextcloud login page is reachable."),
        )
    product = status.get("productname", "Nextcloud")
    current = _version(status)
    details = {
        _("Product"): product,
        _("Version"): current,
        _("Edition"): status.get("edition") or "Community",
    }
    return info(_("{product} {version} detected.", product=product, version=current), details=details)


@check(
    "nextcloud.version",
    title="Nextcloud version up to date and supported",
    category="app",
    severity=Severity.HIGH,
    apps=APPS,
)
async def version(ctx: ScanContext) -> Outcome:
    """Compares the version with the supported release branches (endoflife.date)."""
    status = await _require(ctx)
    return await assess_eol(
        "nextcloud",
        _version(status),
        name="Nextcloud",
        extended_support=bool(status.get("extendedSupport")),
    )


@check(
    "nextcloud.advisories",
    title="No known vulnerabilities",
    category="app",
    severity=Severity.HIGH,
    apps=APPS,
)
async def advisories(ctx: ScanContext) -> Outcome:
    """Checks the version against the published Nextcloud security advisories."""
    status = await _require(ctx)
    return await assess_advisories(
        "nextcloud/security-advisories",
        _version(status),
        name="Nextcloud",
        package=lambda pkg: (
            "nextcloud" in str(pkg.get("ecosystem", "")).lower() and str(pkg.get("name", "")).lower() == "server"
        ),
    )


@check(
    "nextcloud.state",
    title="Installation status",
    category="app",
    severity=Severity.CRITICAL,
    apps=APPS,
)
async def state(ctx: ScanContext) -> Outcome:
    """An unfinished installation lets anyone create the admin account."""
    status = await _require(ctx)
    if not status.get("installed"):
        return failed(
            _("Nextcloud is not fully installed – anyone can open the setup wizard and create an admin account."),
            recommendation=_("Finish the installation immediately or take the instance offline."),
        )
    if status.get("needsDbUpgrade"):
        return warned(
            _("A database upgrade is pending."),
            severity=Severity.MEDIUM,
            recommendation=_("Run occ upgrade."),
        )
    if status.get("maintenance"):
        return warned(_("The instance is in maintenance mode."), severity=Severity.LOW)
    return passed(_("Installation completed, no maintenance mode."))


DATA_PROBES = {
    # Marker file: .ncdata since Nextcloud 29, .ocdata before (usually empty).
    "data/.ncdata": lambda r: r.status == 200 and "Nextcloud data directory" in r.text,
    "data/.ocdata": lambda r: r.status == 200 and len(r.body) < 64 and not r.is_html,
    "data/nextcloud.log": lambda r: r.status == 200 and '"reqId"' in r.text,
    "data/htaccesstest.txt": lambda r: r.status == 200 and "htaccess" in r.text and not r.is_html,
}


@check(
    "nextcloud.data_dir",
    title="Data directory not public",
    category="app",
    severity=Severity.CRITICAL,
    apps=APPS,
)
async def data_dir(ctx: ScanContext) -> Outcome:
    """If the data directory lies unprotected in the webroot, all files of all users can be downloaded."""
    await _require(ctx)
    exposed = []
    for path, matches in DATA_PROBES.items():
        resp = await ctx.try_fetch(path)
        if resp is not None and matches(resp):
            exposed.append(ctx.target.url(path))
    if exposed:
        return failed(
            _("The data directory can be accessed from the internet!"),
            details=exposed,
            recommendation=_(
                "Move the data directory outside the webroot or block it in the web server. "
                "The bundled .htaccess has no effect under nginx."
            ),
            references=[HARDENING],
        )
    return passed(_("The data directory is not reachable."))


SOURCE_PROBES = {
    "config/config.php": ("$CONFIG", Severity.CRITICAL),
    "occ": ("<?php", Severity.HIGH),
    "version.php": ("<?php", Severity.HIGH),
}


@check(
    "nextcloud.source",
    title="Configuration and source code protected",
    category="app",
    severity=Severity.CRITICAL,
    apps=APPS,
)
async def source(ctx: ScanContext) -> Outcome:
    """PHP files must never be served as source code (e.g. config.php with the database password)."""
    await _require(ctx)
    exposed, severities = [], []
    for path, (needle, severity) in SOURCE_PROBES.items():
        resp = await ctx.try_fetch(path)
        if resp is not None and resp.status == 200 and needle in resp.text:
            exposed.append(ctx.target.url(path))
            severities.append(severity)
    if exposed:
        return failed(
            _("PHP source code is served in plain text."),
            details=exposed,
            severity=worst_severity(severities),
            recommendation=_("Configure the PHP handler in the web server correctly and block /config, /lib etc."),
            references=[HARDENING],
        )
    return passed(_("config.php and PHP source files cannot be retrieved."))


@check(
    "nextcloud.headers",
    title="Nextcloud-specific headers",
    category="app",
    severity=Severity.LOW,
    apps=APPS,
)
async def nc_headers(ctx: ScanContext) -> Outcome:
    """Checks X-Robots-Tag and X-Permitted-Cross-Domain-Policies like the Nextcloud admin overview."""
    await _require(ctx)
    resp = await ctx.main_page()
    robots = resp.headers.get("x-robots-tag", "").lower()
    xpcdp = resp.headers.get("x-permitted-cross-domain-policies", "").lower()
    details = {
        "X-Robots-Tag": robots or "–",
        "X-Permitted-Cross-Domain-Policies": xpcdp or "–",
    }
    missing = []
    if not ("noindex" in robots and "nofollow" in robots):
        missing.append('X-Robots-Tag "noindex, nofollow"')
    if xpcdp != "none":
        missing.append('X-Permitted-Cross-Domain-Policies "none"')
    if missing:
        return failed(
            _("Not set correctly: {headers}.", headers=", ".join(missing)),
            details=details,
            recommendation=_("Set the headers in the web server or via the bundled .htaccess."),
            references=[HARDENING],
        )
    return passed(_("All headers recommended by Nextcloud are set."), details=details)


WELL_KNOWN = {
    ".well-known/caldav": "remote.php/dav",
    ".well-known/carddav": "remote.php/dav",
}


@check(
    "nextcloud.well_known",
    title="CalDAV/CardDAV redirects",
    category="app",
    severity=Severity.INFO,
    apps=APPS,
)
async def well_known(ctx: ScanContext) -> Outcome:
    """Not a security issue, but needed for the automatic setup of calendar and contact clients."""
    await _require(ctx)
    broken = {}
    for path, expected in WELL_KNOWN.items():
        resp = await ctx.try_fetch(path, root=True)
        location = (resp.location or "") if resp else ""
        if not (resp and resp.status in (301, 302, 307, 308) and expected in location):
            broken[path] = f"Status {resp.status if resp else '–'}, Location {location or '–'}"
    if broken:
        return warned(
            _("/.well-known redirects are missing or do not point to remote.php/dav."),
            details=broken,
            recommendation=_("Set up redirects to /remote.php/dav/ in the reverse proxy."),
        )
    return passed(_("CalDAV and CardDAV redirects are correct."))


@check(
    "nextcloud.registration",
    title="No open self-registration",
    category="app",
    severity=Severity.MEDIUM,
    apps=APPS,
)
async def registration(ctx: ScanContext) -> Outcome:
    """The Registration app lets strangers create accounts for themselves."""
    await _require(ctx)
    resp = await ctx.try_fetch("index.php/apps/registration/", follow=True)
    if resp and resp.status == 200 and "/apps/registration" in resp.url and "<form" in resp.text:
        return warned(
            _("Self-registration is publicly reachable."),
            details={"URL": resp.url},
            recommendation=_("Only allow registration with admin approval or for specific email domains."),
        )
    return passed(_("No public self-registration found."))
