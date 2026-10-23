"""Gitea / Forgejo profile and checks."""

from __future__ import annotations

import httpx

from ..core.advisories import assess_advisories
from ..core.context import ScanContext
from ..core.models import Outcome, Severity, SkipCheck, errored, info, passed, warned
from ..core.registry import AppProfile, Detection, check, detector, register_app
from ..core.versions import assess_latest, gitea_latest, github_latest
from ..i18n import _

APP = register_app(
    AppProfile(
        id="gitea",
        name="Gitea / Forgejo",
        short="GT",
        color="#609926",
        description="Version, open registration, public user list.",
        url_hint="https://git.example.com",
        cors_paths=("api/v1/version",),
        order=20,
    )
)
APPS = [APP.id]


async def _version(ctx: ScanContext) -> str:
    data = await ctx.get_json("api/v1/version")
    if not isinstance(data, dict) or "version" not in data:
        raise SkipCheck(_("No Gitea/Forgejo found at this URL (/api/v1/version)."))
    return str(data["version"])


def _is_forgejo(version: str) -> bool:
    # Forgejo reports e.g. "11.0.1+gitea-1.22.0".
    return "+gitea" in version


@detector(APP.id)
async def identify(ctx: ScanContext) -> Detection | None:
    try:
        version = await _version(ctx)
    except SkipCheck:
        return None
    return Detection("Forgejo" if _is_forgejo(version) else "Gitea", version)


@check("gitea.detect", title="Gitea/Forgejo detected", category="app", severity=Severity.INFO, apps=APPS)
async def detect(ctx: ScanContext) -> Outcome:
    """Reads the version via /api/v1/version."""
    try:
        version = await _version(ctx)
    except SkipCheck as exc:
        return warned(str(exc))
    product = "Forgejo" if _is_forgejo(version) else "Gitea"
    return info(
        _("{product} {version} detected.", product=product, version=version),
        details={_("Product"): product, _("Version"): version},
    )


@check("gitea.version", title="Version up to date", category="app", severity=Severity.HIGH, apps=APPS)
async def version(ctx: ScanContext) -> Outcome:
    """Compares with the latest release on GitHub (Gitea) or Codeberg (Forgejo)."""
    current = await _version(ctx)
    try:
        if _is_forgejo(current):
            latest = await gitea_latest("https://codeberg.org", "forgejo/forgejo")
            return assess_latest("Forgejo", current, latest, reference="https://forgejo.org/releases/")
        latest = await github_latest("go-gitea/gitea")
        return assess_latest("Gitea", current, latest, reference="https://github.com/go-gitea/gitea/releases")
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return errored(
            _(
                "Version {version} detected, latest version could not be retrieved ({error}).",
                version=current,
                error=exc,
            )
        )


GITEA_PACKAGES = {"", "gitea", "gitea.dev", "code.gitea.io/gitea"}


@check(
    "gitea.advisories",
    title="No known vulnerabilities",
    category="app",
    severity=Severity.HIGH,
    apps=APPS,
)
async def advisories(ctx: ScanContext) -> Outcome:
    """Checks the version against the Gitea security advisories on GitHub."""
    current = await _version(ctx)
    if _is_forgejo(current):
        raise SkipCheck(_("There are no machine-readable advisories for Forgejo on GitHub."))
    return await assess_advisories(
        "go-gitea/gitea",
        current,
        name="Gitea",
        package=lambda pkg: str(pkg.get("name") or "").lower() in GITEA_PACKAGES,
    )


@check(
    "gitea.registration",
    title="No open registration",
    category="app",
    severity=Severity.MEDIUM,
    apps=APPS,
)
async def registration(ctx: ScanContext) -> Outcome:
    """Open registration invites spam accounts and abuse (e.g. malware hosting)."""
    await _version(ctx)
    resp = await ctx.try_fetch("user/sign_up")
    if resp and resp.status == 200 and 'name="retype"' in resp.text:
        return warned(
            _("Anyone can create an account."),
            recommendation=_(
                "[service] DISABLE_REGISTRATION = true or allow registration only by invitation/email approval."
            ),
        )
    return passed(_("Self-registration is disabled."))


@check(
    "gitea.public_users",
    title="User list not public",
    category="app",
    severity=Severity.LOW,
    apps=APPS,
)
async def public_users(ctx: ScanContext) -> Outcome:
    """Without REQUIRE_SIGNIN_VIEW, users and public repositories are visible to everyone."""
    await _version(ctx)
    data = await ctx.get_json("api/v1/users/search?limit=5")
    users = data.get("data") if isinstance(data, dict) else None
    if users:
        names = [u.get("login", "?") for u in users]
        return warned(
            _("User accounts can be listed without logging in."),
            details=names,
            recommendation=_("Set [service] REQUIRE_SIGNIN_VIEW = true if the instance is private."),
        )
    return passed(_("Users cannot be listed without logging in."))
