"""Home Assistant profile and checks.

Home Assistant counts *every* request answered with 401 as a failed login
(http/ban.py) and bans the IP once login_attempts_threshold is reached. All
checks therefore only use endpoints that work without authentication, and
no_probe_paths keeps every other check away from the authenticated API.
"""

from __future__ import annotations

from ..core.context import ScanContext
from ..core.models import Outcome, Severity, SkipCheck, failed, info, passed, warned
from ..core.registry import AppProfile, Detection, check, detector, register_app
from ..i18n import _

APP = register_app(
    AppProfile(
        id="homeassistant",
        name="Home Assistant",
        short="HA",
        color="#18bcf2",
        description="Onboarding, authentication providers. Does not trigger the login ban.",
        url_hint="https://ha.example.com",
        cors_paths=("auth/providers",),
        # /api/onboarding is public, everything else under /api needs a token.
        no_probe_paths=(r"api(?:/(?!onboarding$)|$)",),
        order=50,
    )
)
APPS = [APP.id]


@detector(APP.id)
async def identify(ctx: ScanContext) -> Detection | None:
    async def load() -> bool:
        manifest = await ctx.get_json("manifest.json")
        return isinstance(manifest, dict) and "Home Assistant" in str(manifest.get("name", ""))

    return Detection("Home Assistant") if await ctx.memo("homeassistant:detected", load) else None


async def _require(ctx: ScanContext) -> None:
    if await identify(ctx) is None:
        raise SkipCheck(_("No Home Assistant found at this URL (manifest.json)."))


@check("homeassistant.detect", title="Home Assistant detected", category="app", severity=Severity.INFO, apps=APPS)
async def detect(ctx: ScanContext) -> Outcome:
    """Detects Home Assistant by its web app manifest."""
    try:
        await _require(ctx)
    except SkipCheck as exc:
        return warned(str(exc))
    return info(_("Home Assistant detected (the version is not visible without logging in)."))


@check(
    "homeassistant.onboarding",
    title="Onboarding completed",
    category="app",
    severity=Severity.CRITICAL,
    apps=APPS,
)
async def onboarding(ctx: ScanContext) -> Outcome:
    """An open onboarding lets anyone create the owner account."""
    await _require(ctx)
    steps = await ctx.get_json("api/onboarding")
    if not isinstance(steps, list):
        return passed(_("Onboarding status cannot be retrieved publicly."))
    open_steps = [s.get("step") for s in steps if isinstance(s, dict) and not s.get("done")]
    if "user" in open_steps:
        return failed(
            _("Onboarding is open – anyone can create the owner account."),
            recommendation=_("Complete the onboarding immediately."),
        )
    if open_steps:
        return info(_("Open onboarding steps: {steps}.", steps=", ".join(map(str, open_steps))))
    return passed(_("Onboarding is completed."))


@check(
    "homeassistant.auth_providers",
    title="Secure authentication providers",
    category="app",
    severity=Severity.MEDIUM,
    apps=APPS,
)
async def auth_providers(ctx: ScanContext) -> Outcome:
    """trusted_networks logs clients in without a password – dangerous behind reverse proxies."""
    await _require(ctx)
    data = await ctx.get_json("auth/providers")
    providers = data.get("providers", data) if isinstance(data, dict) else data
    if not isinstance(providers, list):
        return info(_("Authentication providers could not be retrieved."))
    types = [str(p.get("type")) for p in providers if isinstance(p, dict)]
    if "trusted_networks" in types:
        return warned(
            _("The trusted_networks provider is active."),
            details=types,
            recommendation=_(
                "Make sure trusted_networks only contains internal networks and "
                "trusted_proxies is set correctly; otherwise remove it."
            ),
        )
    return passed(_("Active providers: {providers}.", providers=", ".join(types) or "–"), details=types)
