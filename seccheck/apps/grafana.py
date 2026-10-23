"""Grafana profile and checks.

Grafana embeds its public frontend settings (window.grafanaBootData) in the
login page; signup and anonymous access are read from there. Grafana's
brute-force protection only counts password logins, which are never sent.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..core.context import ScanContext
from ..core.models import Outcome, Severity, SkipCheck, failed, info, passed, warned
from ..core.registry import AppProfile, Detection, check, detector, register_app
from ..core.versions import assess_eol
from ..i18n import _

APP = register_app(
    AppProfile(
        id="grafana",
        name="Grafana",
        short="GF",
        color="#f46800",
        description="Version, registration, anonymous access, metrics.",
        url_hint="https://grafana.example.com",
        cors_paths=("api/health",),
        order=90,
    )
)
APPS = [APP.id]

# grafanaBootData is written as one "key: {json}," line per section.
_BOOT_SECTION = re.compile(r"^\s*(user|settings):\s*(\{.*\}),?\s*$", re.MULTILINE)


async def _health(ctx: ScanContext) -> dict[str, Any]:
    data = await ctx.get_json("api/health")
    if not isinstance(data, dict) or "database" not in data:
        raise SkipCheck(_("No {product} found at this URL ({path}).", product="Grafana", path="/api/health"))
    return data


async def _boot_data(ctx: ScanContext) -> dict[str, dict[str, Any]]:
    """The user and settings sections of grafanaBootData on the login page."""

    async def load() -> dict[str, dict[str, Any]]:
        resp = await ctx.try_fetch("login")
        if resp is None or resp.status != 200 or "grafanaBootData" not in resp.text:
            return {}
        sections: dict[str, dict[str, Any]] = {}
        for name, raw in _BOOT_SECTION.findall(resp.text):
            try:
                sections[name] = json.loads(raw)
            except ValueError:
                continue
        return sections

    return await ctx.memo("grafana:boot", load)


async def _settings(ctx: ScanContext) -> dict[str, Any]:
    await _health(ctx)
    settings = (await _boot_data(ctx)).get("settings")
    if not isinstance(settings, dict):
        raise SkipCheck(_("Frontend settings on the login page not readable."))
    return settings


async def _version(ctx: ScanContext) -> str | None:
    health = await _health(ctx)
    if health.get("version"):
        return str(health["version"])
    build = (await _boot_data(ctx)).get("settings", {}).get("buildInfo", {})
    return str(build["version"]) if isinstance(build, dict) and build.get("version") else None


@detector(APP.id)
async def identify(ctx: ScanContext) -> Detection | None:
    try:
        data = await _health(ctx)
    except SkipCheck:
        return None
    return Detection("Grafana", str(data["version"]) if data.get("version") else None)


@check("grafana.detect", title="Grafana detected", category="app", severity=Severity.INFO, apps=APPS)
async def detect(ctx: ScanContext) -> Outcome:
    """Detects Grafana via /api/health."""
    try:
        version = await _version(ctx)
    except SkipCheck as exc:
        return warned(str(exc))
    if version is None:
        return info(_("Grafana detected (the version is hidden)."))
    return info(_("{product} {version} detected.", product="Grafana", version=version), details={_("Version"): version})


@check("grafana.version", title="Version supported", category="app", severity=Severity.HIGH, apps=APPS)
async def version(ctx: ScanContext) -> Outcome:
    """Grafana maintains several release branches in parallel; checked against endoflife.date."""
    current = await _version(ctx)
    if current is None:
        raise SkipCheck(_("Version hidden ([auth.anonymous] hide_version)."))
    return await assess_eol("grafana", current, name="Grafana")


@check(
    "grafana.signup",
    title="No open registration",
    category="app",
    severity=Severity.MEDIUM,
    apps=APPS,
)
async def signup(ctx: ScanContext) -> Outcome:
    """With allow_sign_up anyone can create an account and gets the default role."""
    settings = await _settings(ctx)
    if settings.get("disableUserSignUp") is False:
        return warned(
            _("Anyone can create a Grafana account themselves."),
            recommendation=_("Set [users] allow_sign_up = false (GF_USERS_ALLOW_SIGN_UP=false)."),
        )
    return passed(_("Self-registration is disabled."))


@check(
    "grafana.anonymous",
    title="No anonymous access",
    category="app",
    severity=Severity.HIGH,
    apps=APPS,
)
async def anonymous(ctx: ScanContext) -> Outcome:
    """With anonymous access enabled, every visitor sees the dashboards and data sources of the organization."""
    settings = await _settings(ctx)
    if settings.get("anonymousEnabled") is not True:
        return passed(_("Anonymous access is disabled."))
    user = (await _boot_data(ctx)).get("user", {})
    role = str(user.get("orgRole") or "?")
    details = {_("Role of anonymous visitors"): role, _("Organization"): user.get("orgName") or "?"}
    recommendation = _(
        "Set [auth.anonymous] enabled = false; for public dashboards use the "
        "'Public dashboards' feature or snapshots instead."
    )
    if role in {"Admin", "Editor"}:
        return failed(
            _("Anonymous access is active; every visitor has the role {role}.", role=role),
            details=details,
            recommendation=recommendation,
        )
    return warned(
        _("Anonymous access is active (role {role}); dashboards are visible without login.", role=role),
        details=details,
        recommendation=recommendation,
        severity=Severity.MEDIUM,
    )


@check(
    "grafana.metrics",
    title="Metrics not public",
    category="app",
    severity=Severity.LOW,
    apps=APPS,
)
async def metrics(ctx: ScanContext) -> Outcome:
    """The Prometheus endpoint /metrics reveals the version, plugins and internal metrics."""
    await _health(ctx)
    resp = await ctx.try_fetch("metrics")
    # The output is several hundred KB; grafana_build_info lies beyond MAX_BODY.
    if resp and resp.status == 200 and "# HELP grafana_" in resp.text:
        return warned(
            _("The internal Prometheus metrics are available without login."),
            details={"URL": resp.url},
            recommendation=_(
                "Set [metrics] basic_auth_username/basic_auth_password or block /metrics in the reverse proxy."
            ),
        )
    return passed(_("The metrics are not publicly available."))
