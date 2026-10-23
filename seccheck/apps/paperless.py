"""Paperless-ngx profile and checks.

The installed version is only sent to logged-in users (X-Version header), so
the version check relies on /api/remote_version/: Paperless compares itself
with the newest GitHub release and reports only whether an update exists.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.context import HttpResult, ScanContext
from ..core.models import Outcome, Severity, SkipCheck, failed, info, passed, warned
from ..core.registry import AppProfile, Detection, check, detector, register_app
from ..i18n import _

APP = register_app(
    AppProfile(
        id="paperless",
        name="Paperless-ngx",
        short="PL",
        color="#17541f",
        description="Updates, initial setup, open registration, API protection.",
        url_hint="https://paperless.example.com",
        cors_paths=("api/remote_version/",),
        order=70,
    )
)
APPS = [APP.id]

# <meta name="author"> of every Paperless-ngx account page, not translated.
_LOGIN_MARKER = "Paperless-ngx project and contributors"
# Rendered on the login page while no user exists (FIRST_INSTALL).
_FIRST_INSTALL_MARKER = "forward to the signup page if no users exist"
# The "Sign up" link is only rendered with PAPERLESS_ACCOUNT_ALLOW_SIGNUPS.
_SIGNUP_LINK = re.compile(r"<a\s[^>]*href=\"[^\"]*/accounts/signup/")


async def _login_page(ctx: ScanContext) -> HttpResult:
    """The login page, or a redirect carrying X-Version (PAPERLESS_AUTO_LOGIN_USERNAME)."""
    resp = await ctx.try_fetch("accounts/login/")
    if resp is not None:
        if resp.status == 200 and _LOGIN_MARKER in resp.text:
            return resp
        if resp.headers.get("x-version"):
            return resp
    raise SkipCheck(_("No {product} found at this URL ({path}).", product="Paperless-ngx", path="/accounts/login/"))


@detector(APP.id)
async def identify(ctx: ScanContext) -> Detection | None:
    try:
        resp = await _login_page(ctx)
    except SkipCheck:
        return None
    return Detection("Paperless-ngx", resp.headers.get("x-version"))


@check("paperless.detect", title="Paperless-ngx detected", category="app", severity=Severity.INFO, apps=APPS)
async def detect(ctx: ScanContext) -> Outcome:
    """Detects Paperless-ngx by its login page."""
    try:
        resp = await _login_page(ctx)
    except SkipCheck as exc:
        return warned(str(exc))
    version = resp.headers.get("x-version")
    if version:
        return info(
            _("{product} {version} detected.", product="Paperless-ngx", version=version),
            details={_("Version"): version},
        )
    return info(_("{product} detected (the version is not visible without login).", product="Paperless-ngx"))


@check("paperless.version", title="Version up to date", category="app", severity=Severity.HIGH, apps=APPS)
async def version(ctx: ScanContext) -> Outcome:
    """Paperless compares itself with the latest GitHub release (/api/remote_version/)."""
    await _login_page(ctx)
    data: Any = await ctx.get_json("api/remote_version/")
    if not isinstance(data, dict) or not isinstance(data.get("update_available"), bool):
        raise SkipCheck(_("Update status not publicly available (/api/remote_version/)."))
    latest = str(data.get("version") or "")
    details = {_("Latest version"): latest or "?"}
    if latest.lstrip("v") in {"", "0.0.0"}:
        return info(
            _("Paperless could not fetch the latest version from GitHub."),
            details=details,
        )
    if data["update_available"]:
        return failed(
            _(
                "Update available: the latest version is {latest}. New releases often contain security fixes.",
                latest=latest,
            ),
            details=details,
            recommendation=_("Update Paperless-ngx to {latest}.", latest=latest),
            severity=Severity.MEDIUM,
            references=["https://github.com/paperless-ngx/paperless-ngx/releases"],
        )
    return passed(_("Paperless-ngx is up to date ({latest}).", latest=latest), details=details)


@check(
    "paperless.first_user",
    title="Initial setup completed",
    category="app",
    severity=Severity.CRITICAL,
    apps=APPS,
)
async def first_user(ctx: ScanContext) -> Outcome:
    """Without users Paperless allows registration; the first account becomes superuser."""
    resp = await _login_page(ctx)
    if resp.status == 200 and _FIRST_INSTALL_MARKER in resp.text:
        return failed(
            _("There are no users yet; anyone can register and becomes superuser."),
            recommendation=_(
                "Create an admin account immediately (e.g. via PAPERLESS_ADMIN_USER or "
                "'manage.py createsuperuser') or take the instance offline until then."
            ),
        )
    return passed(_("Initial setup is completed."))


@check(
    "paperless.signup",
    title="No open registration",
    category="app",
    severity=Severity.MEDIUM,
    apps=APPS,
)
async def signup(ctx: ScanContext) -> Outcome:
    """With PAPERLESS_ACCOUNT_ALLOW_SIGNUPS anyone can create an account."""
    resp = await _login_page(ctx)
    if resp.status != 200:
        raise SkipCheck(_("Login page not visible (automatic login active)."))
    if _SIGNUP_LINK.search(resp.text):
        return warned(
            _("The login page offers self-registration."),
            recommendation=_("Remove PAPERLESS_ACCOUNT_ALLOW_SIGNUPS or set it to false."),
        )
    return passed(_("Self-registration is disabled."))


@check(
    "paperless.api_auth",
    title="API requires login",
    category="app",
    severity=Severity.CRITICAL,
    apps=APPS,
)
async def api_auth(ctx: ScanContext) -> Outcome:
    """The REST API must not return data without login."""
    await _login_page(ctx)
    resp = await ctx.fetch("api/ui_settings/")
    if resp.status == 200:
        user: Any = None
        try:
            data = resp.json()
            user = data.get("user", {}).get("username") if isinstance(data, dict) else None
        except (ValueError, AttributeError):
            pass
        return failed(
            _("The API returns data without login; every visitor is logged in (as {user}).", user=repr(user))
            if user
            else _("The API returns data without login; every visitor is logged in."),
            recommendation=_(
                "Remove PAPERLESS_AUTO_LOGIN_USERNAME; with remote user login, make sure that only the "
                "reverse proxy can set the header."
            ),
        )
    return passed(_("The API requires login (status {status}).", status=resp.status))
