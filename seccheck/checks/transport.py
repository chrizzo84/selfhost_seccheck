"""HTTP transport checks: redirects, HSTS, cookies, CORS, methods."""

from __future__ import annotations

import re

from ..core.context import FetchError, ScanContext
from ..core.models import Outcome, Severity, SkipCheck, failed, info, passed, warned
from ..core.registry import check
from ..i18n import _

HSTS_MIN = 180 * 86400
HSTS_RECOMMENDED = 365 * 86400


@check(
    "transport.http_redirect",
    title="HTTP redirects to HTTPS",
    category="transport",
    severity=Severity.HIGH,
    description="Requests via http:// must be redirected straight to https://.",
)
async def http_redirect(ctx: ScanContext) -> Outcome:
    if not ctx.target.is_https:
        raise SkipCheck(_("The instance is already accessed over HTTP (see “HTTPS available”)."))
    url = ctx.target.plain_http_url()
    try:
        resp = await ctx.fetch(url)
    except FetchError:
        return passed(_("Port 80 is not reachable – no unencrypted access possible."))

    location = resp.location or ""
    details = {_("Request"): url, "Status": resp.status, "Location": location or "–"}
    if resp.status in (301, 302, 303, 307, 308):
        if location.startswith("https://"):
            if resp.status in (301, 308):
                return passed(_("Permanent redirect ({status}) to HTTPS.", status=resp.status), details=details)
            return warned(
                _("Redirects to HTTPS, but only temporarily ({status}).", status=resp.status),
                details=details,
                severity=Severity.LOW,
                recommendation=_("Use a permanent redirect (301/308)."),
            )
        return failed(
            _("HTTP does not redirect to an HTTPS address."),
            details=details,
            recommendation=_("Set up a redirect from http:// to https:// in the web server."),
        )
    if resp.status >= 400:
        return passed(
            _("HTTP serves no content (status {status}).", status=resp.status),
            details=details,
        )
    return failed(
        _("The instance is usable over unencrypted HTTP."),
        details=details,
        recommendation=_("Redirect all HTTP requests to HTTPS with 301/308."),
    )


def _parse_hsts(value: str) -> dict[str, str | bool]:
    result: dict[str, str | bool] = {}
    for part in value.split(";"):
        key, _sep, val = part.strip().partition("=")
        if key:
            result[key.lower()] = val.strip().strip('"') if val else True
    return result


@check(
    "transport.hsts",
    title="HTTP Strict Transport Security (HSTS)",
    category="transport",
    severity=Severity.HIGH,
    description="HSTS stops browsers from ever opening the site unencrypted (SSL stripping).",
)
async def hsts(ctx: ScanContext) -> Outcome:
    if not ctx.target.is_https:
        raise SkipCheck(_("Only relevant for HTTPS."))
    resp = await ctx.main_page()
    value = resp.headers.get("strict-transport-security")
    ref = ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"]
    if not value:
        return failed(
            _("No Strict-Transport-Security header set."),
            recommendation=_("Set the header: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            references=ref,
        )
    parsed = _parse_hsts(value)
    try:
        max_age = int(str(parsed.get("max-age", "0")))
    except ValueError:
        max_age = 0
    details = {
        "Header": value,
        _("max-age (days)"): max_age // 86400,
        "includeSubDomains": _("yes") if "includesubdomains" in parsed else _("no"),
        "preload": _("yes") if "preload" in parsed else _("no"),
    }
    if max_age < HSTS_MIN:
        return warned(
            _("HSTS enabled, but max-age of {days} days is too short (at least 180).", days=max_age // 86400),
            details=details,
            severity=Severity.MEDIUM,
            recommendation=_("Use max-age=31536000 (1 year)."),
            references=ref,
        )
    return passed(_("HSTS enabled with a max-age of {days} days.", days=max_age // 86400), details=details)


def _parse_cookie(raw: str) -> tuple[str, set[str], dict[str, str]]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0]
    flags, attrs = set(), {}
    for p in parts[1:]:
        key, sep, val = p.partition("=")
        if sep:
            attrs[key.lower()] = val
        elif key:
            flags.add(key.lower())
    return name, flags, attrs


@check(
    "transport.cookies",
    title="Cookie security attributes",
    category="transport",
    severity=Severity.MEDIUM,
    description="Session cookies need Secure, HttpOnly and SameSite.",
)
async def cookies(ctx: ScanContext) -> Outcome:
    resp = await ctx.main_page()
    if not resp.set_cookies:
        return passed(_("The start page sets no cookies."))

    problems: list[str] = []
    missing_secure = False
    rows = {}
    for raw in resp.set_cookies:
        name, flags, attrs = _parse_cookie(raw)
        missing = []
        if ctx.target.is_https and "secure" not in flags:
            missing.append("Secure")
            missing_secure = True
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        elif attrs["samesite"].lower() == "none" and "secure" not in flags:
            missing.append(_("Secure (required for SameSite=None)"))
        rows[name] = _("missing: {attributes}", attributes=", ".join(missing)) if missing else "ok"
        if missing:
            problems.append(f"{name} ({', '.join(missing)})")

    if not problems:
        if ctx.target.is_https:
            return passed(_("All {count} cookies have Secure, HttpOnly and SameSite.", count=len(rows)), details=rows)
        return passed(_("All {count} cookies have HttpOnly and SameSite.", count=len(rows)), details=rows)
    rec = _(
        "Set cookies with Secure; HttpOnly; SameSite=Lax (or Strict). HttpOnly may only be missing "
        "on cookies that JavaScript reads on purpose (e.g. CSRF tokens)."
    )
    if missing_secure:
        return failed(
            _("Cookies without Secure flag: {cookies}", cookies="; ".join(problems)), details=rows, recommendation=rec
        )
    return warned(_("Missing attributes: {cookies}", cookies="; ".join(problems)), details=rows, recommendation=rec)


EVIL_ORIGIN = "https://seccheck-cors-probe.example"


@check(
    "transport.cors",
    title="CORS configuration",
    category="transport",
    severity=Severity.HIGH,
    description="Third-party origins must not be able to access the application with credentials.",
)
async def cors(ctx: ScanContext) -> Outcome:
    paths = ["", *ctx.app.cors_paths]
    reflected_creds, reflected, wildcard = [], [], []
    tested = {}
    for path in paths:
        try:
            resp = await ctx.fetch(path, headers={"Origin": EVIL_ORIGIN})
        except FetchError:
            continue
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
        label = "/" + path.lstrip("/") if path else _("/ (start page)")
        tested[label] = acao or _("no ACAO header")
        if acao == EVIL_ORIGIN or acao == "null":
            (reflected_creds if acac else reflected).append(label)
        elif acao == "*":
            wildcard.append(label)

    if not tested:
        raise SkipCheck(_("None of the paths was reachable."))
    rec = _("Set Access-Control-Allow-Origin only for known origins; never reflect the Origin header unchecked.")
    if reflected_creds:
        return failed(
            _("Arbitrary origins are allowed with credentials: {paths}.", paths=", ".join(reflected_creds)),
            details=tested,
            recommendation=rec,
        )
    if reflected:
        return warned(
            _("Arbitrary origins are allowed (without credentials): {paths}.", paths=", ".join(reflected)),
            details=tested,
            severity=Severity.MEDIUM,
            recommendation=rec,
        )
    if wildcard:
        return info(_("Access-Control-Allow-Origin: * on {paths}.", paths=", ".join(wildcard)), details=tested)
    return passed(_("Third-party origins are not allowed."), details=tested)


@check(
    "transport.trace",
    title="HTTP method TRACE disabled",
    category="transport",
    severity=Severity.LOW,
    description="TRACE echoes requests back including headers (cross-site tracing).",
)
async def trace(ctx: ScanContext) -> Outcome:
    resp = await ctx.fetch("", method="TRACE")
    if resp.status == 200 and re.search(r"^TRACE ", resp.text, re.MULTILINE):
        return failed(
            _("The server answers TRACE requests."),
            recommendation=_("Disable TRACE in the web server (Apache: TraceEnable off)."),
        )
    return passed(_("TRACE is not supported (status {status}).", status=resp.status))
