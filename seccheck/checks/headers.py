"""Security response headers of the start page."""

from __future__ import annotations

import re

from ..core.context import ScanContext
from ..core.models import Outcome, Severity, failed, passed, warned
from ..core.registry import check
from ..i18n import _

MDN = "https://developer.mozilla.org/docs/Web/HTTP/Headers/"


def _csp_directives(value: str) -> dict[str, list[str]]:
    directives = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


@check(
    "headers.csp",
    title="Content-Security-Policy",
    category="headers",
    severity=Severity.MEDIUM,
    description="A CSP limits which scripts may run and mitigates XSS.",
)
async def csp(ctx: ScanContext) -> Outcome:
    resp = await ctx.main_page()
    value = resp.headers.get("content-security-policy")
    ref = [MDN + "Content-Security-Policy"]
    if not value:
        if resp.headers.get("content-security-policy-report-only"):
            return warned(
                _("CSP is only active in report-only mode and is not enforced."),
                recommendation=_("Enforce the CSP as Content-Security-Policy once testing is done."),
                references=ref,
            )
        return failed(
            _("No Content-Security-Policy set."),
            recommendation=_("Define a restrictive CSP, e.g. default-src 'self'; frame-ancestors 'self'."),
            references=ref,
        )
    directives = _csp_directives(value)
    scripts = directives.get("script-src", directives.get("default-src"))
    weak = []
    if scripts is None:
        weak.append(_("neither script-src nor default-src defined"))
    else:
        if "'unsafe-inline'" in scripts and not any(s.startswith(("'nonce-", "'sha")) for s in scripts):
            weak.append(_("'unsafe-inline' for scripts"))
        if "'unsafe-eval'" in scripts:
            weak.append(_("'unsafe-eval' for scripts"))
        if "*" in scripts:
            weak.append(_("wildcard * for scripts"))
    details = {"Header": value}
    if weak:
        return warned(
            _("CSP present but weakened: {weaknesses}.", weaknesses=", ".join(weak)),
            details=details,
            severity=Severity.LOW,
            references=ref,
        )
    return passed(_("Content-Security-Policy is set."), details=details)


@check(
    "headers.clickjacking",
    title="Clickjacking protection",
    category="headers",
    severity=Severity.MEDIUM,
    description="X-Frame-Options or CSP frame-ancestors prevent embedding in third-party pages.",
)
async def clickjacking(ctx: ScanContext) -> Outcome:
    resp = await ctx.main_page()
    xfo = (resp.headers.get("x-frame-options") or "").strip()
    ancestors = _csp_directives(resp.headers.get("content-security-policy", "")).get("frame-ancestors")
    details = {"X-Frame-Options": xfo or "–", "frame-ancestors": " ".join(ancestors) if ancestors else "–"}
    if ancestors is not None:
        if "*" in ancestors:
            return failed(_("CSP frame-ancestors allows every site (*)."), details=details)
        return passed(_("Embedding restricted via CSP frame-ancestors."), details=details)
    if xfo.upper() in {"DENY", "SAMEORIGIN"}:
        return passed(f"X-Frame-Options: {xfo.upper()}.", details=details)
    return failed(
        _("The page can be embedded by third-party websites in an iframe."),
        details=details,
        recommendation=_("Set X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'."),
        references=[MDN + "X-Frame-Options"],
    )


@check(
    "headers.nosniff",
    title="X-Content-Type-Options",
    category="headers",
    severity=Severity.LOW,
    description="nosniff stops browsers from interpreting files as a different type.",
)
async def nosniff(ctx: ScanContext) -> Outcome:
    resp = await ctx.main_page()
    value = (resp.headers.get("x-content-type-options") or "").strip().lower()
    if value == "nosniff":
        return passed("X-Content-Type-Options: nosniff.")
    return failed(
        _("X-Content-Type-Options: nosniff is missing."),
        recommendation=_("Set the header: X-Content-Type-Options: nosniff"),
        references=[MDN + "X-Content-Type-Options"],
    )


SAFE_REFERRER = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "no-referrer-when-downgrade",
}


@check(
    "headers.referrer",
    title="Referrer-Policy",
    category="headers",
    severity=Severity.LOW,
    description="Prevents full URLs (including share links) from being sent to third-party sites.",
)
async def referrer(ctx: ScanContext) -> Outcome:
    resp = await ctx.main_page()
    raw = resp.headers.get("referrer-policy", "")
    # Multiple values are allowed; the last one the browser understands wins.
    policies = [p.strip().lower() for p in raw.split(",") if p.strip()]
    ref = [MDN + "Referrer-Policy"]
    if not policies:
        return warned(
            _("No Referrer-Policy set (browsers then use strict-origin-when-cross-origin)."),
            recommendation=_("Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin."),
            references=ref,
        )
    effective = policies[-1]
    if effective in SAFE_REFERRER:
        return passed(f"Referrer-Policy: {raw}.")
    return failed(
        _("Unsafe Referrer-Policy: {policy}.", policy=effective),
        recommendation=_("Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin."),
        references=ref,
    )


@check(
    "headers.permissions",
    title="Permissions-Policy",
    category="headers",
    severity=Severity.LOW,
    description="Restricts browser features such as camera, microphone or location.",
)
async def permissions(ctx: ScanContext) -> Outcome:
    resp = await ctx.main_page()
    value = resp.headers.get("permissions-policy")
    if value:
        return passed(_("Permissions-Policy is set."), details={"Header": value})
    return warned(
        _("No Permissions-Policy set."),
        recommendation=_(
            "Disable features you do not need, e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ),
        references=[MDN + "Permissions-Policy"],
    )


DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")


@check(
    "headers.disclosure",
    title="No version numbers in headers",
    category="headers",
    severity=Severity.LOW,
    description="Version numbers of the web server or PHP make it easier for attackers to find matching exploits.",
)
async def disclosure(ctx: ScanContext) -> Outcome:
    resp = await ctx.main_page()
    found = {h: resp.headers[h] for h in DISCLOSURE_HEADERS if h in resp.headers}
    versioned = {h: v for h, v in found.items() if re.search(r"\d+\.\d+", v)}
    if versioned:
        listed = ", ".join(f"{h}: {v}" for h, v in versioned.items())
        return warned(
            _("Headers reveal software versions: {headers}.", headers=listed),
            details=found,
            recommendation="nginx: server_tokens off; Apache: ServerTokens Prod; PHP: expose_php = Off",
        )
    if found:
        return passed(_("Headers name the software but no versions."), details=found)
    return passed(_("No revealing headers found."))
