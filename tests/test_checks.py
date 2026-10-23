"""Checks against mocked HTTP responses."""

from __future__ import annotations

import contextlib

import httpx
import pytest

from seccheck.apps import nextcloud
from seccheck.checks import exposure, headers, transport
from seccheck.core.context import FetchError
from seccheck.core.models import Severity, SkipCheck, Status
from seccheck.core.registry import checks_for

pytestmark = pytest.mark.asyncio

GOOD_HEADERS = {
    "content-type": "text/html",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
    "server": "nginx",
}


def html(headers: dict[str, str] | None = None, body: str = "<!doctype html><html></html>", status: int = 200):
    return lambda request: httpx.Response(status, headers=headers or {"content-type": "text/html"}, text=body)


async def test_good_headers_pass(make_ctx) -> None:
    ctx = make_ctx(html(GOOD_HEADERS))
    for check in (
        headers.csp,
        headers.clickjacking,
        headers.nosniff,
        headers.referrer,
        headers.permissions,
        headers.disclosure,
        transport.hsts,
    ):
        outcome = await check(ctx)
        assert outcome.status == Status.PASS, (check.__name__, outcome.summary)


async def test_missing_headers_fail(make_ctx) -> None:
    ctx = make_ctx(html())
    assert (await headers.csp(ctx)).status == Status.FAIL
    assert (await headers.clickjacking(ctx)).status == Status.FAIL
    assert (await headers.nosniff(ctx)).status == Status.FAIL
    assert (await transport.hsts(ctx)).status == Status.FAIL


async def test_weak_csp_and_short_hsts_warn(make_ctx) -> None:
    ctx = make_ctx(
        html(
            {
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-eval'",
                "strict-transport-security": "max-age=86400",
            }
        )
    )
    csp = await headers.csp(ctx)
    assert csp.status == Status.WARN and csp.severity == Severity.LOW
    hsts = await transport.hsts(ctx)
    assert hsts.status == Status.WARN


async def test_version_disclosure(make_ctx) -> None:
    ctx = make_ctx(html({"content-type": "text/html", "server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/8.1.2"}))
    assert (await headers.disclosure(ctx)).status == Status.WARN


async def test_cookie_flags(make_ctx) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=[
                ("content-type", "text/html"),
                ("set-cookie", "sid=1; Path=/; HttpOnly"),
                ("set-cookie", "ok=1; Secure; HttpOnly; SameSite=Lax"),
            ],
            text="<html></html>",
        )

    outcome = await transport.cookies(make_ctx(handler))
    assert outcome.status == Status.FAIL
    assert "sid" in outcome.summary
    assert outcome.details["sid"] == "missing: Secure, SameSite"
    assert outcome.details["ok"] == "ok"


async def test_cors_reflection_with_credentials(make_ctx) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("origin", "")
        return httpx.Response(
            200,
            headers={"access-control-allow-origin": origin, "access-control-allow-credentials": "true"},
            text="{}",
        )

    outcome = await transport.cors(make_ctx(handler))
    assert outcome.status == Status.FAIL


async def test_http_redirect(make_ctx) -> None:
    ok = make_ctx(lambda r: httpx.Response(301, headers={"location": "https://cloud.example.com/"}))
    assert (await transport.http_redirect(ok)).status == Status.PASS
    served = make_ctx(html())
    assert (await transport.http_redirect(served)).status == Status.FAIL
    with pytest.raises(SkipCheck):
        await transport.http_redirect(make_ctx(html(), url="http://cloud.example.com"))


async def test_spa_catch_all_is_no_false_positive(make_ctx) -> None:
    """Apps that answer every path with 200 + HTML must not trigger exposure findings."""
    outcome = await exposure.sensitive_files(make_ctx(html()))
    assert outcome.status == Status.PASS


async def test_exposed_git_and_env(make_ctx) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        files = {"/.git/HEAD": "ref: refs/heads/main\n", "/.env": "DB_PASSWORD=hunter2\n"}
        body = files.get(request.url.path)
        if body is None:
            return httpx.Response(404, text="not found")
        return httpx.Response(200, headers={"content-type": "text/plain"}, text=body)

    outcome = await exposure.sensitive_files(make_ctx(handler))
    assert outcome.status == Status.FAIL
    assert outcome.severity == Severity.CRITICAL
    assert len(outcome.details) == 2


def nextcloud_handler(status: dict, extra: dict[str, httpx.Response] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/status.php":
            return httpx.Response(200, json=status)
        if extra and request.url.path in extra:
            return extra[request.url.path]
        return httpx.Response(404, text="nope")

    return handler


NC_STATUS = {
    "installed": True,
    "maintenance": False,
    "needsDbUpgrade": False,
    "version": "35.0.2.2",
    "versionstring": "35.0.2",
}


async def test_nextcloud_not_installed(make_ctx) -> None:
    ctx = make_ctx(nextcloud_handler({**NC_STATUS, "installed": False}), app="nextcloud")
    assert (await nextcloud.state(ctx)).status == Status.FAIL


async def test_nextcloud_data_dir_exposed(make_ctx) -> None:
    exposed = {"/data/.ncdata": httpx.Response(200, text="# Nextcloud data directory\n")}
    ctx = make_ctx(nextcloud_handler(NC_STATUS, exposed), app="nextcloud")
    assert (await nextcloud.data_dir(ctx)).status == Status.FAIL
    clean = make_ctx(nextcloud_handler(NC_STATUS), app="nextcloud")
    assert (await nextcloud.data_dir(clean)).status == Status.PASS


async def test_homeassistant_scan_never_triggers_401(make_ctx) -> None:
    """Every 401 counts as a failed login in Home Assistant and can get the scanner banned."""
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        requested.append(path)
        if path == "/manifest.json":
            return httpx.Response(200, json={"name": "Home Assistant"})
        if path == "/api/onboarding":
            return httpx.Response(200, json=[{"step": "user", "done": True}])
        if path == "/auth/providers":
            return httpx.Response(200, json={"providers": [{"type": "homeassistant"}]})
        if path.startswith("/api"):
            return httpx.Response(401, text="401: Unauthorized")
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html></html>")

    ctx = make_ctx(handler, app="homeassistant")
    # TLS and DNS checks talk to the network directly, not through the HTTP client.
    specs = [s for s in checks_for(ctx.app) if s.category not in {"tls", "dns"}]
    for spec in specs:
        with contextlib.suppress(SkipCheck, FetchError):
            await spec.func(ctx)

    assert "/manifest.json" in requested
    unauthenticated_api = [p for p in requested if p.startswith("/api") and p != "/api/onboarding"]
    assert unauthenticated_api == []


async def test_blocked_path_is_refused_before_sending(make_ctx) -> None:
    sent: list[str] = []
    ctx = make_ctx(lambda r: sent.append(r.url.path) or httpx.Response(401), app="homeassistant")
    assert await ctx.try_fetch("api/") is None
    assert await ctx.try_fetch("api/states") is None
    assert await ctx.try_fetch("api/onboarding") is not None
    assert sent == ["/api/onboarding"]


async def test_nextcloud_checks_skip_without_nextcloud(make_ctx) -> None:
    ctx = make_ctx(html(), app="nextcloud")
    assert (await nextcloud.detect(ctx)).status == Status.WARN
    with pytest.raises(SkipCheck):
        await nextcloud.data_dir(ctx)
