"""Immich, Paperless-ngx, Portainer, Grafana, AdGuard Home and Uptime Kuma against mocked HTTP.

Response bodies are trimmed copies of what the official Docker images return
(Immich 3.3.5, Paperless-ngx 3.3.4, Portainer CE 2.45.3, Grafana 13.2.4,
AdGuard Home 0.107.79, Uptime Kuma 2.5.7).
"""

from __future__ import annotations

import json

import httpx
import pytest

from seccheck.apps import adguard, grafana, immich, paperless, portainer, uptimekuma
from seccheck.core.models import SkipCheck, Status

pytestmark = pytest.mark.asyncio

SPA = httpx.Response(200, headers={"content-type": "text/html"}, text="<!doctype html><html><body>app</body></html>")


def routes(table: dict[str, httpx.Response], default: httpx.Response | None = None):
    """Answer by path; unknown paths get 404 (or ``default``, e.g. a SPA shell)."""
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        resp = table.get(request.url.path)
        if resp is not None:
            return resp
        return default if default is not None else httpx.Response(404, text="not found")

    handler.requested = requested  # type: ignore[attr-defined]
    return handler


# --- Immich -------------------------------------------------------------------

IMMICH_VERSION = httpx.Response(200, json={"major": 3, "minor": 3, "patch": 5, "prerelease": None})


def immich_config(initialized: bool) -> httpx.Response:
    return httpx.Response(200, json={"isInitialized": initialized, "isOnboarded": initialized, "publicUsers": True})


async def test_immich_detection(make_ctx) -> None:
    ctx = make_ctx(routes({"/api/server/version": IMMICH_VERSION}), app="immich")
    det = await immich.identify(ctx)
    assert det is not None and det.version == "3.3.5"
    assert (await immich.detect(ctx)).status == Status.INFO
    # A SPA that answers every path with HTML is not Immich.
    other = make_ctx(routes({}, default=SPA), app="immich")
    assert await immich.identify(other) is None
    assert (await immich.detect(other)).status == Status.WARN


async def test_immich_admin_setup(make_ctx) -> None:
    open_ = make_ctx(
        routes({"/api/server/version": IMMICH_VERSION, "/api/server/config": immich_config(False)}), app="immich"
    )
    assert (await immich.admin_setup(open_)).status == Status.FAIL
    done = make_ctx(
        routes({"/api/server/version": IMMICH_VERSION, "/api/server/config": immich_config(True)}), app="immich"
    )
    assert (await immich.admin_setup(done)).status == Status.PASS


# --- Paperless-ngx --------------------------------------------------------------

PL_HEAD = '<meta name="author" content="Paperless-ngx project and contributors"><title>Paperless-ngx sign in</title>'
PL_FIRST = (
    PL_HEAD
    + '<script>// forward to the signup page if no users exist\nwindow.location.href = "/accounts/signup/";</script>'
)
PL_SIGNUP = PL_HEAD + '<p>Please sign in.<br/>Don\'t have an account yet? <a href="/accounts/signup/">Sign up</a></p>'


def pl_login(body: str) -> httpx.Response:
    return httpx.Response(200, headers={"content-type": "text/html"}, text=body)


async def test_paperless_detection(make_ctx) -> None:
    ctx = make_ctx(routes({"/accounts/login/": pl_login(PL_HEAD)}), app="paperless")
    det = await paperless.identify(ctx)
    assert det is not None and det.version is None
    # Auto-login redirects away from the login page, but sends X-Version.
    auto = make_ctx(
        routes({"/accounts/login/": httpx.Response(302, headers={"location": "/dashboard", "x-version": "3.3.4"})}),
        app="paperless",
    )
    assert (await paperless.identify(auto)).version == "3.3.4"
    other = make_ctx(routes({}, default=SPA), app="paperless")
    assert await paperless.identify(other) is None
    assert (await paperless.detect(other)).status == Status.WARN


async def test_paperless_first_user_and_signup(make_ctx) -> None:
    fresh = make_ctx(routes({"/accounts/login/": pl_login(PL_FIRST)}), app="paperless")
    assert (await paperless.first_user(fresh)).status == Status.FAIL
    # The JS redirect to the signup page is not the "Sign up" link.
    assert (await paperless.signup(fresh)).status == Status.PASS

    signup = make_ctx(routes({"/accounts/login/": pl_login(PL_SIGNUP)}), app="paperless")
    assert (await paperless.first_user(signup)).status == Status.PASS
    assert (await paperless.signup(signup)).status == Status.WARN


async def test_paperless_api_auth(make_ctx) -> None:
    locked = routes(
        {
            "/accounts/login/": pl_login(PL_HEAD),
            "/api/ui_settings/": httpx.Response(
                401,
                headers={"www-authenticate": "Token"},
                json={"detail": "Authentication credentials were not provided."},
            ),
        }
    )
    assert (await paperless.api_auth(make_ctx(locked, app="paperless"))).status == Status.PASS
    auto = routes(
        {
            "/accounts/login/": httpx.Response(302, headers={"location": "/dashboard", "x-version": "3.3.4"}),
            "/api/ui_settings/": httpx.Response(200, json={"user": {"id": 2, "username": "admin"}, "settings": {}}),
        }
    )
    outcome = await paperless.api_auth(make_ctx(auto, app="paperless"))
    assert outcome.status == Status.FAIL and "admin" in outcome.summary


async def test_paperless_version(make_ctx) -> None:
    def ctx_for(data: dict):
        return make_ctx(
            routes({"/accounts/login/": pl_login(PL_HEAD), "/api/remote_version/": httpx.Response(200, json=data)}),
            app="paperless",
        )

    assert (await paperless.version(ctx_for({"version": "v3.3.4", "update_available": False}))).status == Status.PASS
    assert (await paperless.version(ctx_for({"version": "v3.4.0", "update_available": True}))).status == Status.FAIL
    # GitHub unreachable from the server: Paperless reports 0.0.0 / False.
    assert (await paperless.version(ctx_for({"version": "0.0.0", "update_available": False}))).status == Status.INFO


# --- Portainer ----------------------------------------------------------------

PT_STATUS = httpx.Response(200, json={"Version": "2.45.3", "InstanceID": "450a0d86-73f7-43dd-a70e-68c2b14e2278"})
PT_NO_ADMIN = httpx.Response(404, json={"message": "No administrator account found inside the database"})


def pt_settings(token: bool) -> httpx.Response:
    return httpx.Response(200, json={"AuthenticationMethod": 1, "RequiresSetupToken": token})


async def test_portainer_detection(make_ctx) -> None:
    ctx = make_ctx(routes({"/api/status": PT_STATUS}), app="portainer")
    det = await portainer.identify(ctx)
    assert det is not None and det.version == "2.45.3"
    other = make_ctx(routes({"/api/status": httpx.Response(200, json={"status": "ok"})}), app="portainer")
    assert await portainer.identify(other) is None


async def test_portainer_admin_setup(make_ctx) -> None:
    done = routes({"/api/status": PT_STATUS, "/api/users/admin/check": httpx.Response(204)})
    assert (await portainer.admin_setup(make_ctx(done, app="portainer"))).status == Status.PASS

    open_ = routes(
        {"/api/status": PT_STATUS, "/api/users/admin/check": PT_NO_ADMIN, "/api/settings/public": pt_settings(False)}
    )
    assert (await portainer.admin_setup(make_ctx(open_, app="portainer"))).status == Status.FAIL

    token = routes(
        {"/api/status": PT_STATUS, "/api/users/admin/check": PT_NO_ADMIN, "/api/settings/public": pt_settings(True)}
    )
    assert (await portainer.admin_setup(make_ctx(token, app="portainer"))).status == Status.WARN

    timeout = routes(
        {
            "/api/status": PT_STATUS,
            "/api/users/admin/check": httpx.Response(
                303,
                headers={"redirect-reason": "AdminInitTimeout"},
                json={"message": "Administrator initialization timeout"},
            ),
        }
    )
    outcome = await portainer.admin_setup(make_ctx(timeout, app="portainer"))
    assert outcome.status == Status.WARN and "restart" in outcome.summary


# --- Grafana ------------------------------------------------------------------

GF_HEALTH = httpx.Response(200, json={"database": "ok", "version": "13.2.4", "commit": "0e79aef9d9"})


def gf_login(*, signup: bool = False, anonymous: bool = False, role: str = "") -> httpx.Response:
    user = {"isSignedIn": False, "orgName": "Main Org." if anonymous else "", "orgRole": role}
    settings = {
        "disableUserSignUp": not signup,
        "anonymousEnabled": anonymous,
        "buildInfo": {"version": "13.2.4", "edition": "Open Source"},
    }
    body = (
        '<html><body><script nonce="">\n      window.grafanaBootData = {\n'
        f"        user: {json.dumps(user)},\n"
        f"        settings: {json.dumps(settings)},\n"
        "        navTree: [],\n      };\n</script></body></html>"
    )
    return httpx.Response(200, headers={"content-type": "text/html"}, text=body)


async def test_grafana_detection(make_ctx) -> None:
    ctx = make_ctx(routes({"/api/health": GF_HEALTH}), app="grafana")
    det = await grafana.identify(ctx)
    assert det is not None and det.version == "13.2.4"
    hidden = make_ctx(routes({"/api/health": httpx.Response(200, json={"database": "ok"})}), app="grafana")
    assert (await grafana.identify(hidden)).version is None
    other = make_ctx(routes({"/api/health": httpx.Response(200, json={"status": "UP"})}), app="grafana")
    assert await grafana.identify(other) is None


async def test_grafana_signup_and_anonymous(make_ctx) -> None:
    closed = make_ctx(routes({"/api/health": GF_HEALTH, "/login": gf_login()}), app="grafana")
    assert (await grafana.signup(closed)).status == Status.PASS
    assert (await grafana.anonymous(closed)).status == Status.PASS

    viewer = make_ctx(
        routes({"/api/health": GF_HEALTH, "/login": gf_login(signup=True, anonymous=True, role="Viewer")}),
        app="grafana",
    )
    assert (await grafana.signup(viewer)).status == Status.WARN
    assert (await grafana.anonymous(viewer)).status == Status.WARN

    admin = make_ctx(
        routes({"/api/health": GF_HEALTH, "/login": gf_login(anonymous=True, role="Admin")}), app="grafana"
    )
    assert (await grafana.anonymous(admin)).status == Status.FAIL


async def test_grafana_metrics(make_ctx) -> None:
    metrics = httpx.Response(
        200,
        headers={"content-type": "text/plain"},
        text="# HELP go_gc_duration_seconds x\n# HELP grafana_access_evaluation_count y\n",
    )
    exposed = make_ctx(routes({"/api/health": GF_HEALTH, "/metrics": metrics}), app="grafana")
    assert (await grafana.metrics(exposed)).status == Status.WARN
    locked = make_ctx(routes({"/api/health": GF_HEALTH, "/metrics": httpx.Response(401)}), app="grafana")
    assert (await grafana.metrics(locked)).status == Status.PASS


# --- AdGuard Home ---------------------------------------------------------------

AGH_LOGIN = httpx.Response(
    200,
    headers={"content-type": "text/html"},
    text='<link rel="mask-icon" href="assets/safari-pinned-tab.svg" color="#67B279"><title>Login</title>'
    '<script defer="defer" src="login.7c61bbe3e8598fe0a882.js"></script>',
)
AGH_INSTALL = httpx.Response(200, headers={"content-type": "text/html"}, text="<title>Setup AdGuard Home</title>")
AGH_ADDRESSES = httpx.Response(
    200, json={"interfaces": {"eth0": {}}, "version": "v0.107.79", "web_port": 80, "dns_port": 53}
)
AGH_STATUS = httpx.Response(200, json={"version": "v0.107.79", "running": True, "protection_enabled": True})


async def test_adguard_detection(make_ctx) -> None:
    assert await adguard.identify(make_ctx(routes({"/login.html": AGH_LOGIN}), app="adguard")) is not None
    install = routes(
        {"/login.html": httpx.Response(302, headers={"location": "/install.html"}), "/install.html": AGH_INSTALL}
    )
    assert await adguard.identify(make_ctx(install, app="adguard")) is not None
    other = make_ctx(routes({}, default=SPA), app="adguard")
    assert await adguard.identify(other) is None
    assert (await adguard.detect(other)).status == Status.WARN


async def test_adguard_setup(make_ctx) -> None:
    install = routes(
        {
            "/login.html": httpx.Response(302, headers={"location": "/install.html"}),
            "/install.html": AGH_INSTALL,
            "/control/install/get_addresses": AGH_ADDRESSES,
        }
    )
    ctx = make_ctx(install, app="adguard")
    assert (await adguard.setup(ctx)).status == Status.FAIL
    with pytest.raises(SkipCheck):
        await adguard.auth(ctx)
    done = make_ctx(routes({"/login.html": AGH_LOGIN}), app="adguard")
    assert (await adguard.setup(done)).status == Status.PASS


async def test_adguard_auth(make_ctx) -> None:
    locked = routes({"/login.html": AGH_LOGIN, "/control/status": httpx.Response(401)})
    assert (await adguard.auth(make_ctx(locked, app="adguard"))).status == Status.PASS
    with pytest.raises(SkipCheck):
        await adguard.version(make_ctx(locked, app="adguard"))
    open_ = routes({"/login.html": AGH_LOGIN, "/control/status": AGH_STATUS})
    assert (await adguard.auth(make_ctx(open_, app="adguard"))).status == Status.FAIL


# --- Uptime Kuma ----------------------------------------------------------------

KUMA_ENTRY = httpx.Response(200, json={"type": "entryPage", "entryPage": None})
KUMA_SETUP_ENTRY = httpx.Response(200, json={"type": "setup-database"})
KUMA_HTML = httpx.Response(
    200, headers={"content-type": "text/html"}, text="<!DOCTYPE html><html><title>Uptime Kuma</title></html>"
)


async def test_uptimekuma_detection(make_ctx) -> None:
    assert await uptimekuma.identify(make_ctx(routes({"/api/entry-page": KUMA_ENTRY}), app="uptimekuma")) is not None
    other = make_ctx(
        routes({"/api/entry-page": httpx.Response(200, json={"type": "page"})}, default=SPA), app="uptimekuma"
    )
    assert await uptimekuma.identify(other) is None


async def test_uptimekuma_db_setup(make_ctx) -> None:
    open_ = routes(
        {
            "/api/entry-page": KUMA_SETUP_ENTRY,
            "/setup-database-info": httpx.Response(200, json={"runningSetup": False, "needSetup": True}),
        },
        default=KUMA_HTML,
    )
    ctx = make_ctx(open_, app="uptimekuma")
    assert (await uptimekuma.db_setup(ctx)).status == Status.FAIL
    with pytest.raises(SkipCheck):
        await uptimekuma.auth(ctx)
    done = routes(
        {
            "/api/entry-page": KUMA_ENTRY,
            "/setup-database-info": httpx.Response(200, json={"runningSetup": False, "needSetup": False}),
        }
    )
    assert (await uptimekuma.db_setup(make_ctx(done, app="uptimekuma"))).status == Status.PASS


async def test_uptimekuma_auth(make_ctx) -> None:
    locked = routes(
        {"/api/entry-page": KUMA_ENTRY, "/metrics": httpx.Response(401, headers={"www-authenticate": "Basic"})}
    )
    assert (await uptimekuma.auth(make_ctx(locked, app="uptimekuma"))).status == Status.PASS
    metrics = httpx.Response(
        200, headers={"content-type": "text/plain; version=0.0.4"}, text="# HELP monitor_cert_days_remaining x\n"
    )
    open_ = routes({"/api/entry-page": KUMA_ENTRY, "/metrics": metrics})
    assert (await uptimekuma.auth(make_ctx(open_, app="uptimekuma"))).status == Status.FAIL


# --- Detectors are safe for unknown targets -------------------------------------

NEW_APPS = (immich, paperless, portainer, grafana, adguard, uptimekuma)


async def test_new_detectors_never_touch_home_assistant_api(make_ctx) -> None:
    """Auto-detection runs every detector against unknown targets; none may hit HA's authenticated API."""
    ha_api = {"/api/", "/api/config", "/api/states", "/api/services", "/api/events", "/api/core/state"}
    handler = routes({"/manifest.json": httpx.Response(200, json={"name": "Home Assistant"})})
    ctx = make_ctx(handler)
    for module in NEW_APPS:
        assert await module.identify(ctx) is None
    assert not set(handler.requested) & ha_api
    assert all(p != "/api" for p in handler.requested)


async def test_new_detectors_swallow_connection_errors(make_ctx) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    ctx = make_ctx(boom)
    for module in NEW_APPS:
        assert await module.identify(ctx) is None
