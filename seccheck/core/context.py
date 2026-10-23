"""Per-scan state shared by all checks: target, HTTP client and cached probes."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar
from urllib.parse import urlsplit

import httpx

from .. import config
from ..i18n import _
from .models import SkipCheck
from .registry import AppProfile
from .target import Target
from .tls import TlsInfo, gather_tls_info

T = TypeVar("T")

MAX_BODY = 256 * 1024


class FetchError(Exception):
    pass


class BlockedPath(FetchError):
    """The app profile forbids requesting this path (see AppProfile.no_probe_paths)."""


@dataclass
class HttpResult:
    url: str
    status: int
    headers: httpx.Headers
    body: bytes
    # Redirect hops before the final response: (status, url, location).
    history: list[tuple[int, str, str | None]] = field(default_factory=list)
    # Set-Cookie headers of the final response and all redirect hops.
    set_cookies: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        return self.content_type in {"text/html", "application/xhtml+xml"} or self.text.lstrip()[
            :15
        ].lower().startswith(("<!doctype html", "<html"))

    @property
    def location(self) -> str | None:
        return self.headers.get("location")

    def json(self) -> Any:
        return json.loads(self.body)


def _describe_http_error(exc: httpx.HTTPError) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return _("timed out")
    if isinstance(exc, httpx.ConnectError):
        return _("connection failed ({error})", error=exc) if str(exc) else _("connection failed")
    return f"{type(exc).__name__}: {exc}"


def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        # Certificate problems are reported by the TLS checks; the HTTP checks
        # should still be able to look at the instance.
        verify=False,
        timeout=config.HTTP_TIMEOUT,
        headers={"User-Agent": config.USER_AGENT},
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
    )


class ScanContext:
    def __init__(self, target: Target, app: AppProfile, client: httpx.AsyncClient):
        self.target = target
        self.app = app
        self.client = client
        self._memo: dict[str, asyncio.Future[Any]] = {}

    async def memo(self, key: str, factory: Callable[[], Awaitable[T]]) -> T:
        """Run ``factory`` once per scan and share the result between checks."""
        fut = self._memo.get(key)
        if fut is None:
            fut = asyncio.ensure_future(factory())
            self._memo[key] = fut
        # shield: a check hitting its timeout must not cancel the shared work.
        return await asyncio.shield(fut)

    def close(self) -> None:
        for fut in self._memo.values():
            if not fut.done():
                fut.cancel()
            elif not fut.cancelled():
                fut.exception()  # mark as retrieved, avoids asyncio warnings

    # --- HTTP ---------------------------------------------------------------

    def resolve(self, target: str, *, root: bool = False) -> str:
        if target.startswith(("http://", "https://")):
            return target
        return self.target.root_url(target) if root else self.target.url(target)

    async def fetch(
        self,
        target: str = "",
        *,
        method: str = "GET",
        follow: bool = False,
        root: bool = False,
        headers: dict[str, str] | None = None,
    ) -> HttpResult:
        url = self.resolve(target, root=root)
        self._ensure_probe_allowed(url)
        key = f"fetch:{method}:{url}:{follow}:{sorted((headers or {}).items())}"
        return await self.memo(key, lambda: self._fetch(url, method, follow, headers))

    def _ensure_probe_allowed(self, url: str) -> None:
        base = self.target.url()
        if not self.app.no_probe_paths or not url.startswith(base):
            return
        path = urlsplit(url).path[len(self.target.base_path) :]
        if any(re.match(pattern, path) for pattern in self.app.no_probe_paths):
            raise BlockedPath(
                _(
                    "/{path} is not requested for {app} because the app counts unauthenticated "
                    "requests as failed logins.",
                    path=path,
                    app=_(self.app.name),
                )
            )

    async def _fetch(self, url: str, method: str, follow: bool, headers: dict[str, str] | None) -> HttpResult:
        try:
            async with self.client.stream(method, url, headers=headers, follow_redirects=follow) as resp:
                body = bytearray()
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) >= MAX_BODY:
                        break
        except httpx.HTTPError as exc:
            raise FetchError(f"{url}: {_describe_http_error(exc)}") from exc

        cookies: list[str] = []
        history = []
        for hop in resp.history:
            history.append((hop.status_code, str(hop.url), hop.headers.get("location")))
            cookies.extend(hop.headers.get_list("set-cookie"))
        cookies.extend(resp.headers.get_list("set-cookie"))
        return HttpResult(
            url=str(resp.url),
            status=resp.status_code,
            headers=resp.headers,
            body=bytes(body[:MAX_BODY]),
            history=history,
            set_cookies=cookies,
        )

    async def try_fetch(self, target: str = "", **kw: Any) -> HttpResult | None:
        try:
            return await self.fetch(target, **kw)
        except FetchError:
            return None

    async def get_json(self, target: str = "", **kw: Any) -> Any:
        """Parsed JSON body of a 200 response, or None (unreachable, error, not JSON)."""
        resp = await self.try_fetch(target, **kw)
        if resp is None or resp.status != 200:
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    async def main_page(self) -> HttpResult:
        """The app's start page after following redirects (e.g. to /login)."""
        try:
            return await self.fetch("", follow=True)
        except FetchError as exc:
            raise SkipCheck(_("Start page not reachable: {error}", error=exc)) from exc

    # --- TLS ----------------------------------------------------------------

    async def tls(self) -> TlsInfo:
        t = self.target
        return await self.memo("tls:info", lambda: gather_tls_info(t.host, t.tls_port))

    async def require_tls(self) -> TlsInfo:
        info = await self.tls()
        if not info.reachable:
            raise SkipCheck(_("No HTTPS reachable on port {port} ({error}).", port=info.port, error=info.error))
        if info.cert is None:
            raise SkipCheck(_("The server did not present a certificate."))
        return info
