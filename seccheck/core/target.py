"""Parsing and validation of the URL the user wants to scan."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from .. import config
from ..i18n import _

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class TargetError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    base_path: str  # always starts and ends with "/"

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return False
        return True

    @property
    def tls_port(self) -> int:
        """Port used for TLS checks. For http:// targets we look at 443."""
        return self.port if self.is_https else 443

    def _netloc(self, scheme: str, port: int) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if _DEFAULT_PORTS[scheme] == port else f"{host}:{port}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self._netloc(self.scheme, self.port)}"

    def url(self, path: str = "") -> str:
        """URL relative to the app's base path (e.g. https://host/nextcloud/<path>)."""
        return self.origin + self.base_path + path.lstrip("/")

    def root_url(self, path: str = "") -> str:
        """URL relative to the host root, e.g. for /.well-known/."""
        return self.origin + "/" + path.lstrip("/")

    def plain_http_url(self) -> str:
        """The same location over unencrypted HTTP on port 80."""
        return f"http://{self._netloc('http', 80)}{self.base_path}"

    def https_url(self) -> str:
        return f"https://{self._netloc('https', self.tls_port)}{self.base_path}"


def parse_target(raw: str) -> Target:
    raw = (raw or "").strip()
    if not raw:
        raise TargetError(_("Please enter a URL."))
    if not _SCHEME_RE.match(raw):
        raw = "https://" + raw
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise TargetError(_("Only http:// and https:// are supported."))
    if parts.username or parts.password:
        raise TargetError(_("Please do not put credentials into the URL."))
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise TargetError(_("The URL contains no host name."))
    try:
        port = parts.port or _DEFAULT_PORTS[scheme]
    except ValueError as exc:
        raise TargetError(_("Invalid port in the URL.")) from exc

    path = parts.path or "/"
    # People paste deep links like /index.php/login or /apps/files; keep only
    # the installation directory in front of the PHP front controller.
    path = re.split(r"/index\.php(?:/|$)", path, maxsplit=1)[0] or "/"
    if not path.startswith("/"):
        path = "/" + path
    if not path.endswith("/"):
        path += "/"
    return Target(scheme=scheme, host=host, port=port, base_path=path)


async def ensure_allowed(target: Target) -> None:
    """Optionally reject targets in private networks (SSRF protection)."""
    if not config.BLOCK_PRIVATE_TARGETS:
        return
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(target.host, target.port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetError(_("Host name {host} could not be resolved.", host=target.host)) from exc
    for *_rest, sockaddr in infos:
        addr = ipaddress.ip_address(sockaddr[0])
        if not addr.is_global:
            raise TargetError(
                _(
                    "{host} resolves to a private/internal address ({address}). "
                    "Internal targets are disabled on this server.",
                    host=target.host,
                    address=addr,
                )
            )
