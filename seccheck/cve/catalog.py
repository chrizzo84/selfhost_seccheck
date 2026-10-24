"""Products the CVE feed knows, and where their vulnerabilities are published.

A product has one or more sources:

    ghsa  repository security advisories on GitHub ("owner/repo")
    osv   a package in OSV.dev ("Ecosystem", "package name")
    nvd   a CPE vendor:product in the NVD

A vulnerability reported by several sources is stored once (keyed by its CVE
id). For the affected version ranges, sources are trusted in the order osv,
ghsa, nvd: OSV ranges are machine-readable, GitHub advisories are written by
the project itself, NVD ranges are added later by NIST and lag behind.

To support a new product, add an entry here. Finding the identifiers:
OSV: https://osv.dev/list?q=<name>; NVD: https://nvd.nist.gov/products/cpe/search;
GitHub: the "Security" tab of the project's repository.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SourceKind = Literal["ghsa", "osv", "nvd"]
SOURCE_PRIORITY: tuple[SourceKind, ...] = ("osv", "ghsa", "nvd")


@dataclass(frozen=True)
class Source:
    kind: SourceKind
    # ghsa: "owner/repo"; osv: "Ecosystem:package"; nvd: "vendor:product"
    ref: str
    # ghsa only: package names (lowercase) to keep; empty keeps all.
    packages: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.ref}"


@dataclass(frozen=True)
class Product:
    id: str
    name: str
    sources: tuple[Source, ...]
    # App profile whose scans report this product's version.
    app: str | None = None
    # Detection.product names (lowercase) when one app profile covers several products.
    detect_names: tuple[str, ...] = ()
    # Linux distributions ship security fixes without changing the upstream
    # version (backports), so a version match is only "possibly affected".
    backports: bool = False


def ghsa(repo: str, *packages: str) -> Source:
    return Source("ghsa", repo, tuple(p.lower() for p in packages))


def osv(ecosystem: str, package: str) -> Source:
    return Source("osv", f"{ecosystem}:{package}")


def nvd(cpe: str) -> Source:
    return Source("nvd", cpe)


PRODUCTS: tuple[Product, ...] = (
    # Products with an app profile: their version comes from scans.
    Product(
        "nextcloud",
        "Nextcloud Server",
        (ghsa("nextcloud/security-advisories", "server"), nvd("nextcloud:nextcloud_server")),
        app="nextcloud",
    ),
    Product(
        "gitea",
        "Gitea",
        (osv("Go", "code.gitea.io/gitea"), nvd("gitea:gitea")),
        app="gitea",
        detect_names=("gitea",),
    ),
    Product("forgejo", "Forgejo", (nvd("forgejo:forgejo"),), app="gitea", detect_names=("forgejo",)),
    Product(
        "vaultwarden",
        "Vaultwarden",
        (ghsa("dani-garcia/vaultwarden"), osv("crates.io", "vaultwarden")),
        app="vaultwarden",
    ),
    Product("jellyfin", "Jellyfin", (ghsa("jellyfin/jellyfin"), nvd("jellyfin:jellyfin")), app="jellyfin"),
    Product("immich", "Immich", (ghsa("immich-app/immich"),), app="immich"),
    Product("paperless", "Paperless-ngx", (ghsa("paperless-ngx/paperless-ngx"),), app="paperless"),
    Product("portainer", "Portainer", (ghsa("portainer/portainer"), nvd("portainer:portainer")), app="portainer"),
    Product("grafana", "Grafana", (osv("Go", "github.com/grafana/grafana"), nvd("grafana:grafana")), app="grafana"),
    Product(
        "adguard",
        "AdGuard Home",
        (osv("Go", "github.com/AdguardTeam/AdGuardHome"), nvd("adguard:adguardhome")),
        app="adguard",
    ),
    Product(
        "uptimekuma",
        "Uptime Kuma",
        (ghsa("louislam/uptime-kuma"), osv("npm", "uptime-kuma")),
        app="uptimekuma",
    ),
    Product(
        "homeassistant",
        "Home Assistant",
        (osv("PyPI", "homeassistant"), ghsa("home-assistant/core"), nvd("home-assistant:home-assistant")),
        app="homeassistant",
    ),
    # Watchlist only: the version is entered by hand.
    Product("authentik", "authentik", (osv("Go", "goauthentik.io"), ghsa("goauthentik/authentik"))),
    Product("caddy", "Caddy", (osv("Go", "github.com/caddyserver/caddy/v2"),)),
    Product("httpd", "Apache HTTP Server", (nvd("apache:http_server"),), backports=True),
    Product("mastodon", "Mastodon", (ghsa("mastodon/mastodon"),)),
    Product("synapse", "Matrix Synapse", (osv("PyPI", "matrix-synapse"),)),
    Product("nginx", "nginx", (nvd("f5:nginx"),), backports=True),
    Product("openssh", "OpenSSH", (nvd("openbsd:openssh"),), backports=True),
    Product("pihole", "Pi-hole", (ghsa("pi-hole/pi-hole"), nvd("pi-hole:pi-hole"))),
    Product("plex", "Plex Media Server", (nvd("plex:media_server"),)),
    Product("proxmox", "Proxmox VE", (nvd("proxmox:virtual_environment"),)),
    Product(
        "traefik",
        "Traefik",
        (
            osv("Go", "github.com/traefik/traefik/v3"),
            osv("Go", "github.com/traefik/traefik/v2"),
            nvd("traefik:traefik"),
        ),
    ),
    Product("wordpress", "WordPress", (nvd("wordpress:wordpress"),)),
)

_BY_ID = {p.id: p for p in PRODUCTS}


def get_product(product_id: str | None) -> Product | None:
    return _BY_ID.get(product_id or "")


def product_for(app_id: str, detected: str | None = None) -> Product | None:
    """The product an app profile's scan found, e.g. ("gitea", "Forgejo") -> forgejo."""
    candidates = [p for p in PRODUCTS if p.app == app_id]
    if len(candidates) > 1 and detected:
        name = detected.lower()
        for product in candidates:
            if any(n in name for n in product.detect_names):
                return product
    return candidates[0] if candidates else None
