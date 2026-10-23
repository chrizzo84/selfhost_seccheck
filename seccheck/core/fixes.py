"""Ready-to-paste web server configuration for the findings of a scan.

Each fix belongs to a check id. Response headers are collected across all
fixes and rendered once per server (Caddy and Traefik need them in a single
block); everything else is a raw snippet per server.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..i18n import N_, _
from .models import CheckResult, Status

SERVERS = {"nginx": "nginx", "apache": "Apache", "caddy": "Caddy", "traefik": "Traefik"}

MOZILLA_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
)


@dataclass(frozen=True)
class Fix:
    headers: dict[str, str] = field(default_factory=dict)
    # Raw snippets per server key; a server without an entry needs nothing extra.
    snippets: dict[str, str] = field(default_factory=dict)


TLS_FIX = Fix(
    snippets={
        "nginx": f"ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers {MOZILLA_CIPHERS};\nssl_prefer_server_ciphers off;",
        "apache": f"SSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLCipherSuite {MOZILLA_CIPHERS}\nSSLHonorCipherOrder off",
        "caddy": N_(
            "# Caddy only uses TLS 1.2/1.3 with secure ciphers by default.\n"
            "# Remove custom 'tls { protocols ... ciphers ... }' settings."
        ),
        "traefik": "tls:\n  options:\n    default:\n      minVersion: VersionTLS12\n      sniStrict: true",
    }
)

FIXES: dict[str, Fix] = {
    "transport.hsts": Fix(headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}),
    "headers.nosniff": Fix(headers={"X-Content-Type-Options": "nosniff"}),
    "headers.clickjacking": Fix(headers={"X-Frame-Options": "SAMEORIGIN"}),
    "headers.referrer": Fix(headers={"Referrer-Policy": "strict-origin-when-cross-origin"}),
    "headers.permissions": Fix(headers={"Permissions-Policy": "camera=(), microphone=(), geolocation=()"}),
    "nextcloud.headers": Fix(
        headers={"X-Robots-Tag": "noindex, nofollow", "X-Permitted-Cross-Domain-Policies": "none"}
    ),
    "headers.csp": Fix(
        snippets={
            "nginx": N_(
                "# A CSP is application-specific. To test, start with report-only:\n"
                "# add_header Content-Security-Policy-Report-Only \"default-src 'self'\" always;"
            ),
            "apache": N_(
                "# A CSP is application-specific. To test, start with report-only:\n"
                "# Header always set Content-Security-Policy-Report-Only \"default-src 'self'\""
            ),
            "caddy": N_(
                "# A CSP is application-specific. To test, start with report-only:\n"
                "# header Content-Security-Policy-Report-Only \"default-src 'self'\""
            ),
            "traefik": N_(
                "# A CSP is application-specific. To test, start with report-only:\n"
                "# contentSecurityPolicy: \"default-src 'self'\"  (in the headers middleware)"
            ),
        }
    ),
    "headers.disclosure": Fix(
        snippets={
            "nginx": N_("server_tokens off;\n# PHP: expose_php = Off in php.ini"),
            "apache": N_(
                "ServerTokens Prod\nServerSignature Off\nHeader always unset X-Powered-By\n"
                "# PHP: expose_php = Off in php.ini"
            ),
            "caddy": "header {\n\t-Server\n\t-X-Powered-By\n}",
            "traefik": N_(
                '# In the headers middleware under customResponseHeaders:\n#   Server: ""\n#   X-Powered-By: ""'
            ),
        }
    ),
    "transport.http_redirect": Fix(
        snippets={
            "nginx": "server {\n    listen 80;\n    server_name example.com;\n"
            "    return 301 https://$host$request_uri;\n}",
            "apache": "<VirtualHost *:80>\n    ServerName example.com\n"
            "    Redirect permanent / https://example.com/\n</VirtualHost>",
            "caddy": N_(
                "# Caddy redirects HTTP to HTTPS automatically as long as the site\n"
                "# is defined with a domain name (without an http:// prefix)."
            ),
            "traefik": N_(
                '# Static configuration (traefik.yml):\nentryPoints:\n  web:\n    address: ":80"\n'
                "    http:\n      redirections:\n        entryPoint:\n          to: websecure\n          scheme: https"
            ),
        }
    ),
    "tls.legacy_protocols": TLS_FIX,
    "tls.weak_ciphers": TLS_FIX,
    "tls.forward_secrecy": TLS_FIX,
    "transport.trace": Fix(snippets={"apache": "TraceEnable off"}),
    "exposure.sensitive_files": Fix(
        snippets={
            "nginx": "location ~ /\\.(?!well-known) {\n    deny all;\n}",
            "apache": "RedirectMatch 404 /\\.(?!well-known)",
            "caddy": "@hidden path_regexp /\\.(?!well-known)\nrespond @hidden 404",
            "traefik": N_(
                "# Traefik cannot block paths by itself - solve it in the backend web server\n"
                "# or route a higher-priority router rule to a 404 service."
            ),
        }
    ),
    "exposure.directory_listing": Fix(
        snippets={
            "nginx": "autoindex off;",
            "apache": "Options -Indexes",
            "caddy": N_("# Use file_server without 'browse'."),
        }
    ),
    "nextcloud.well_known": Fix(
        snippets={
            "nginx": "location = /.well-known/carddav { return 301 $scheme://$host/remote.php/dav/; }\n"
            "location = /.well-known/caldav  { return 301 $scheme://$host/remote.php/dav/; }",
            "apache": "Redirect 301 /.well-known/carddav /remote.php/dav/\n"
            "Redirect 301 /.well-known/caldav /remote.php/dav/",
            "caddy": "redir /.well-known/carddav /remote.php/dav/ 301\nredir /.well-known/caldav /remote.php/dav/ 301",
            "traefik": "http:\n  middlewares:\n    nextcloud-dav:\n      redirectRegex:\n"
            '        permanent: true\n        regex: "https://(.*)/.well-known/(card|cal)dav"\n'
            '        replacement: "https://${1}/remote.php/dav/"',
        }
    ),
}


def _render_headers(server: str, headers: dict[str, str]) -> str:
    if server == "nginx":
        return "\n".join(f'add_header {k} "{v}" always;' for k, v in headers.items())
    if server == "apache":
        return "\n".join(f'Header always set {k} "{v}"' for k, v in headers.items())
    if server == "caddy":
        lines = "\n".join(f'\t{k} "{v}"' for k, v in headers.items())
        return f"header {{\n{lines}\n}}"
    lines = "\n".join(f'          {k}: "{v}"' for k, v in headers.items())
    return f"http:\n  middlewares:\n    security-headers:\n      headers:\n        customResponseHeaders:\n{lines}"


INTRO = {
    "nginx": N_("# Inside the site's server { ... } block (listen 443 ssl)."),
    "apache": N_("# Inside the <VirtualHost *:443> block; needs mod_headers and mod_ssl."),
    "caddy": N_("# Inside the site block, e.g. example.com { ... }."),
    "traefik": N_(
        "# Dynamic configuration (file provider). Add the middleware to the router:\n"
        "#   middlewares: [security-headers]"
    ),
}


def build_fixes(results: list[CheckResult]) -> dict[str, str]:
    """Server key -> config text. Empty if nothing in the scan can be fixed by config."""
    relevant = [
        FIXES[r.id] for r in results if r.id in FIXES and r.status in (Status.FAIL, Status.WARN) and not r.accepted
    ]
    if not relevant:
        return {}

    headers: dict[str, str] = {}
    for fix in relevant:
        headers.update(fix.headers)

    out = {}
    for server in SERVERS:
        parts = [_(INTRO[server])]
        if headers:
            parts.append(_render_headers(server, headers))
        seen: set[str] = set()
        for fix in relevant:
            snippet = fix.snippets.get(server)
            # Snippets with comments are marked with N_(); others pass through unchanged.
            snippet = _(snippet) if snippet else snippet
            if snippet and snippet not in seen:
                seen.add(snippet)
                parts.append(snippet)
        if len(parts) > 1:
            out[server] = "\n\n".join(parts) + "\n"
    return out
