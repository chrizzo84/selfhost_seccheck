"""Fallback profile: only the generic checks."""

from ..core.registry import AppProfile, register_app

register_app(
    AppProfile(
        id="generic",
        name="Other web application",
        short="WEB",
        color="#64748b",
        description="Basic checks for any web application: TLS, certificate, headers, exposed files.",
        url_hint="https://app.example.com",
        order=999,
    )
)
