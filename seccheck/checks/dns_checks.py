"""DNS checks."""

from __future__ import annotations

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..core.context import ScanContext
from ..core.models import Outcome, Severity, SkipCheck, passed, warned
from ..core.registry import check
from ..i18n import _


async def _caa_records(domain: str) -> tuple[str, list[str]] | None:
    """CAA lookup climbs the tree until a record set is found (RFC 8659)."""
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        try:
            answer = await dns.asyncresolver.resolve(name, "CAA", lifetime=5)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        return name, [r.to_text() for r in answer]
    return None


@check(
    "dns.caa",
    title="CAA record",
    category="dns",
    severity=Severity.LOW,
    description="CAA records define which CAs may issue certificates for the domain.",
)
async def caa(ctx: ScanContext) -> Outcome:
    host = ctx.target.host
    if ctx.target.is_ip or "." not in host:
        raise SkipCheck(_("Only relevant for domain names."))
    try:
        found = await _caa_records(host)
    except dns.exception.DNSException as exc:
        raise SkipCheck(_("DNS lookup failed: {error}", error=exc)) from exc
    if found is None:
        return warned(
            _("No CAA record set – any CA may issue certificates for this domain."),
            recommendation=_('Create a CAA record, e.g. example.com. CAA 0 issue "letsencrypt.org"'),
            references=["https://letsencrypt.org/docs/caa/"],
        )
    name, records = found
    return passed(_("CAA record present on {name}.", name=name), details=records)
