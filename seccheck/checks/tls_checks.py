"""TLS and certificate checks."""

from __future__ import annotations

from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from ..core import cipherscan
from ..core import tls as tlslib
from ..core.context import ScanContext
from ..core.models import Outcome, Severity, failed, info, passed, warned
from ..core.registry import check
from ..i18n import N_, _

# sslyze needs ~30 s for a full enumeration.
SSLYZE_TIMEOUT = 120.0

PROXY_HINT = N_("The easiest fix is a reverse proxy such as Caddy, Traefik or nginx with a Let's Encrypt certificate.")


async def _protocols(ctx: ScanContext) -> dict[str, bool | None]:
    t = await ctx.require_tls()
    return await ctx.memo("tls:protocols", lambda: tlslib.probe_protocols(t.host, t.port))


@check(
    "tls.https",
    title="HTTPS available",
    category="tls",
    severity=Severity.CRITICAL,
    description="The instance must be reachable encrypted over HTTPS.",
)
async def https_available(ctx: ScanContext) -> Outcome:
    t = ctx.target
    tls = await ctx.tls()
    if t.is_https:
        if tls.reachable:
            return passed(
                _("TLS connection established ({protocol}, {cipher}).", protocol=tls.protocol, cipher=tls.cipher)
            )
        return failed(
            _("No TLS handshake possible on port {port}: {error}", port=tls.port, error=tls.error),
            recommendation=_(PROXY_HINT),
        )
    if tls.reachable:
        return failed(
            _("The given URL uses unencrypted HTTP although HTTPS is available on port 443."),
            recommendation=_("Open the instance via {url} and redirect HTTP to HTTPS.", url=t.https_url()),
        )
    return failed(
        _(
            "The instance is only reachable over unencrypted HTTP. Passwords and "
            "session cookies are transmitted in plain text."
        ),
        recommendation=_(PROXY_HINT),
    )


@check(
    "tls.cert_info",
    title="Certificate details",
    category="tls",
    severity=Severity.INFO,
    description="Overview of the certificate served.",
)
async def cert_info(ctx: ScanContext) -> Outcome:
    tls = await ctx.require_tls()
    cert = tls.cert
    assert cert is not None
    dns, ips = tlslib.san_names(cert)
    key = cert.public_key()
    details = {
        _("Subject"): tlslib.short_name(cert.subject),
        _("Issuer"): tlslib.short_name(cert.issuer),
        _("Valid from"): cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M UTC"),
        _("Valid until"): cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC"),
        _("Alternative names"): ", ".join(dns + ips) or "–",
        _("Key"): _describe_key(key),
        _("Signature"): cert.signature_algorithm_oid._name,
        _("Serial number"): format(cert.serial_number, "X"),
        "SHA-256": tlslib.fingerprint(cert),
        _("Certificates in chain"): str(len(tls.chain)),
        _("Protocol"): tls.protocol or "?",
        "Cipher": tls.cipher or "?",
    }
    return info(
        _(
            "{subject}, issued by {issuer}.",
            subject=tlslib.short_name(cert.subject),
            issuer=tlslib.short_name(cert.issuer),
        ),
        details=details,
    )


@check(
    "tls.cert_trusted",
    title="Certificate chain trusted",
    category="tls",
    severity=Severity.CRITICAL,
    description="The certificate must come from a trusted CA and the chain must be complete.",
)
async def cert_trusted(ctx: ScanContext) -> Outcome:
    tls = await ctx.require_tls()
    assert tls.cert is not None
    if tls.trusted:
        return passed(_("Chain valid, issued by {issuer}.", issuer=tlslib.short_name(tls.cert.issuer)))

    error = tls.verify_error or _("unknown error")
    lowered = error.lower()
    if tlslib.is_self_signed(tls.cert) or "self-signed" in lowered or "self signed" in lowered:
        reason = _("The certificate is self-signed.")
    elif "local issuer" in lowered:
        reason = _("The issuing CA is unknown or the server does not send the intermediate certificate.")
    elif "expired" in lowered:
        reason = _("A certificate in the chain has expired.")
    else:
        reason = _("The certificate chain could not be verified.")
    return failed(
        f"{reason} ({error})",
        details={_("Issuer"): tlslib.short_name(tls.cert.issuer), _("Error"): error},
        recommendation=_(
            "Use a certificate from a public CA (e.g. Let's Encrypt) and serve the "
            "full chain (fullchain.pem). For an internal CA, the scanner can trust "
            "your CA via SECCHECK_CA_BUNDLE."
        ),
    )


@check(
    "tls.cert_hostname",
    title="Certificate matches the hostname",
    category="tls",
    severity=Severity.CRITICAL,
    description="The hostname must be listed in the certificate's Subject Alternative Names.",
)
async def cert_hostname(ctx: ScanContext) -> Outcome:
    tls = await ctx.require_tls()
    assert tls.cert is not None
    dns, ips = tlslib.san_names(tls.cert)
    names = dns + ips
    if tlslib.hostname_matches(tls.cert, ctx.target.host):
        return passed(_("{host} is included in the certificate.", host=ctx.target.host), details={_("Names"): names})
    return failed(
        _("The certificate is not valid for {host}.", host=ctx.target.host),
        details={_("Names in certificate"): names or [_("(no SAN entries)")]},
        recommendation=_("Issue a certificate that contains the hostname as a Subject Alternative Name."),
    )


@check(
    "tls.cert_expiry",
    title="Certificate valid and not about to expire",
    category="tls",
    severity=Severity.CRITICAL,
    description="Expired or soon-to-expire certificates cause errors and point to missing auto-renewal.",
)
async def cert_expiry(ctx: ScanContext) -> Outcome:
    tls = await ctx.require_tls()
    cert = tls.cert
    assert cert is not None
    now = datetime.now(UTC)
    not_before, not_after = cert.not_valid_before_utc, cert.not_valid_after_utc
    remaining = (not_after - now).total_seconds() / 86400
    lifetime = max(1.0, (not_after - not_before).total_seconds() / 86400)
    details = {
        _("Valid until"): not_after.strftime("%Y-%m-%d %H:%M UTC"),
        _("Days remaining"): int(remaining),
        _("Lifetime (days)"): int(lifetime),
    }

    if now < not_before:
        return failed(_("The certificate is only valid from {date}.", date=f"{not_before:%Y-%m-%d}"), details=details)
    if remaining < 0:
        return failed(
            _("The certificate expired {days} day(s) ago.", days=int(-remaining)),
            details=details,
            recommendation=_("Renew the certificate and set up automatic renewal (ACME)."),
        )
    # Thresholds scale with the lifetime: 45/90-day ACME certs are renewed
    # with far fewer days left than 1-year certificates.
    if remaining < min(7.0, lifetime * 0.08):
        return failed(
            _("The certificate expires in {days} days.", days=f"{remaining:.1f}"),
            details=details,
            severity=Severity.HIGH,
            recommendation=_("Renew the certificate immediately and check why auto-renewal is not working."),
        )
    if remaining < min(30.0, lifetime * 0.2):
        return warned(
            _("The certificate expires in {days} days.", days=int(remaining)),
            details=details,
            severity=Severity.MEDIUM,
            recommendation=_("Check that automatic renewal works."),
        )
    return passed(
        _("Valid until {date} ({days} days left).", date=f"{not_after:%Y-%m-%d}", days=int(remaining)),
        details=details,
    )


def _describe_key(key: object) -> str:
    if isinstance(key, rsa.RSAPublicKey):
        return _("RSA {bits} bit", bits=key.key_size)
    if isinstance(key, ec.EllipticCurvePublicKey):
        return _("ECDSA {curve} ({bits} bit)", curve=key.curve.name, bits=key.key_size)
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(key, dsa.DSAPublicKey):
        return _("DSA {bits} bit", bits=key.key_size)
    return type(key).__name__


@check(
    "tls.cert_key",
    title="Certificate key strength",
    category="tls",
    severity=Severity.HIGH,
    description="RSA keys need at least 2048 bits, EC keys at least 256 bits.",
)
async def cert_key(ctx: ScanContext) -> Outcome:
    tls = await ctx.require_tls()
    assert tls.cert is not None
    key = tls.cert.public_key()
    desc = _describe_key(key)
    weak = (
        (isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048)
        or (isinstance(key, ec.EllipticCurvePublicKey) and key.key_size < 256)
        or isinstance(key, dsa.DSAPublicKey)
    )
    if weak:
        return failed(
            _("Weak key: {key}.", key=desc),
            recommendation=_("Generate a new certificate with RSA ≥ 2048 bits or ECDSA P-256."),
        )
    return passed(f"{desc}.")


@check(
    "tls.cert_signature",
    title="Signature algorithm",
    category="tls",
    severity=Severity.HIGH,
    description="MD5 and SHA-1 signatures are considered broken.",
)
async def cert_signature(ctx: ScanContext) -> Outcome:
    tls = await ctx.require_tls()
    assert tls.cert is not None
    algo = tls.cert.signature_hash_algorithm
    name = tls.cert.signature_algorithm_oid._name
    if algo is not None and algo.name.lower() in {"md5", "sha1"}:
        return failed(
            _("Insecure signature algorithm: {algorithm}.", algorithm=name),
            recommendation=_("Reissue the certificate."),
        )
    return passed(f"{name}.")


async def _sslyze(ctx: ScanContext) -> cipherscan.CipherReport | None:
    """Full sslyze enumeration if installed, else None (fall back to OpenSSL probes)."""
    if not cipherscan.AVAILABLE:
        return None
    t = await ctx.require_tls()
    report = await ctx.memo("tls:sslyze", lambda: cipherscan.scan_ciphers(t.host, t.port))
    return None if report.error else report


MOZILLA = ["https://ssl-config.mozilla.org/"]


@check(
    "tls.legacy_protocols",
    title="Outdated TLS versions disabled",
    category="tls",
    severity=Severity.HIGH,
    description="SSLv2/v3, TLS 1.0 and 1.1 are deprecated (RFC 8996) and should not be offered.",
    timeout=SSLYZE_TIMEOUT,
)
async def legacy_protocols(ctx: ScanContext) -> Outcome:
    protocols: dict[str, bool | None] = dict(await _protocols(ctx))
    if report := await _sslyze(ctx):
        # sslyze also covers SSLv2/SSLv3; keep the OpenSSL probe where it could not test.
        protocols = {
            name: bool(report.accepted[name]) if name in report.accepted else protocols.get(name)
            for name in cipherscan.PROTOCOLS
        }
    labels = {True: _("enabled"), False: _("disabled"), None: _("not testable")}
    details = {name: labels[value] for name, value in protocols.items()}
    old = [v for v in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1") if v in protocols]
    legacy = [v for v in old if protocols.get(v)]
    if legacy:
        return failed(
            _("Server accepts {protocols}.", protocols=", ".join(legacy)),
            details=details,
            recommendation=_("Allow only TLS 1.2 and 1.3, e.g. nginx: ssl_protocols TLSv1.2 TLSv1.3;"),
            references=MOZILLA,
        )
    if all(protocols.get(v) is None for v in old):
        return info(_("Outdated protocols could not be tested with the local OpenSSL version."), details=details)
    return passed(_("{protocols} are disabled.", protocols=", ".join(old)), details=details)


@check(
    "tls.tls13",
    title="TLS 1.3 supported",
    category="tls",
    severity=Severity.LOW,
    description="TLS 1.3 is faster and only offers secure ciphers.",
)
async def tls13(ctx: ScanContext) -> Outcome:
    protocols = await _protocols(ctx)
    if protocols.get("TLSv1.3"):
        return passed(_("TLS 1.3 is offered."))
    if protocols.get("TLSv1.3") is None:
        return info(_("TLS 1.3 could not be tested."))
    return warned(
        _("TLS 1.3 is not offered."),
        recommendation=_("Enable TLS 1.3 in the web server or reverse proxy."),
    )


async def _cipher_probe(ctx: ScanContext, key: str, specs: dict[str, str]) -> dict[str, bool | None] | None:
    """None if the server does not speak TLS <= 1.2 at all (then only TLS 1.3 ciphers exist)."""
    protocols = await _protocols(ctx)
    if not any(protocols.get(v) for v in ("TLSv1.0", "TLSv1.1", "TLSv1.2")):
        return None
    t = await ctx.require_tls()
    return await ctx.memo(key, lambda: tlslib.probe_ciphers(t.host, t.port, specs))


def _cipher_details(found: dict[str, list[str]]) -> dict[str, str]:
    return {proto: ", ".join(ciphers) for proto, ciphers in found.items()}


@check(
    "tls.weak_ciphers",
    title="No insecure ciphers",
    category="tls",
    severity=Severity.HIGH,
    description="NULL, export, RC4, DES and 3DES ciphers must not be offered.",
    timeout=SSLYZE_TIMEOUT,
)
async def weak_ciphers(ctx: ScanContext) -> Outcome:
    rec = _("Configure ciphers according to Mozilla 'intermediate'.")
    if report := await _sslyze(ctx):
        weak = report.weak()
        if weak:
            names = sorted({c for cs in weak.values() for c in cs})
            return failed(
                _("{count} insecure cipher(s) accepted.", count=len(names)),
                details=_cipher_details(weak),
                recommendation=rec,
                references=MOZILLA,
            )
        counts = {p: _("{count} cipher(s) accepted", count=len(cs)) for p, cs in report.accepted.items() if cs}
        return passed(_("No insecure ciphers accepted (full check with sslyze)."), details=counts)

    result = await _cipher_probe(ctx, "tls:weak_ciphers", tlslib.WEAK_CIPHERS)
    if result is None:
        return passed(_("Only TLS 1.3 is enabled – it offers secure ciphers only."))
    labels = {True: _("accepted"), False: _("rejected"), None: _("not testable locally")}
    # Cipher class labels are marked with N_() in core.tls.
    details = {_(name): labels[v] for name, v in result.items()}
    accepted = [_(name) for name, v in result.items() if v]
    if accepted:
        return failed(
            _("Insecure ciphers accepted: {ciphers}.", ciphers=", ".join(accepted)),
            details=details,
            recommendation=rec,
            references=MOZILLA,
        )
    untested = [name for name, v in result.items() if v is None]
    if untested:
        return passed(
            _(
                "None of the tested insecure ciphers is accepted ({count} classes not testable "
                "locally, install sslyze for a full check).",
                count=len(untested),
            ),
            details=details,
        )
    return passed(_("None of the tested insecure ciphers is accepted."), details=details)


@check(
    "tls.forward_secrecy",
    title="Forward secrecy",
    category="tls",
    severity=Severity.MEDIUM,
    description="Ciphers with static RSA key exchange allow recorded connections to be decrypted later.",
    timeout=SSLYZE_TIMEOUT,
)
async def forward_secrecy(ctx: ScanContext) -> Outcome:
    rec = _("Allow only ECDHE/DHE ciphers (Mozilla 'intermediate').")
    if report := await _sslyze(ctx):
        missing = report.without_forward_secrecy()
        if missing:
            return failed(
                _("Server accepts ciphers without forward secrecy (static RSA key exchange)."),
                details=_cipher_details(missing),
                recommendation=rec,
                references=MOZILLA,
            )
        return passed(_("All accepted ciphers use (EC)DHE key exchange."))

    result = await _cipher_probe(ctx, "tls:kRSA", {"kRSA": tlslib.NO_FORWARD_SECRECY})
    if result is None:
        return passed(_("Only TLS 1.3 is enabled – forward secrecy is always provided."))
    if result["kRSA"] is None:
        return info(_("RSA key exchange could not be tested locally."))
    if result["kRSA"]:
        return failed(
            _("Server accepts ciphers without forward secrecy (static RSA key exchange)."),
            recommendation=rec,
            references=MOZILLA,
        )
    return passed(_("All ciphers use (EC)DHE key exchange."))
