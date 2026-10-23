"""Low-level TLS probing: handshakes, protocol/cipher support, certificate parsing."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import ssl
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .. import config
from ..i18n import N_, _

PROTOCOLS: dict[str, ssl.TLSVersion] = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

# OpenSSL cipher strings for cipher classes that must not be offered.
# Labels with words are marked with N_() and translated where they are shown.
WEAK_CIPHERS: dict[str, str] = {
    N_("NULL (no encryption)"): "eNULL",
    N_("Anonymous (no authentication)"): "aNULL",
    "EXPORT": "EXP",
    "RC4": "RC4",
    "DES": "DES",
    "3DES": "3DES",
}
NO_FORWARD_SECRECY = "kRSA"

# Errors raised by the local OpenSSL before anything reached the server.
_LOCAL_REFUSALS = {"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_CIPHER_MATCH"}


@dataclass
class Handshake:
    ok: bool
    error: str | None = None
    verify_failed: bool = False
    # The handshake failed because the server spoke TLS but refused our offer.
    rejected: bool = False
    # Network-level failure (reset, timeout) that may succeed on retry.
    transient: bool = False
    protocol: str | None = None
    cipher: str | None = None
    cert_der: bytes | None = None
    chain_der: list[bytes] = field(default_factory=list)


def make_context(
    *,
    verify: bool,
    min_version: ssl.TLSVersion | None = None,
    max_version: ssl.TLSVersion | None = None,
    ciphers: str | None = None,
) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context(cafile=config.CA_BUNDLE)
        # Hostname matching is checked separately so chain trust and name
        # mismatch can be reported as two findings.
        ctx.check_hostname = False
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if min_version is not None:
        ctx.minimum_version = min_version
    if max_version is not None:
        ctx.maximum_version = max_version
    if ciphers is not None:
        ctx.set_ciphers(ciphers)
    return ctx


def legacy_context(
    version: ssl.TLSVersion | None = None, ciphers: str = "ALL", *, verify: bool = False
) -> ssl.SSLContext:
    """Context that allows legacy protocols/ciphers, for probing only."""
    ctx = make_context(verify=verify)
    ctx.minimum_version = version or ssl.TLSVersion.TLSv1
    ctx.maximum_version = version or ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(f"{ciphers}:@SECLEVEL=0")
    return ctx


def _sni(host: str) -> str | None:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return None


def _describe(exc: BaseException) -> str:
    if isinstance(exc, TimeoutError):
        return _("Timeout")
    if isinstance(exc, ConnectionRefusedError):
        return _("Connection refused")
    if isinstance(exc, OSError) and exc.strerror:
        return exc.strerror
    return str(exc) or type(exc).__name__


async def handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float = 8.0) -> Handshake:
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=_sni(host) or ""),
            timeout,
        )
    except ssl.SSLCertVerificationError as exc:
        return Handshake(ok=False, verify_failed=True, error=exc.verify_message or str(exc))
    except ssl.SSLError as exc:
        reason = exc.reason or str(exc)
        return Handshake(ok=False, error=reason, rejected=reason not in _LOCAL_REFUSALS)
    except ConnectionResetError as exc:
        # Some servers simply drop the connection instead of sending an alert.
        return Handshake(ok=False, error=_describe(exc), rejected=True, transient=True)
    except (OSError, TimeoutError) as exc:
        return Handshake(ok=False, error=_describe(exc), transient=True)

    try:
        sslobj = writer.get_extra_info("ssl_object")
        cipher = sslobj.cipher()
        chain: list[bytes] = []
        with contextlib.suppress(Exception):
            chain = [bytes(c) for c in sslobj.get_unverified_chain() or []]
        return Handshake(
            ok=True,
            protocol=sslobj.version(),
            cipher=cipher[0] if cipher else None,
            cert_der=sslobj.getpeercert(binary_form=True),
            chain_der=chain,
        )
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 2)


@dataclass
class TlsInfo:
    host: str
    port: int
    reachable: bool
    error: str | None = None
    trusted: bool = False
    verify_error: str | None = None
    protocol: str | None = None
    cipher: str | None = None
    cert: x509.Certificate | None = None
    chain: list[x509.Certificate] = field(default_factory=list)


async def _handshake_retry(host: str, port: int, ctx: ssl.SSLContext) -> Handshake:
    hs = await handshake(host, port, ctx)
    if not hs.ok and hs.transient:
        await asyncio.sleep(0.5)
        hs = await handshake(host, port, ctx)
    return hs


async def gather_tls_info(host: str, port: int) -> TlsInfo:
    verified = await _handshake_retry(host, port, make_context(verify=True))
    if not verified.ok and not verified.verify_failed:
        # Maybe the server only speaks legacy TLS that our default context refuses.
        legacy = await _handshake_retry(host, port, legacy_context(verify=True))
        if legacy.ok or legacy.verify_failed:
            verified = legacy

    if verified.ok:
        hs, trusted, verify_error = verified, True, None
    elif verified.verify_failed:
        hs = await _handshake_retry(host, port, make_context(verify=False))
        if not hs.ok:
            hs = await _handshake_retry(host, port, legacy_context())
        trusted, verify_error = False, verified.error
    else:
        return TlsInfo(host=host, port=port, reachable=False, error=verified.error)

    if not hs.ok:
        return TlsInfo(host=host, port=port, reachable=False, error=hs.error)

    cert = x509.load_der_x509_certificate(hs.cert_der) if hs.cert_der else None
    chain = []
    for der in hs.chain_der:
        with contextlib.suppress(ValueError):
            chain.append(x509.load_der_x509_certificate(der))
    return TlsInfo(
        host=host,
        port=port,
        reachable=True,
        trusted=trusted,
        verify_error=verify_error,
        protocol=hs.protocol,
        cipher=hs.cipher,
        cert=cert,
        chain=chain,
    )


async def probe_protocols(host: str, port: int) -> dict[str, bool | None]:
    """True = accepted, False = refused by server, None = could not be tested."""

    async def probe(version: ssl.TLSVersion) -> bool | None:
        try:
            if version >= ssl.TLSVersion.TLSv1_2:
                ctx = make_context(verify=False, min_version=version, max_version=version)
            else:
                ctx = legacy_context(version)
        except (ssl.SSLError, ValueError):
            return None
        hs = await handshake(host, port, ctx)
        if hs.ok:
            return True
        return False if hs.rejected else None

    names = list(PROTOCOLS)
    results = await asyncio.gather(*(probe(PROTOCOLS[n]) for n in names))
    return dict(zip(names, results, strict=True))


async def probe_ciphers(host: str, port: int, cipher_specs: dict[str, str]) -> dict[str, bool | None]:
    async def probe(spec: str) -> bool | None:
        try:
            ctx = legacy_context(ciphers=spec)
        except ssl.SSLError:
            return None  # cipher class not compiled into the local OpenSSL
        hs = await handshake(host, port, ctx)
        if hs.ok:
            return True
        return False if hs.rejected else None

    labels = list(cipher_specs)
    results = await asyncio.gather(*(probe(cipher_specs[label]) for label in labels))
    return dict(zip(labels, results, strict=True))


# --- certificate helpers -----------------------------------------------------


def san_names(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return [], []
    dns = san.get_values_for_type(x509.DNSName)
    ips = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    return dns, ips


def hostname_matches(cert: x509.Certificate, host: str) -> bool:
    dns, ips = san_names(cert)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return str(ip) in ips
    host = host.lower().rstrip(".")
    for name in dns:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        # Wildcards match exactly one left-most label (RFC 6125).
        if name.startswith("*.") and "." in name[2:]:
            label, _sep, rest = host.partition(".")
            if label and rest == name[2:]:
                return True
    return False


def name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else None


def short_name(name: x509.Name) -> str:
    cn = name_attr(name, x509.NameOID.COMMON_NAME)
    org = name_attr(name, x509.NameOID.ORGANIZATION_NAME)
    if cn and org:
        return f"{cn} ({org})"
    return cn or org or name.rfc4514_string() or "?"


def is_self_signed(cert: x509.Certificate) -> bool:
    return cert.issuer == cert.subject


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()
