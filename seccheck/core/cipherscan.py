"""Full cipher-suite enumeration via sslyze (optional dependency, `pip install -e '.[full]'`).

sslyze ships its own OpenSSL builds (nassl), so it can test SSLv2/SSLv3,
RC4, DES and 3DES even where the system OpenSSL no longer supports them.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

from ..i18n import _

try:
    from sslyze import (
        ScanCommand,
        ScanCommandAttemptStatusEnum,
        Scanner,
        ServerNetworkLocation,
        ServerScanRequest,
        ServerScanStatusEnum,
    )

    AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the installation
    AVAILABLE = False

PROTOCOLS = {
    "SSLv2": "ssl_2_0_cipher_suites",
    "SSLv3": "ssl_3_0_cipher_suites",
    "TLSv1.0": "tls_1_0_cipher_suites",
    "TLSv1.1": "tls_1_1_cipher_suites",
    "TLSv1.2": "tls_1_2_cipher_suites",
    "TLSv1.3": "tls_1_3_cipher_suites",
}

# IANA cipher names, e.g. TLS_RSA_WITH_RC4_128_SHA.
_WEAK = re.compile(r"_NULL_|_anon_|EXPORT|_RC4_|_DES_|3DES|_RC2_|_IDEA_|_MD5$")


@dataclass
class CipherReport:
    # Protocol -> accepted cipher suites (IANA names). Missing = not testable.
    accepted: dict[str, list[str]] = field(default_factory=dict)
    error: str | None = None

    @property
    def protocols(self) -> list[str]:
        return [p for p, ciphers in self.accepted.items() if ciphers]

    def weak(self) -> dict[str, list[str]]:
        return {
            p: [c for c in cs if _WEAK.search(c)] for p, cs in self.accepted.items() if any(_WEAK.search(c) for c in cs)
        }

    def without_forward_secrecy(self) -> dict[str, list[str]]:
        # TLS 1.3 suites are always (EC)DHE; below that only *DHE_* key exchanges are.
        return {
            p: [c for c in cs if "DHE_" not in c]
            for p, cs in self.accepted.items()
            if p != "TLSv1.3" and any("DHE_" not in c for c in cs)
        }


def _scan_sync(host: str, port: int) -> CipherReport:
    commands = {getattr(ScanCommand, attr.upper()) for attr in PROTOCOLS.values()}
    scanner = Scanner()
    scanner.queue_scans(
        [ServerScanRequest(server_location=ServerNetworkLocation(hostname=host, port=port), scan_commands=commands)]
    )
    report = CipherReport()
    for result in scanner.get_results():
        if result.scan_status != ServerScanStatusEnum.COMPLETED or result.scan_result is None:
            report.error = _("sslyze could not connect ({status})", status=result.scan_status.name)
            return report
        for label, attr in PROTOCOLS.items():
            attempt = getattr(result.scan_result, attr)
            if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                report.accepted[label] = [c.cipher_suite.name for c in attempt.result.accepted_cipher_suites]
    return report


async def scan_ciphers(host: str, port: int) -> CipherReport:
    if not AVAILABLE:
        return CipherReport(error=_("sslyze is not installed"))
    return await asyncio.to_thread(_scan_sync, host, port)
