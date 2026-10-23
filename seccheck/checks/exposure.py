"""Files and endpoints that must never be publicly reachable.

Every probe validates the response body with a signature. Many apps answer
unknown paths with 200 and their HTML shell, so a status code alone would
produce false positives.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass

from ..core.context import HttpResult, ScanContext
from ..core.models import Outcome, Severity, failed, info, passed, warned, worst_severity
from ..core.registry import check
from ..i18n import N_, _


@dataclass(frozen=True)
class Probe:
    path: str
    label: str  # marked with N_(), translated where it is shown
    severity: Severity
    matches: Callable[[HttpResult], bool]


def _ok(r: HttpResult) -> bool:
    return r.status == 200 and not r.is_html


def _contains(*needles: str) -> Callable[[HttpResult], bool]:
    return lambda r: _ok(r) and any(n in r.text for n in needles)


def _regex(pattern: str) -> Callable[[HttpResult], bool]:
    rx = re.compile(pattern, re.MULTILINE)
    return lambda r: _ok(r) and bool(rx.search(r.text))


def _magic(prefix: bytes) -> Callable[[HttpResult], bool]:
    return lambda r: r.status == 200 and r.body.startswith(prefix)


def _html_contains(needle: str) -> Callable[[HttpResult], bool]:
    return lambda r: r.status == 200 and needle in r.text


PROBES: list[Probe] = [
    Probe(".git/HEAD", N_("Git repository"), Severity.CRITICAL, _regex(r"^ref: refs/")),
    Probe(".git/config", N_("Git configuration"), Severity.CRITICAL, _contains("[core]")),
    Probe(".env", N_("Environment variables (.env)"), Severity.CRITICAL, _regex(r"^[A-Z][A-Z0-9_]*=")),
    Probe(".aws/credentials", N_("AWS credentials"), Severity.CRITICAL, _contains("aws_access_key_id")),
    Probe(".htpasswd", N_("Password file (.htpasswd)"), Severity.CRITICAL, _regex(r"^[\w.-]+:(\$|\{SHA\})")),
    Probe("docker-compose.yml", "docker-compose.yml", Severity.HIGH, _regex(r"^services:")),
    Probe("backup.sql", N_("Database dump"), Severity.CRITICAL, _contains("CREATE TABLE", "INSERT INTO")),
    Probe("dump.sql", N_("Database dump"), Severity.CRITICAL, _contains("CREATE TABLE", "INSERT INTO")),
    Probe("backup.zip", N_("Backup archive"), Severity.HIGH, _magic(b"PK\x03\x04")),
    Probe("backup.tar.gz", N_("Backup archive"), Severity.HIGH, _magic(b"\x1f\x8b")),
    Probe(".DS_Store", N_("macOS directory index (.DS_Store)"), Severity.LOW, _magic(b"\x00\x00\x00\x01Bud1")),
    Probe("server-status", "Apache server-status", Severity.MEDIUM, _html_contains("Apache Server Status")),
    Probe("nginx_status", "nginx stub_status", Severity.LOW, _contains("Active connections:")),
    Probe("phpinfo.php", "phpinfo()", Severity.MEDIUM, _html_contains("PHP Version")),
    Probe("info.php", "phpinfo()", Severity.MEDIUM, _html_contains("PHP Version")),
]


@check(
    "exposure.sensitive_files",
    title="No sensitive files reachable",
    category="exposure",
    severity=Severity.HIGH,
    description="Looks for Git repositories, .env files, backups, database dumps and status pages.",
)
async def sensitive_files(ctx: ScanContext) -> Outcome:
    t = ctx.target
    bases = {t.root_url(), t.url()}  # root and app base path, if different

    async def run(base: str, probe: Probe) -> tuple[str, Probe] | None:
        resp = await ctx.try_fetch(base + probe.path)
        return (base + probe.path, probe) if resp and probe.matches(resp) else None

    results = await asyncio.gather(*(run(b, p) for b in sorted(bases) for p in PROBES))
    found = [r for r in results if r]
    tested = len(PROBES) * len(bases)
    if not found:
        return passed(_("None of the {count} checked files is reachable.", count=tested))

    return failed(
        _(
            "{count} sensitive file(s) publicly reachable: {files}.",
            count=len(found),
            files=", ".join(sorted({_(p.label) for _url, p in found})),
        ),
        details=[f"{url} – {_(p.label)}" for url, p in found],
        severity=worst_severity([p.severity for _url, p in found]),
        recommendation=_(
            "Remove the files from the web root or block access in the web server "
            "(e.g. nginx: location ~ /\\. { deny all; }). Rotate any leaked credentials."
        ),
    )


@check(
    "exposure.directory_listing",
    title="No directory listing",
    category="exposure",
    severity=Severity.MEDIUM,
    description="Automatic directory indexes expose files that are not linked anywhere.",
)
async def directory_listing(ctx: ScanContext) -> Outcome:
    resp = await ctx.main_page()
    if re.search(r"<title>\s*Index of /", resp.text, re.IGNORECASE):
        return failed(
            _("The web server shows a directory listing."),
            recommendation=_("Disable directory listing (nginx: autoindex off; Apache: Options -Indexes)."),
        )
    return passed(_("No directory listing on the start page."))


@check(
    "hygiene.security_txt",
    title="security.txt present",
    category="hygiene",
    severity=Severity.INFO,
    description="security.txt (RFC 9116) names a contact for security reports.",
)
async def security_txt(ctx: ScanContext) -> Outcome:
    resp = await ctx.try_fetch(".well-known/security.txt", root=True, follow=True)
    if resp and resp.status == 200 and not resp.is_html and "contact:" in resp.text.lower():
        return passed(_("/.well-known/security.txt is present."))
    if ctx.target.is_ip:
        return info(_("No security.txt found."))
    return warned(
        _("No /.well-known/security.txt found."),
        recommendation=_("Create a security.txt with a Contact field for publicly reachable services."),
        references=["https://securitytxt.org/"],
    )
