from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from seccheck.core.models import CheckResult, Severity, Status
from seccheck.core.registry import CATEGORIES, all_apps, all_checks, all_detectors, checks_for
from seccheck.core.scoring import compute_rating
from seccheck.core.target import TargetError, parse_target
from seccheck.core.tls import hostname_matches
from seccheck.core.versions import assess_latest, parse_version

# --- target -------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, url, tls_port",
    [
        ("cloud.example.com", "https://cloud.example.com/", 443),
        ("https://cloud.example.com/nextcloud", "https://cloud.example.com/nextcloud/", 443),
        ("https://cloud.example.com/index.php/login?x=1", "https://cloud.example.com/", 443),
        ("https://Cloud.Example.com:8443/nc/index.php/apps/files", "https://cloud.example.com:8443/nc/", 8443),
        ("http://192.168.1.10:8080", "http://192.168.1.10:8080/", 443),
        ("https://[::1]:8443/", "https://[::1]:8443/", 8443),
    ],
)
def test_parse_target(raw: str, url: str, tls_port: int) -> None:
    target = parse_target(raw)
    assert target.url() == url
    assert target.tls_port == tls_port


def test_parse_target_root_and_http_urls() -> None:
    target = parse_target("https://example.com:8443/nextcloud/")
    assert target.root_url(".well-known/caldav") == "https://example.com:8443/.well-known/caldav"
    assert target.plain_http_url() == "http://example.com/nextcloud/"


@pytest.mark.parametrize("raw", ["", "ftp://example.com", "https://user:pw@example.com", "https://:80"])
def test_parse_target_rejects(raw: str) -> None:
    with pytest.raises(TargetError):
        parse_target(raw)


# --- registry -----------------------------------------------------------------


def test_registry_is_consistent() -> None:
    checks = all_checks()
    assert len({c.id for c in checks}) == len(checks)
    assert all(c.category in CATEGORIES for c in checks)
    app_ids = {a.id for a in all_apps()}
    for spec in checks:
        assert spec.apps is None or spec.apps <= app_ids, spec.id
        assert spec.description, f"{spec.id} has no description"


def test_every_app_has_a_detector() -> None:
    missing = {a.id for a in all_apps()} - {"generic"} - set(all_detectors())
    assert not missing, f"Apps without @detector: {missing}"


def test_app_specific_checks_only_run_for_their_app() -> None:
    by_id = {a.id: a for a in all_apps()}
    nextcloud = {c.id for c in checks_for(by_id["nextcloud"])}
    generic = {c.id for c in checks_for(by_id["generic"])}
    assert "nextcloud.data_dir" in nextcloud
    assert "nextcloud.data_dir" not in generic
    assert "tls.cert_expiry" in nextcloud and "tls.cert_expiry" in generic


# --- scoring ------------------------------------------------------------------


def _result(status: Status, severity: Severity, category: str = "tls") -> CheckResult:
    return CheckResult(
        id=f"x.{status}.{severity}", title="t", category=category, status=status, severity=severity, summary=""
    )


def test_perfect_score() -> None:
    rating = compute_rating([_result(Status.PASS, Severity.HIGH), _result(Status.INFO, Severity.INFO)])
    assert rating.score == 100 and rating.grade == "A+" and not rating.caps


def test_warnings_count_half() -> None:
    rating = compute_rating([_result(Status.WARN, Severity.MEDIUM), _result(Status.FAIL, Severity.LOW)])
    assert rating.score == 100 - 4 - 3
    assert rating.grade == "A"


def test_critical_failure_caps_grade() -> None:
    results = [_result(Status.FAIL, Severity.CRITICAL)] + [_result(Status.PASS, Severity.LOW)] * 5
    rating = compute_rating(results)
    assert rating.score == 60
    assert rating.grade == "F"
    assert rating.caps


def test_high_failure_caps_at_c() -> None:
    rating = compute_rating([_result(Status.FAIL, Severity.HIGH)])
    assert rating.score == 80
    assert rating.grade == "C"


def test_skips_and_errors_do_not_count() -> None:
    rating = compute_rating([_result(Status.SKIP, Severity.CRITICAL), _result(Status.ERROR, Severity.CRITICAL)])
    assert rating.score == 100


# --- versions -----------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, parsed",
    [
        ("31.0.5", (31, 0, 5)),
        ("v10.10.7", (10, 10, 7)),
        ("11.0.1+gitea-1.22.0", (11, 0, 1)),
        ("1.23.0-rc1", (1, 23, 0)),
    ],
)
def test_parse_version(raw: str, parsed: tuple[int, ...]) -> None:
    assert parse_version(raw) == parsed


def test_assess_latest() -> None:
    assert assess_latest("X", "1.2.3", "1.2.3").status == Status.PASS
    patch = assess_latest("X", "1.2.1", "1.2.3")
    assert patch.status == Status.FAIL and patch.severity == Severity.MEDIUM
    minor = assess_latest("X", "1.1.9", "1.2.0")
    assert minor.status == Status.FAIL and minor.severity == Severity.HIGH


# --- certificates -------------------------------------------------------------


def _cert(*names: str) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, names[0])])
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .sign(key, hashes.SHA256())
    )


def test_hostname_matching() -> None:
    cert = _cert("example.com", "*.example.com")
    assert hostname_matches(cert, "example.com")
    assert hostname_matches(cert, "cloud.example.com")
    assert hostname_matches(cert, "CLOUD.example.com.")
    assert not hostname_matches(cert, "a.b.example.com")  # wildcard covers one label only
    assert not hostname_matches(cert, "example.org")
    assert not hostname_matches(cert, "notexample.com")


# --- advisories ---------------------------------------------------------------

from seccheck.core.advisories import in_range, is_affected


@pytest.mark.parametrize(
    "version, vulnerable, patched, expected",
    [
        # Nextcloud: branch list of lower bounds, one fix per branch
        ("33.0.2", ">= 32.0.0, >= 33.0.0, >= 34.0.0", "32.0.12, 33.0.6, 34.0.1", True),
        ("33.0.6", ">= 32.0.0, >= 33.0.0, >= 34.0.0", "32.0.12, 33.0.6, 34.0.1", False),
        ("35.0.2", ">= 32.0.0, >= 33.0.0, >= 34.0.0", "32.0.12, 33.0.6, 34.0.1", False),
        ("31.0.9", ">= 32.0.0, >= 33.0.0", "32.0.12, 33.0.6", False),
        # Vaultwarden: unicode operator, AND-range
        ("1.36.0", "≤ 1.36.0", "1.37.0", True),
        ("1.37.0", "≤ 1.36.0", "1.37.0", False),
        ("1.36.0", ">1.36.0, < 1.37.0", "1.37.0", False),
        # Jellyfin: older branch without its own fix
        ("10.11.3", "< 12.0", "12.0", True),
        # Immich: exact vulnerable version
        ("3.2.2", "v3.2.2", "v3.2.4", True),
        ("3.2.3", "v3.2.2", "v3.2.4", False),
        # Gitea: older minor branch, fixed only in newer minor
        ("1.21.5", "<= 1.22.0", "1.22.1", True),
        ("1.21.7", "<= 1.22.0", "1.21.6, 1.22.1", False),
        # No fix known: range decides
        ("3.1.0", "<= v3.1.0", None, True),
        ("3.1.0", "", None, None),
    ],
)
def test_is_affected(version: str, vulnerable: str, patched: str | None, expected: bool | None) -> None:
    assert is_affected(parse_version(version), vulnerable, patched) is expected


def test_in_range_unparseable() -> None:
    assert in_range((1, 0), "all versions") is None


# --- cipher classification ----------------------------------------------------

from seccheck.core.cipherscan import CipherReport


def test_cipher_report_classification() -> None:
    report = CipherReport(
        accepted={
            "TLSv1.2": [
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_WITH_RC4_128_SHA",
                "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            ],
            "TLSv1.3": ["TLS_AES_128_GCM_SHA256"],
            "SSLv3": [],
        }
    )
    assert report.protocols == ["TLSv1.2", "TLSv1.3"]
    assert report.weak() == {"TLSv1.2": ["TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"]}
    assert report.without_forward_secrecy() == {
        "TLSv1.2": ["TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"]
    }


def test_assess_branches_lts_and_sts() -> None:
    from datetime import date

    from seccheck.core.versions import assess_branches

    today = date(2026, 10, 23)
    releases = [
        ("2.45.0", date(2026, 9, 1)),
        ("2.39.8", date(2026, 9, 20)),  # LTS patch released after the newer STS
        ("2.39.7", date(2026, 6, 1)),
        ("2.33.9", date(2025, 11, 1)),
    ]
    lts = assess_branches("Portainer", "2.39.8", releases, today=today)
    assert lts.status == Status.PASS
    behind = assess_branches("Portainer", "2.39.7", releases, today=today)
    assert behind.status == Status.FAIL and behind.severity == Severity.MEDIUM
    stale = assess_branches("Portainer", "2.33.9", releases, today=today)
    assert stale.status == Status.FAIL and stale.severity == Severity.HIGH
    assert assess_branches("Portainer", "2.45.0", releases, today=today).status == Status.PASS
