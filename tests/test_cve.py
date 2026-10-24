"""CVE feed: version matching, source normalization, merging, alerts and API."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from seccheck import notify
from seccheck import store as store_module
from seccheck.core.models import CheckResult, Severity, Status
from seccheck.core.registry import get_app, load_plugins
from seccheck.cve import feed, sources
from seccheck.cve.catalog import PRODUCTS, product_for
from seccheck.cve.matching import assess, evaluate, merge
from seccheck.i18n import language
from seccheck.store import Store

load_plugins()


@pytest.fixture
def store() -> Store:
    return Store(":memory:")


def span(low: str | None, high: str | None, to_incl: bool = False) -> dict[str, Any]:
    return {"type": "span", "from": low, "from_incl": True, "to": high, "to_incl": to_incl}


def entry(vuln_id: str, ranges: list[dict[str, Any]], **fields: Any) -> dict[str, Any]:
    return {
        "id": vuln_id,
        "aliases": [],
        "summary": f"summary of {vuln_id}",
        "description": "",
        "severity": "high",
        "cvss": None,
        "published": "2026-01-01T00:00:00Z",
        "modified": "2026-01-01T00:00:00Z",
        "url": f"https://example.org/{vuln_id}",
        "ranges": ranges,
        "withdrawn": False,
        **fields,
    }


# --- catalog ----------------------------------------------------------------------


def test_catalog_is_consistent() -> None:
    ids = [p.id for p in PRODUCTS]
    assert len(ids) == len(set(ids))
    for product in PRODUCTS:
        assert product.sources, product.id
        if product.app:
            assert get_app(product.app) is not None, product.id


def test_product_for_app_and_detection() -> None:
    assert product_for("nextcloud").id == "nextcloud"
    assert product_for("gitea", "Forgejo").id == "forgejo"
    assert product_for("gitea", "Gitea").id == "gitea"
    assert product_for("generic") is None


# --- matching ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("version", "ranges", "expected"),
    [
        ("1.2.3", [span("1.0", "1.2.4")], (True, "1.2.4")),
        ("1.2.4", [span("1.0", "1.2.4")], (False, None)),
        ("0.9", [span("1.0", "1.2.4")], (False, None)),
        ("1.2.4", [span("0", "1.2.4", to_incl=True)], (True, None)),
        ("5.0", [span(None, None)], (True, None)),
        ("2.1.0", [span("1.0", "1.5"), span("2.0", "2.1.1")], (True, "2.1.1")),
        ("1.3", [{"type": "exact", "versions": ["1.3.0", "1.4"]}], (True, None)),
        ("1.3.1", [{"type": "exact", "versions": ["1.3.0"]}], (False, None)),
        ("28.0.1", [{"type": "ghsa", "vulnerable": "< 28.0.4", "patched": "28.0.4"}], (True, "28.0.4")),
        ("1.0", [span("abc", None)], (None, None)),
        ("1.0", [], (None, None)),
    ],
)
def test_evaluate(version: str, ranges: list[dict[str, Any]], expected: tuple[bool | None, str | None]) -> None:
    from seccheck.core.versions import parse_version

    assert evaluate(parse_version(version), ranges) == expected


def test_assess_prefers_osv_over_nvd() -> None:
    sources_ = {
        "nvd:x:y": entry("CVE-1", [span(None, "3.0")]),
        "osv:Go:x": entry("CVE-1", [span("2.0", "2.5")]),
    }
    assert assess("1.0", sources_) == ("not_affected", None)
    assert assess("2.1", sources_) == ("affected", "2.5")
    # Without usable OSV ranges, the NVD decides.
    assert assess("1.0", {"nvd:x:y": sources_["nvd:x:y"], "osv:Go:x": entry("CVE-1", [])}) == ("affected", "3.0")


def test_assess_unknown_version() -> None:
    assert assess(None, {"nvd:x:y": entry("CVE-1", [span(None, None)])}) == ("unknown", None)
    assert assess("latest", {"nvd:x:y": entry("CVE-1", [span(None, None)])}) == ("unknown", None)


def test_merge_prefers_project_texts_and_nvd_score() -> None:
    merged = merge(
        "CVE-1",
        {
            "nvd:a:b": entry(
                "CVE-1", [], summary="", description="Long NVD text. More.", severity="critical", cvss=9.8
            ),
            "ghsa:o/r": entry("CVE-1", [], aliases=["GHSA-aaaa-bbbb-cccc"], severity="high", cvss=7.5),
        },
    )
    assert merged["summary"] == "summary of CVE-1"
    assert merged["severity"] == "high" and merged["cvss"] == 9.8
    assert merged["aliases"] == ["GHSA-aaaa-bbbb-cccc"]
    assert merged["description"] == "Long NVD text. More."


# --- source normalization ----------------------------------------------------------


def test_normalize_osv_ranges() -> None:
    vuln = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["CVE-2024-1", "GO-2024-1"],
        "summary": "Bad thing",
        "database_specific": {"severity": "MODERATE"},
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "example.org/app"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]},
                    {"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"last_affected": "2.0.3"}]},
                    {"type": "GIT", "events": [{"introduced": "abc"}]},
                ],
            },
            {"package": {"ecosystem": "Go", "name": "other"}, "ranges": [{"type": "SEMVER", "events": []}]},
        ],
    }
    e = sources.normalize_osv(vuln, "Go", "example.org/app")
    assert e["id"] == "CVE-2024-1"
    assert e["aliases"] == ["GHSA-xxxx-yyyy-zzzz", "GO-2024-1"]
    assert e["severity"] == "medium"
    assert e["ranges"] == [span("0", "1.2.0"), span("2.0.0", "2.0.3", to_incl=True)]


def test_normalize_nvd_cpe_matches() -> None:
    item = {
        "cve": {
            "id": "CVE-2025-1",
            "published": "2025-02-05T18:15:32.567",
            "lastModified": "2025-03-01T10:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Something in nginx."}],
            "metrics": {
                "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 4.3, "baseSeverity": "MEDIUM"}}]
            },
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:open_source:*:*:*",
                                    "versionStartIncluding": "1.11.4",
                                    "versionEndExcluding": "1.26.3",
                                },
                                {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:1.27.3:*:*:*:*:*:*:*"},
                                {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx_plus:*:*:*:*:*:*:*:*"},
                                {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
                            ]
                        }
                    ]
                }
            ],
        }
    }
    e = sources.normalize_nvd(item, "f5:nginx")
    assert e["ranges"] == [span("1.11.4", "1.26.3"), {"type": "exact", "versions": ["1.27.3"]}]
    assert (e["severity"], e["cvss"]) == ("medium", 4.3)
    assert e["published"] == "2025-02-05T18:15:32Z"
    assert e["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2025-1"


def test_normalize_ghsa_filters_packages() -> None:
    adv = {
        "ghsa_id": "GHSA-1111-2222-3333",
        "cve_id": None,
        "summary": "Talk bug",
        "severity": "low",
        "updated_at": "2026-01-01T00:00:00Z",
        "vulnerabilities": [
            {"package": {"name": "spreed"}, "vulnerable_version_range": "< 2", "patched_versions": "2"}
        ],
    }
    assert sources.normalize_ghsa(adv, ("server",)) is None
    e = sources.normalize_ghsa(adv)
    assert e["id"] == "GHSA-1111-2222-3333" and e["ranges"][0]["vulnerable"] == "< 2"


@pytest.mark.asyncio
async def test_fetch_ghsa_follows_cursor_and_stops_at_known_items() -> None:
    def adv(n: int, updated: str) -> dict[str, Any]:
        return {"ghsa_id": f"GHSA-{n}", "cve_id": f"CVE-2026-{n}", "updated_at": updated, "vulnerabilities": []}

    pages = {
        "": ([adv(1, "2026-10-02T00:00:00Z"), adv(2, "2026-10-01T00:00:00Z")], "https://api.github.com/next?after=c1"),
        "c1": ([adv(3, "2026-09-01T00:00:00Z")], "https://api.github.com/next?after=c2"),
        "c2": ([adv(4, "2026-01-01T00:00:00Z")], None),
    }
    requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        cursor = request.url.params.get("after", "")
        requested.append(cursor)
        items, nxt = pages[cursor]
        headers = {"Link": f'<{nxt}>; rel="next"'} if nxt else {}
        return httpx.Response(200, json=items, headers=headers)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        everything = await sources.fetch_ghsa(client, "o/r", (), None)
        requested.clear()
        recent = await sources.fetch_ghsa(client, "o/r", (), "2026-09-15T00:00:00Z")
    assert [e["id"] for e in everything] == ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2026-4"]
    assert [e["id"] for e in recent] == ["CVE-2026-1", "CVE-2026-2"]
    assert requested == ["", "c1"]  # page c1 already reaches older items, c2 is never requested


# --- store ------------------------------------------------------------------------


def test_upsert_merges_sources_and_moves_ghsa_rows_to_cve_id(store: Store) -> None:
    ghsa_only = entry("GHSA-aaaa-bbbb-cccc", [{"type": "ghsa", "vulnerable": "< 2", "patched": "2"}])
    assert store.cve_upsert("p", "ghsa:o/r", [ghsa_only]) == 1
    # Later the advisory gets a CVE id, and the NVD reports the same CVE.
    with_cve = {**ghsa_only, "id": "CVE-2026-5", "aliases": ["GHSA-aaaa-bbbb-cccc"]}
    assert store.cve_upsert("p", "ghsa:o/r", [with_cve]) == 0
    assert store.cve_upsert("p", "nvd:o:r", [entry("CVE-2026-5", [span(None, "2")])]) == 0
    rows = store.cve_vulns(["p"])
    assert [r["id"] for r in rows] == ["CVE-2026-5"]
    assert set(rows[0]["sources"]) == {"ghsa:o/r", "nvd:o:r"}
    assert rows[0]["data"]["aliases"] == ["GHSA-aaaa-bbbb-cccc"]

    # A complete list without the vulnerability removes that source only.
    store.cve_upsert("p", "nvd:o:r", [], replace=True)
    assert set(store.cve_vulns(["p"])[0]["sources"]) == {"ghsa:o/r"}
    # Withdrawn by its last source: gone.
    store.cve_upsert("p", "ghsa:o/r", [{**with_cve, "withdrawn": True}])
    assert store.cve_vulns(["p"]) == []


def test_migration_adds_target_columns(tmp_path: Any) -> None:
    import sqlite3

    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.execute(
        "CREATE TABLE targets (id INTEGER PRIMARY KEY, app TEXT NOT NULL, url TEXT NOT NULL, "
        "label TEXT NOT NULL DEFAULT '', schedule TEXT NOT NULL DEFAULT 'off', notify INTEGER NOT NULL DEFAULT 1, "
        "accepted TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, UNIQUE (app, url))"
    )
    db.execute("INSERT INTO targets (app, url, created_at) VALUES ('nextcloud', 'https://c/', '2026-01-01')")
    db.commit()
    db.close()
    store = Store(path)
    assert store.set_target_software(1, "nextcloud", "31.0.1") is True
    assert store.set_target_software(1, "nextcloud", "31.0.1") is False
    assert store.cve_targets()[0]["version"] == "31.0.1"


def test_backfill_versions_from_stored_scan(store: Store) -> None:
    target = store.get_or_create_target("nextcloud", "https://cloud.example.com/")
    detect = CheckResult(
        id="nextcloud.detect",
        title="Nextcloud detected",
        category="app",
        status=Status.INFO,
        severity=Severity.INFO,
        summary="Nextcloud 30.0.2 detected.",
        details={"Produkt": "Nextcloud", "Version": "30.0.2"},
    ).model_dump(mode="json")
    now = datetime.now(UTC).isoformat()
    rating = {"grade": "A", "score": 95, "counts": {}}
    store.add_scan(
        target["id"], trigger="manual", started_at=now, finished_at=now, rating=rating, results=[detect], fixes={}
    )
    assert feed.backfill_versions(store) == 1
    assert store.cve_targets()[0]["product"] == "nextcloud"
    assert store.cve_targets()[0]["version"] == "30.0.2"
    assert feed.backfill_versions(store) == 0


# --- sync, evaluation and alerts ------------------------------------------------------


@pytest.fixture
def fake_sources(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Replaces all network sources; tests put entries into data["vulns"]."""
    data: dict[str, Any] = {"vulns": [], "kev": {}, "calls": []}

    async def fetch(client: Any, source: Any, since: str | None) -> list[dict[str, Any]]:
        data["calls"].append((source.key, since))
        return list(data["vulns"]) if source.kind == "ghsa" else []

    async def kev(client: Any) -> dict[str, Any]:
        return data["kev"]

    async def epss(client: Any, ids: list[str]) -> dict[str, tuple[float, float]]:
        return {i: (0.5, 0.9) for i in ids}

    monkeypatch.setattr(feed, "_fetch", fetch)
    monkeypatch.setattr(sources, "fetch_kev", kev)
    monkeypatch.setattr(sources, "fetch_epss", epss)
    return data


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str, int]]:
    messages: list[tuple[str, str, int]] = []

    async def send(settings: dict[str, Any], title: str, body: str, priority: int = 3) -> dict[str, str]:
        messages.append((title, body, priority))
        return {"ntfy": "ok"}

    monkeypatch.setattr(notify, "send", send)
    return messages


def nextcloud_vuln(n: int, severity: str = "high") -> dict[str, Any]:
    return entry(f"CVE-2026-{n}", [{"type": "ghsa", "vulnerable": "< 31.0.5", "patched": "31.0.5"}], severity=severity)


@pytest.mark.asyncio
async def test_first_sync_is_silent_then_new_and_exploited_vulns_alert(
    store: Store, fake_sources: dict[str, Any], sent: list[tuple[str, str, int]]
) -> None:
    store.add_watch("nextcloud", "31.0.1", "Cloud")
    fake_sources["vulns"] = [nextcloud_vuln(1)]
    result = await feed.sync(store)
    assert result["new"] == 1 and result["alerts"] == 0 and not sent
    assert store.cve_match_counts() == {"watch:1": {"total": 1, "kev": 0}}

    # A new high and a new low vulnerability: only the high one passes the default threshold.
    fake_sources["vulns"] = [nextcloud_vuln(2), nextcloud_vuln(3, "low")]
    await feed.sync(store)
    assert len(sent) == 1
    title, body, priority = sent[0]
    assert title == "SecCheck: Cloud – new vulnerability CVE-2026-2"
    assert "CVE-2026-2" in body and "CVE-2026-3" not in body and "31.0.5" in body
    assert priority == 4

    # Nothing new: no alert. Then CVE-2026-1 lands in CISA KEV.
    await feed.sync(store)
    assert len(sent) == 1
    fake_sources["kev"] = {"CVE-2026-1": {"date_added": "2026-10-01", "due_date": None, "ransomware": False}}
    store.set_cve_sync("kev", synced_at=None, error=None)  # make the daily KEV refresh due again
    await feed.sync(store)
    assert len(sent) == 2 and "actively exploited" in sent[1][0] and sent[1][2] == 5

    # Updating the watched version re-baselines silently.
    store.update_watch(1, version="31.0.5")
    await feed.sync(store)
    assert len(sent) == 2 and store.cve_match_counts() == {}


@pytest.mark.asyncio
async def test_incremental_sync_passes_since(store: Store, fake_sources: dict[str, Any], sent: list) -> None:
    store.add_watch("immich", "1.0.0")
    await feed.sync(store)
    await feed.sync(store, full=False)  # nothing new to sync
    await feed.sync(store)
    assert [since is None for _key, since in fake_sources["calls"]] == [True, False]


@pytest.mark.asyncio
async def test_alerts_respect_settings(store: Store, fake_sources: dict[str, Any], sent: list) -> None:
    store.add_watch("nextcloud", "31.0.1")
    await feed.sync(store)
    notify.save_settings(store, {"cve": {"enabled": False}})
    fake_sources["vulns"] = [nextcloud_vuln(7, "critical")]
    await feed.sync(store)
    assert not sent


def test_compose_cve_in_german() -> None:
    subject = {
        "key": "target:1",
        "name": "Cloud",
        "product_name": "Nextcloud Server",
        "version": "31.0.1",
        "possible": False,
    }
    item = {"id": "CVE-2026-1", "severity": "critical", "cvss": 9.1, "summary": "RCE", "kev": True, "fixed": "31.0.5"}
    with language("de"):
        title, body, priority = notify.compose_cve(
            subject, [item, {**item, "id": "CVE-2026-2"}], [], "http://seccheck.lan"
        )
    assert title == "SecCheck: Cloud – 2 neue Schwachstellen"
    assert "[Kritisch, CVSS 9.1, aktiv ausgenutzt] RCE – behoben in 31.0.5" in body
    assert body.endswith("http://seccheck.lan/#/cves?subject=target:1")
    assert priority == 5


# --- API --------------------------------------------------------------------------------


@pytest.fixture
def client(store: Store, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    from seccheck import main

    monkeypatch.setattr(main, "get_store", lambda: store)
    monkeypatch.setattr(store_module, "get_store", lambda: store)
    monkeypatch.setattr(main.config, "SCHEDULER_ENABLED", False)
    with TestClient(main.app) as c:
        yield c


def test_api_watchlist_overview_and_feed(client: TestClient, store: Store) -> None:
    assert client.post("/api/cve/watch", json={"product": "nope", "version": "1.0"}).status_code == 404
    assert client.post("/api/cve/watch", json={"product": "nginx", "version": "latest"}).status_code == 422
    watch = client.post("/api/cve/watch", json={"product": "nginx", "version": "1.22.1", "label": "Proxy"}).json()

    store.cve_upsert("nginx", "nvd:f5:nginx", [entry("CVE-2025-1", [span("1.11.4", "1.26.3")], severity="medium")])
    store.cve_upsert(
        "nginx", "nvd:f5:nginx", [entry("CVE-2020-9", [span(None, "1.20")], published="2020-01-01T00:00:00Z")]
    )
    store.set_cve_kev({"CVE-2025-1": {"date_added": "2026-01-01", "due_date": None, "ransomware": False, "name": ""}})

    overview = client.get("/api/cve/overview").json()
    subject = overview["subjects"][0]
    assert subject["key"] == f"watch:{watch['id']}" and subject["affected"] == 1 and subject["kev"] == 1
    assert subject["possible"] is True  # nginx: distributions backport fixes
    assert next(p for p in overview["products"] if p["id"] == "nginx")["monitored"] is True

    everything = client.get("/api/cve/feed").json()
    assert [i["id"] for i in everything["items"]] == ["CVE-2025-1", "CVE-2020-9"]  # newest first
    affected = client.get("/api/cve/feed", params={"affected": "true"}).json()
    assert affected["total"] == 1 and affected["items"][0]["affects"][0]["fixed"] == "1.26.3"
    assert client.get("/api/cve/feed", params={"kev": "true"}).json()["total"] == 1
    assert client.get("/api/cve/feed", params={"severity": "high"}).json()["total"] == 1
    assert client.get("/api/cve/feed", params={"q": "cve-2020"}).json()["total"] == 1

    assert client.patch(f"/api/cve/watch/{watch['id']}", json={"version": "1.26.3"}).json()["version"] == "1.26.3"
    assert client.get("/api/cve/overview").json()["subjects"][0]["affected"] == 0
    assert client.delete(f"/api/cve/watch/{watch['id']}").status_code == 204
    assert client.get("/api/cve/overview").json()["subjects"] == []


def test_api_cve_settings_roundtrip(client: TestClient) -> None:
    settings = client.get("/api/settings/notifications").json()
    assert settings["cve"] == {"enabled": True, "min_severity": "high"}
    settings["cve"] = {"enabled": False, "min_severity": "bogus"}
    saved = client.put("/api/settings/notifications", json=settings).json()
    assert saved["cve"] == {"enabled": False, "min_severity": "high"}
