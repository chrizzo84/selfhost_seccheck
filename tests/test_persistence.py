from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from seccheck import notify
from seccheck import store as store_module
from seccheck.core.fixes import build_fixes
from seccheck.core.history import diff_scans
from seccheck.core.models import CheckResult, Severity, Status
from seccheck.core.scoring import compute_rating
from seccheck.i18n import language
from seccheck.service import rerate_latest
from seccheck.store import Store


def result(check_id: str, status: str, severity: str = "medium", accepted: bool = False) -> dict:
    return CheckResult(
        id=check_id,
        title=check_id,
        category="headers",
        status=Status(status),
        severity=Severity(severity),
        summary=f"{check_id} {status}",
        accepted=accepted,
    ).model_dump(mode="json")


def rating_for(results: list[dict]) -> dict:
    return compute_rating([CheckResult(**r) for r in results]).model_dump(mode="json")


def add(store: Store, target_id: int, results: list[dict], finished: datetime) -> int:
    return store.add_scan(
        target_id,
        trigger="manual",
        started_at=finished.isoformat(),
        finished_at=finished.isoformat(),
        rating=rating_for(results),
        results=results,
        fixes={},
    )


@pytest.fixture
def store() -> Store:
    return Store(":memory:")


# --- store ----------------------------------------------------------------------


def test_targets_are_unique_per_app_and_url(store: Store) -> None:
    a = store.get_or_create_target("nextcloud", "https://cloud.example.com/")
    b = store.get_or_create_target("nextcloud", "https://cloud.example.com/")
    c = store.get_or_create_target("generic", "https://cloud.example.com/")
    assert a["id"] == b["id"] != c["id"]
    assert a["accepted"] == [] and a["notify"] is True and a["schedule"] == "off"


def test_scan_history_and_previous(store: Store) -> None:
    t = store.get_or_create_target("generic", "https://a.example/")
    now = datetime.now(UTC)
    first = add(store, t["id"], [result("headers.csp", "fail")], now - timedelta(days=1))
    second = add(store, t["id"], [result("headers.csp", "pass")], now)
    assert store.latest_scan(t["id"])["id"] == second
    assert store.previous_scan(store.get_scan(second))["id"] == first
    listed = store.list_targets()[0]
    assert listed["last_scan"]["id"] == second
    assert [h["score"] for h in listed["history"]] == [92, 100]


def test_due_targets(store: Store) -> None:
    now = datetime.now(UTC)
    off = store.get_or_create_target("generic", "https://off.example/")
    never = store.get_or_create_target("generic", "https://never.example/")
    recent = store.get_or_create_target("generic", "https://recent.example/")
    old = store.get_or_create_target("generic", "https://old.example/")
    for t in (never, recent, old):
        store.update_target(t["id"], schedule="daily")
    add(store, recent["id"], [], now - timedelta(hours=2))
    add(store, old["id"], [], now - timedelta(hours=25))
    due = {t["url"] for t in store.due_targets(now)}
    assert due == {"https://never.example/", "https://old.example/"}
    assert off["url"] not in due


def test_invalid_schedule_rejected(store: Store) -> None:
    t = store.get_or_create_target("generic", "https://a.example/")
    with pytest.raises(ValueError):
        store.update_target(t["id"], schedule="hourly")


# --- diff -------------------------------------------------------------------------


def test_diff_new_and_resolved() -> None:
    before = [result("a", "fail"), result("b", "warn"), result("c", "pass")]
    after = [result("a", "pass"), result("b", "warn"), result("c", "fail", "high")]
    previous = {"results": before, "rating": rating_for(before)}
    diff = diff_scans(previous, after, rating_for(after))
    assert [i["id"] for i in diff["new"]] == ["c"]
    assert [i["id"] for i in diff["resolved"]] == ["a"]
    assert diff["grade_worse"] is True


def test_diff_ignores_accepted_and_first_scan_lists_everything() -> None:
    after = [result("a", "fail", accepted=True), result("b", "warn")]
    diff = diff_scans(None, after, rating_for(after))
    assert diff["first_scan"] and [i["id"] for i in diff["new"]] == ["b"]


# --- accepted risks -------------------------------------------------------------


def test_accepted_findings_do_not_count() -> None:
    plain = compute_rating([CheckResult(**result("x", "fail", "critical"))])
    accepted = compute_rating([CheckResult(**result("x", "fail", "critical", accepted=True))])
    assert plain.grade == "F" and plain.caps
    assert accepted.score == 100 and accepted.grade == "A+" and not accepted.caps
    assert accepted.counts["accepted"] == 1


def test_rerate_latest_applies_accepted_risks(store: Store) -> None:
    t = store.get_or_create_target("generic", "https://a.example/")
    add(store, t["id"], [result("headers.csp", "fail"), result("headers.nosniff", "fail", "low")], datetime.now(UTC))
    store.update_target(t["id"], accepted=["headers.csp"])
    rerated = rerate_latest(store, t["id"])
    assert rerated["rating"]["score"] == 97
    assert store.latest_scan(t["id"])["rating"]["score"] == 97
    assert "X-Content-Type-Options" in rerated["fixes"]["nginx"]


# --- fixes ------------------------------------------------------------------------


def test_fixes_cover_failed_header_checks() -> None:
    results = [
        CheckResult(**result("transport.hsts", "fail", "high")),
        CheckResult(**result("headers.nosniff", "fail", "low")),
        CheckResult(**result("headers.referrer", "pass", "low")),
        CheckResult(**result("headers.permissions", "warn", "low", accepted=True)),
    ]
    fixes = build_fixes(results)
    assert set(fixes) == {"nginx", "apache", "caddy", "traefik"}
    assert 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' in fixes["nginx"]
    assert "X-Content-Type-Options" in fixes["caddy"]
    assert "Referrer-Policy" not in fixes["nginx"]
    assert "Permissions-Policy" not in fixes["nginx"]


def test_no_fixes_without_findings() -> None:
    assert build_fixes([CheckResult(**result("transport.hsts", "pass"))]) == {}


# --- notifications ----------------------------------------------------------------


def test_notification_secrets_are_masked_and_kept(store: Store) -> None:
    notify.save_settings(store, {"ntfy": {"enabled": True, "topic": "lab", "token": "tk_secret"}})
    shown = notify.masked(notify.load_settings(store))
    assert shown["ntfy"]["token"] == notify.SECRET_PLACEHOLDER
    # Sending the form back unchanged must not overwrite the stored token.
    notify.save_settings(store, shown)
    assert notify.load_settings(store)["ntfy"]["token"] == "tk_secret"
    notify.save_settings(store, {"ntfy": {**shown["ntfy"], "token": ""}})
    assert notify.load_settings(store)["ntfy"]["token"] == ""


def test_compose_message() -> None:
    after = [result("tls.cert_expiry", "fail", "critical")]
    before = [result("tls.cert_expiry", "pass")]
    diff = diff_scans({"results": before, "rating": rating_for(before)}, after, rating_for(after))
    target = {"id": 7, "label": "Cloud", "url": "https://cloud.example/"}
    title, body, priority = notify.compose(target, diff, "https://seccheck.lan")
    assert title == "SecCheck: Cloud – Grade A+ → F"
    assert body.startswith("New problems:")
    assert "[Critical] tls.cert_expiry" in body
    assert body.endswith("https://seccheck.lan/#/target/7")
    assert priority == 5
    assert notify.should_notify(diff)

    with language("de"):
        title, body, _prio = notify.compose(target, diff, "")
    assert title == "SecCheck: Cloud – Note A+ → F"
    assert "[Kritisch] tls.cert_expiry" in body


# --- API ----------------------------------------------------------------------------


@pytest.fixture
def client(store: Store, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    from seccheck import main

    monkeypatch.setattr(main, "get_store", lambda: store)
    monkeypatch.setattr(store_module, "get_store", lambda: store)
    monkeypatch.setattr(main.config, "SCHEDULER_ENABLED", False)
    with TestClient(main.app) as c:
        yield c


def test_api_targets_and_accepted_risks(client: TestClient, store: Store) -> None:
    t = store.get_or_create_target("generic", "https://a.example/")
    add(store, t["id"], [result("headers.csp", "fail")], datetime.now(UTC))

    targets = client.get("/api/targets").json()
    assert targets[0]["app_name"] == "Other web application"
    german = client.get("/api/targets", headers={"Accept-Language": "de-DE,de;q=0.9"}).json()
    assert german[0]["app_name"] == "Andere Web-Anwendung"

    assert client.patch(f"/api/targets/{t['id']}", json={"schedule": "hourly"}).status_code == 422
    updated = client.patch(f"/api/targets/{t['id']}", json={"schedule": "weekly", "label": "Lab"}).json()
    assert updated["schedule"] == "weekly" and updated["label"] == "Lab"

    accepted = client.put(f"/api/targets/{t['id']}/accepted/headers.csp").json()
    assert accepted["rating"]["score"] == 100
    assert client.put(f"/api/targets/{t['id']}/accepted/nope.nope").status_code == 404
    reverted = client.delete(f"/api/targets/{t['id']}/accepted/headers.csp").json()
    assert reverted["rating"]["score"] == 92

    scans = client.get(f"/api/targets/{t['id']}/scans").json()["scans"]
    detail = client.get(f"/api/scans/{scans[0]['id']}").json()
    assert detail["diff"]["first_scan"] is True and detail["target"]["label"] == "Lab"

    assert client.delete(f"/api/targets/{t['id']}").status_code == 204
    assert client.get("/api/targets").json() == []


def test_api_notification_test_without_channels(client: TestClient) -> None:
    assert client.post("/api/settings/notifications/test").status_code == 400


@pytest.mark.asyncio
async def test_pushover_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    from urllib.parse import parse_qsl

    import httpx

    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == notify.PUSHOVER_URL
        sent.append(dict(parse_qsl(request.content.decode())))
        return httpx.Response(200, json={"status": 1})

    original = httpx.AsyncClient
    monkeypatch.setattr(
        notify.httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(handler), **kw)
    )
    settings = notify.load_settings(Store(":memory:"))
    settings["pushover"] = {"enabled": True, "token": "app-token", "user": "user-key", "device": ""}

    result = await notify.send(
        settings, "SecCheck: Cloud – Note A → F", "• [Kritisch] Zertifikat abgelaufen", priority=5
    )

    assert result == {"pushover": "ok"}
    assert sent[0]["token"] == "app-token" and sent[0]["user"] == "user-key"
    assert sent[0]["priority"] == "1" and sent[0]["title"].endswith("Note A → F")
    assert "device" not in sent[0]


def test_pushover_secrets_masked(store: Store) -> None:
    notify.save_settings(store, {"pushover": {"enabled": True, "token": "app", "user": "key"}})
    shown = notify.masked(notify.load_settings(store))
    assert shown["pushover"]["token"] == shown["pushover"]["user"] == notify.SECRET_PLACEHOLDER
    notify.save_settings(store, shown)
    assert notify.load_settings(store)["pushover"]["user"] == "key"
