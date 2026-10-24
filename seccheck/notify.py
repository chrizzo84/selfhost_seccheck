"""Notifications via ntfy, Gotify, Pushover and e-mail.

The channel configuration lives in the settings table under "notifications".
Secrets (tokens, SMTP password) are never sent back to the browser; the API
replaces them with a placeholder and keeps the stored value when the
placeholder comes back unchanged.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

import httpx

from . import config
from .core.history import diff_scans
from .i18n import N_, _, normalize
from .store import Store

log = logging.getLogger(__name__)

SETTINGS_KEY = "notifications"
SECRET_PLACEHOLDER = "••••••••"
SECRETS = {"ntfy": ("token",), "gotify": ("token",), "pushover": ("token", "user"), "email": ("password",)}

DEFAULTS: dict[str, Any] = {
    "public_url": "",
    # Language of scheduled scans and their notifications.
    "language": config.DEFAULT_LANGUAGE,
    # Alerts when a new vulnerability affects a monitored system. Actively
    # exploited ones (CISA KEV) are always reported.
    "cve": {"enabled": True, "min_severity": "high"},
    "ntfy": {"enabled": False, "server": "https://ntfy.sh", "topic": "", "token": ""},
    "gotify": {"enabled": False, "url": "", "token": ""},
    # token = application API token, user = user or group key, device optional.
    "pushover": {"enabled": False, "token": "", "user": "", "device": ""},
    "email": {
        "enabled": False,
        "host": "",
        "port": 587,
        "security": "starttls",  # starttls | ssl | none
        "username": "",
        "password": "",
        "sender": "",
        "recipient": "",
    },
}

CVE_SEVERITIES = ("critical", "high", "medium", "low")

SEVERITY_LABELS = {
    "critical": N_("Critical"),
    "high": N_("High"),
    "medium": N_("Medium"),
    "low": N_("Low"),
    "info": N_("Info"),
}


def load_settings(store: Store) -> dict[str, Any]:
    stored = store.get_setting(SETTINGS_KEY, {})
    merged: dict[str, Any] = {
        "public_url": stored.get("public_url", DEFAULTS["public_url"]),
        "language": normalize(stored.get("language", DEFAULTS["language"])),
        "cve": {**DEFAULTS["cve"], **stored.get("cve", {})},
    }
    for channel in SECRETS:
        merged[channel] = {**DEFAULTS[channel], **stored.get(channel, {})}
    return merged


def masked(settings: dict[str, Any]) -> dict[str, Any]:
    out = {"public_url": settings["public_url"], "language": settings["language"], "cve": dict(settings["cve"])}
    for channel, secret_fields in SECRETS.items():
        out[channel] = dict(settings[channel])
        for name in secret_fields:
            out[channel][name] = SECRET_PLACEHOLDER if settings[channel].get(name) else ""
    return out


def save_settings(store: Store, incoming: dict[str, Any]) -> dict[str, Any]:
    current = load_settings(store)
    updated: dict[str, Any] = {
        "public_url": str(incoming.get("public_url", current["public_url"])).strip(),
        "language": normalize(incoming.get("language", current["language"])),
        "cve": _cve_settings({**current["cve"], **(incoming.get("cve") or {})}),
    }
    for channel, secret_fields in SECRETS.items():
        values = {**current[channel], **(incoming.get(channel) or {})}
        for name in secret_fields:
            if values.get(name) == SECRET_PLACEHOLDER:
                values[name] = current[channel].get(name, "")
        # Only keep known keys.
        updated[channel] = {k: values.get(k, v) for k, v in DEFAULTS[channel].items()}
    store.set_setting(SETTINGS_KEY, updated)
    return updated


def _cve_settings(values: dict[str, Any]) -> dict[str, Any]:
    severity = str(values.get("min_severity") or "")
    return {
        "enabled": bool(values.get("enabled")),
        "min_severity": severity if severity in CVE_SEVERITIES else DEFAULTS["cve"]["min_severity"],
    }


# --- channels -------------------------------------------------------------


async def _send_ntfy(cfg: dict[str, Any], title: str, body: str, priority: int, client: httpx.AsyncClient) -> None:
    # JSON publishing keeps UTF-8 titles intact (HTTP headers would need RFC 2047).
    headers = {"Authorization": f"Bearer {cfg['token']}"} if cfg.get("token") else {}
    payload = {
        "topic": cfg["topic"].strip("/"),
        "title": title,
        "message": body,
        "priority": priority,
        "tags": ["shield"],
    }
    resp = await client.post(cfg["server"].rstrip("/") + "/", json=payload, headers=headers)
    resp.raise_for_status()


async def _send_gotify(cfg: dict[str, Any], title: str, body: str, priority: int, client: httpx.AsyncClient) -> None:
    resp = await client.post(
        f"{cfg['url'].rstrip('/')}/message",
        json={"title": title, "message": body, "priority": priority * 2},
        headers={"X-Gotify-Key": cfg["token"]},
    )
    resp.raise_for_status()


PUSHOVER_URL = "https://api.pushover.net/1/messages.json"


async def _send_pushover(cfg: dict[str, Any], title: str, body: str, priority: int, client: httpx.AsyncClient) -> None:
    # Pushover priorities: 0 normal, 1 high (bypasses quiet hours). 2 (emergency)
    # needs acknowledgement and is deliberately not used.
    form = {
        "token": cfg["token"],
        "user": cfg["user"],
        "title": title[:250],
        "message": body[:1024],
        "priority": "1" if priority >= 5 else "0",
    }
    if cfg.get("device"):
        form["device"] = cfg["device"]
    resp = await client.post(PUSHOVER_URL, data=form)
    resp.raise_for_status()


def _send_email_sync(cfg: dict[str, Any], title: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = cfg["sender"] or cfg["username"]
    msg["To"] = cfg["recipient"]
    msg.set_content(body)
    port = int(cfg.get("port") or 587)
    context = ssl.create_default_context()
    if cfg.get("security") == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(cfg["host"], port, timeout=20, context=context)
    else:
        server = smtplib.SMTP(cfg["host"], port, timeout=20)
    with server:
        if cfg.get("security") == "starttls":
            server.starttls(context=context)
        if cfg.get("username"):
            server.login(cfg["username"], cfg["password"])
        server.send_message(msg)


def _configured(channel: str, cfg: dict[str, Any]) -> bool:
    if not cfg.get("enabled"):
        return False
    required = {
        "ntfy": ("server", "topic"),
        "gotify": ("url", "token"),
        "pushover": ("token", "user"),
        "email": ("host", "recipient"),
    }
    return all(cfg.get(k) for k in required[channel])


async def send(settings: dict[str, Any], title: str, body: str, priority: int = 3) -> dict[str, str]:
    """Send to every enabled channel. Returns channel -> "ok" or error text."""
    outcome: dict[str, str] = {}
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": config.USER_AGENT}) as client:
        for channel in SECRETS:
            cfg = settings[channel]
            if not _configured(channel, cfg):
                continue
            try:
                if channel == "ntfy":
                    await _send_ntfy(cfg, title, body, priority, client)
                elif channel == "gotify":
                    await _send_gotify(cfg, title, body, priority, client)
                elif channel == "pushover":
                    await _send_pushover(cfg, title, body, priority, client)
                else:
                    await asyncio.to_thread(_send_email_sync, cfg, title, body)
                outcome[channel] = "ok"
            except Exception as exc:  # report per channel, never break the scan
                log.warning("Notification via %s failed: %s", channel, exc)
                outcome[channel] = f"{type(exc).__name__}: {exc}"
    return outcome


# --- scan reports ---------------------------------------------------------


def should_notify(diff: dict[str, Any]) -> bool:
    return bool(diff["new"]) or diff["grade_worse"]


def compose(target: dict[str, Any], diff: dict[str, Any], public_url: str) -> tuple[str, str, int]:
    name = target["label"] or target["url"]
    if diff["grade_before"] and diff["grade_before"] != diff["grade_after"]:
        grade = _("Grade {before} → {after}", before=diff["grade_before"], after=diff["grade_after"])
    else:
        grade = _("Grade {grade}", grade=diff["grade_after"])
    title = f"SecCheck: {name} – {grade}"

    lines = []
    if diff["new"]:
        lines.append(_("Problems found:") if diff["first_scan"] else _("New problems:"))
        for item in sorted(diff["new"], key=lambda i: list(SEVERITY_LABELS).index(i["severity"])):
            severity = _(SEVERITY_LABELS[item["severity"]])
            lines.append(f"• [{severity}] {item['title']}: {item['summary']}")
    if diff["resolved"]:
        lines.append("")
        lines.append(_("Resolved:"))
        lines.extend(f"• {item['title']}" for item in diff["resolved"])
    if public_url:
        lines.append("")
        lines.append(f"{public_url.rstrip('/')}/#/target/{target['id']}")

    severities = {item["severity"] for item in diff["new"]}
    priority = 5 if "critical" in severities else 4 if "high" in severities or diff["grade_worse"] else 3
    return title, "\n".join(lines) or _("No changes."), priority


async def notify_scan(store: Store, target: dict[str, Any], scan: dict[str, Any]) -> None:
    previous = await asyncio.to_thread(store.previous_scan, scan)
    diff = diff_scans(previous, scan["results"], scan["rating"])
    if not should_notify(diff):
        return
    settings = await asyncio.to_thread(load_settings, store)
    title, body, priority = compose(target, diff, settings["public_url"])
    await send(settings, title, body, priority)


# --- CVE feed ---------------------------------------------------------------


def compose_cve(
    subject: dict[str, Any], new: list[dict[str, Any]], exploited: list[dict[str, Any]], public_url: str
) -> tuple[str, str, int]:
    """Alert for one system: newly matching vulnerabilities and known ones that are now exploited.

    Items are feed records with "id", "severity", "cvss", "summary", "kev", "fixed".
    """
    name = subject["name"]
    if len(new) == 1:
        title = _("SecCheck: {name} – new vulnerability {id}", name=name, id=new[0]["id"])
    elif new:
        title = _("SecCheck: {name} – {count} new vulnerabilities", name=name, count=len(new))
    else:
        title = _("SecCheck: {name} – vulnerability now actively exploited", name=name)
    software = f"{subject['product_name']} {subject['version']}"
    lines = [_("{software} is affected by:", software=software) if new else software]

    def line(item: dict[str, Any]) -> str:
        tags = [_(SEVERITY_LABELS[item["severity"]]) if item["severity"] in SEVERITY_LABELS else _("Unknown")]
        if item.get("cvss"):
            tags.append(f"CVSS {item['cvss']:.1f}")
        if item.get("kev"):
            tags.append(_("actively exploited"))
        text = f"• {item['id']} [{', '.join(tags)}] {item['summary']}"
        if item.get("fixed"):
            text += " – " + _("fixed in {versions}", versions=item["fixed"])
        return text

    lines.extend(line(item) for item in new)
    if exploited:
        lines.append("")
        lines.append(_("Now listed as actively exploited (CISA KEV):"))
        lines.extend(line(item) for item in exploited)
    if subject.get("possible"):
        lines.append("")
        lines.append(_("Distributions often backport fixes without changing the version; check your package."))
    if public_url:
        lines.append("")
        lines.append(f"{public_url.rstrip('/')}/#/cves?subject={subject['key']}")

    items = new + exploited
    if exploited or any(i["severity"] == "critical" for i in items):
        priority = 5
    elif any(i["severity"] == "high" for i in items):
        priority = 4
    else:
        priority = 3
    return title, "\n".join(lines), priority
