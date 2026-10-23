"""Command line interface.

python -m seccheck serve [--host 0.0.0.0] [--port 8000]
python -m seccheck scan nextcloud https://cloud.example.com [--json] [--lang de]
python -m seccheck list [--lang de]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from . import config
from .core.registry import CATEGORIES, all_apps, checks_for, get_app, load_plugins
from .core.runner import run_scan
from .core.target import TargetError, ensure_allowed, parse_target
from .i18n import LANGUAGES, _, set_language

ICONS = {"pass": "✔", "warn": "!", "fail": "✘", "info": "i", "skip": "-", "error": "?"}
COLORS = {"pass": "32", "warn": "33", "fail": "31", "info": "36", "skip": "90", "error": "35"}


def _color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text


async def _scan(app_id: str, url: str, as_json: bool) -> int:
    profile = get_app(app_id)
    if profile is None:
        available = ", ".join(a.id for a in all_apps())
        print(_("Unknown application {app}. Available: {available}", app=repr(app_id), available=available))
        return 2
    try:
        target = parse_target(url)
        await ensure_allowed(target)
    except TargetError as exc:
        print(_("Error: {error}", error=exc))
        return 2

    results, done = [], None
    async for event in run_scan(profile, target):
        if event["type"] == "result":
            results.append(event["result"])
            if not as_json:
                r = event["result"]
                icon = _color(ICONS[r["status"]], COLORS[r["status"]])
                print(f" {icon} {r['title']}: {r['summary']}", flush=True)
        elif event["type"] == "done":
            done = event
        elif event["type"] == "start" and not as_json:
            print(
                _(
                    "Scanning {target} as {app} ({count} checks)",
                    target=event["target"],
                    app=event["app"]["name"],
                    count=len(event["checks"]),
                )
                + "\n"
            )

    assert done is not None
    rating = done["rating"]
    if as_json:
        print(
            json.dumps(
                {"target": target.url(), "app": app_id, "rating": rating, "results": results},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print("\n" + _("Grade: {grade}  ({score}/100)", grade=rating["grade"], score=rating["score"]))
        for cap in rating["caps"]:
            print(f"  ↳ {cap}")
    return 0 if rating["grade"] not in {"D", "F"} else 1


def main() -> int:
    load_plugins()
    parser = argparse.ArgumentParser(prog="seccheck", description="Security checks for self-hosted software")
    parser.add_argument(
        "--lang",
        choices=sorted(LANGUAGES),
        default=config.DEFAULT_LANGUAGE,
        help="language of the output (default: SECCHECK_LANG or en)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="start the web interface")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    scan = sub.add_parser("scan", help="scan an instance from the command line")
    scan.add_argument("app")
    scan.add_argument("url")
    scan.add_argument("--json", action="store_true", help="print the result as JSON")

    sub.add_parser("list", help="list applications and checks")

    args = parser.parse_args()
    set_language(args.lang)
    if args.cmd == "serve":
        import uvicorn

        uvicorn.run("seccheck.main:app", host=args.host, port=args.port)
        return 0
    if args.cmd == "scan":
        return asyncio.run(_scan(args.app, args.url, args.json))

    for profile in all_apps():
        print(f"{_(profile.name)} ({profile.id})")
        for spec in checks_for(profile):
            print(f"   [{_(CATEGORIES[spec.category])}] {spec.id}: {_(spec.title)}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
