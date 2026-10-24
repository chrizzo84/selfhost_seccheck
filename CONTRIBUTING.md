# Contributing to SelfHost SecCheck

Thanks for helping! The most valuable contributions are new application profiles, new checks, translations and
bug reports with enough detail to reproduce them.

## Development setup

```bash
git clone https://github.com/chrizzo84/selfhost-seccheck.git
cd selfhost-seccheck
python3 -m venv .venv
.venv/bin/pip install -e '.[dev,full]'
.venv/bin/python -m seccheck serve --port 8000     # web UI
.venv/bin/python -m pytest                          # tests
.venv/bin/ruff check . && .venv/bin/ruff format .   # lint + format
```

CI runs the same commands; a pull request has to pass `pytest`, `ruff check` and `ruff format --check`.

## Project layout

```
seccheck/
  core/        scanner core: registry, scan context, runner, scoring, TLS, versions, advisories, fixes
  cve/         CVE feed: product catalog, sources (GitHub, OSV, NVD, KEV, EPSS), version matching, sync
  checks/      generic checks that run for every application
  apps/        one module per application: profile, detector and app-specific checks
  locales/     translations of the backend (de/*.json)
  main.py      FastAPI app (JSON API + static frontend)
  store.py     SQLite persistence; service.py, scheduler.py, notify.py for history and notifications
static/        frontend (plain ES modules, no build step), locales/*.json for the UI texts
tests/
```

## Ground rules for checks

SecCheck is pointed at production systems. Every check must be safe to run against an instance whose owner
did not read the code first.

1. **Read-only.** Only GET (and the existing TRACE probe). No POST/PUT/DELETE, no starting setup or login flows,
   nothing that changes state on the target.
2. **No credentials, no login attempts.** Not even "obviously wrong" ones.
3. **Never trigger bans or lockouts.** Some apps count unauthenticated requests as failed logins (Home
   Assistant bans on every 401). Add such paths to `AppProfile.no_probe_paths` (regex relative to the install
   path); the scanner then refuses to send those requests, also from generic checks. Explain why in a comment.
4. **Validate content, not just status codes.** Many apps answer every path with 200 and their HTML shell.
   Match a body signature (see `seccheck/checks/exposure.py`).
5. **Verify against the real thing.** Test new checks against the official Docker image or link the upstream
   source you relied on in the pull request. Do not test against hosts you do not own.

## Adding an application

Create `seccheck/apps/<app>.py`. It is picked up automatically.

```python
from ..core.context import ScanContext
from ..core.models import Outcome, Severity, SkipCheck, failed, info, passed, warned
from ..core.registry import AppProfile, Detection, check, detector, register_app
from ..i18n import _

APP = register_app(
    AppProfile(
        id="example",
        name="Example",
        short="EX",  # 2-3 letters for the logo tile
        color="#2563eb",
        description="Version, open registration.",
        url_hint="https://example.home.lan",
        cors_paths=("api/status",),  # public endpoints the CORS check should also probe
    )
)
APPS = [APP.id]


@detector(APP.id)
async def identify(ctx: ScanContext) -> Detection | None:
    """Used by auto-detection: only harmless GETs, never raise."""
    data = await ctx.get_json("api/status")
    if isinstance(data, dict) and data.get("product") == "Example":
        return Detection("Example", data.get("version"))
    return None


@check("example.registration", title="No open registration", category="app", severity=Severity.MEDIUM, apps=APPS)
async def registration(ctx: ScanContext) -> Outcome:
    """Open registration lets strangers create accounts."""
    if await identify(ctx) is None:
        raise SkipCheck(_("No Example instance found at this URL."))
    page = await ctx.try_fetch("signup")
    if page and page.status == 200 and 'name="password"' in page.text:
        return warned(_("Anyone can create an account."), recommendation=_("Disable public registration."))
    return passed(_("Self-registration is disabled."))
```

Notes:

- Every app needs a `@detector` (a test enforces it). Detectors run against unknown targets during
  auto-detection, so they must only send requests that are harmless for *every* app.
- Write a `<app>.detect` info check as the existing apps do, and a version check if the version is public:
  `assess_latest()` (newest GitHub release), `assess_branches()` (several maintained branches) or
  `assess_eol()` (endoflife.date). If the project publishes GitHub security advisories, add an advisory check with
  `seccheck.core.advisories.assess_advisories()`.
- Add mocked tests (see `tests/test_apps_new.py`: `make_ctx` + `httpx.MockTransport`) for detection and for the
  pass/fail paths of each check.
- Add the app to the table in `README.md`.
- Add the product to `seccheck/cve/catalog.py` with `app="<id>"`, so scans feed the CVE page. Its detector must
  return the version for that.

## Adding a product to the CVE feed

Every product in `seccheck/cve/catalog.py` can be added to the watchlist. A product lists where its
vulnerabilities are published:

```python
Product("caddy", "Caddy", (osv("Go", "github.com/caddyserver/caddy/v2"),))
Product("nginx", "nginx", (nvd("f5:nginx"),), backports=True)
Product("immich", "Immich", (ghsa("immich-app/immich"),), app="immich")
```

- `osv("Ecosystem", "package")` when the project is a package in OSV.dev (Go, PyPI, npm, crates.io, …): the most
  precise ranges. Look it up on https://osv.dev.
- `ghsa("owner/repo", *packages)` when the project publishes security advisories in its GitHub repository.
- `nvd("vendor:product")` for everything else; find the CPE on https://nvd.nist.gov/products/cpe/search.
- `backports=True` for software usually installed from distribution packages, whose fixes are backported without a
  version change. Matches are then shown as "possibly affected".

Check that the source returns data (`curl` the OSV query or the NVD `virtualMatchString`) before adding it.

## Adding a generic check

Put a function decorated with `@check(...)` (without `apps=`) into a module in `seccheck/checks/`. It runs for all
applications; a profile can opt out with `exclude_checks`. If the finding can be fixed with web server
configuration, add an entry to `seccheck/core/fixes.py`.

Useful building blocks on `ScanContext`:

| | |
|---|---|
| `ctx.fetch(path, follow=, root=, method=, headers=)` | HTTP request; paths are relative to the install path, `root=True` makes them relative to the domain. Cached per scan. |
| `ctx.try_fetch(...)`, `ctx.get_json(...)` | return `None` instead of raising |
| `ctx.main_page()` | start page after redirects, shared by the header checks |
| `ctx.tls()`, `ctx.require_tls()` | certificate, chain, protocol and cipher |
| `ctx.memo(key, factory)` | run expensive work (detection, probes) once per scan |
| `raise SkipCheck(...)` | skip when a precondition is missing |
| `@check(..., timeout=120)` | longer timeout for slow checks |

Results: `passed()`, `warned()`, `failed()`, `info()`, `errored()` with optional `details` (dict → table,
list → list), `recommendation`, `references` and `severity` (overrides the check's severity for this finding).
Exceptions and timeouts are caught by the runner and reported as errors without affecting the grade.

## Translations

English is the source language. The backend wraps user-facing strings in `_()` from `seccheck.i18n`; the German
texts live in `seccheck/locales/de/*.json` (English msgid → translation). The frontend uses keys in
`static/locales/<lang>.json`.

```python
from ..i18n import _

return failed(
    _("Certificate expires in {days} days.", days=remaining),
    recommendation=_("Renew the certificate."),
)
```

Rules (enforced by `tests/test_i18n.py`):

- Pass placeholders as keyword arguments; never build the msgid with f-strings or concatenation.
- Check titles, descriptions (the docstring), app names and descriptions are plain English literals; they are
  translated when sent to the client but still need catalog entries.
- Constants defined at import time are marked with `N_()` and translated with `_()` where they are used.
- Do not use `_` as a throwaway variable in modules that import it.
- Every msgid needs an entry in every catalog, placeholders must match, and unused entries are reported.

**Adding a language:** add the code to `LANGUAGES` in `seccheck/i18n.py` and `static/js/i18n.js`, create
`seccheck/locales/<code>/` (copy the German files and translate the values) and `static/locales/<code>.json`.
The tests tell you what is missing.

## Pull requests

- Keep pull requests focused; one app or one feature per PR is easiest to review.
- Describe how you verified the change (Docker image and version, or upstream source links).
- Update `CHANGELOG.md` under "Unreleased".

By contributing you agree that your contribution is licensed under the AGPL-3.0-or-later, like the project.
Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).
