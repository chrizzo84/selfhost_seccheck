"""Registry for checks and app profiles.

Checks register themselves with the ``@check`` decorator, apps with
``register_app``. Modules in ``seccheck.checks`` and ``seccheck.apps`` are
imported automatically, so adding a new file is all it takes to extend the
scanner.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .models import Outcome, Severity

if TYPE_CHECKING:
    from .context import ScanContext

CheckFunc = Callable[["ScanContext"], Awaitable[Outcome]]

# Display order and labels of check categories (translated when sent to clients).
CATEGORIES: dict[str, str] = {
    "tls": "TLS & certificate",
    "transport": "HTTP & transport",
    "headers": "Security headers",
    "exposure": "Exposed files",
    "app": "Application",
    "dns": "DNS",
    "hygiene": "Best practices",
}


@dataclass(frozen=True)
class CheckSpec:
    id: str
    title: str
    category: str
    severity: Severity
    func: CheckFunc
    description: str = ""
    # None means the check applies to every app profile.
    apps: frozenset[str] | None = None
    # Overrides SECCHECK_CHECK_TIMEOUT for slow checks (seconds).
    timeout: float | None = None


@dataclass(frozen=True)
class AppProfile:
    id: str
    name: str
    description: str
    short: str
    color: str = "#64748b"
    url_hint: str = "https://app.example.com"
    # Generic checks that do not make sense for this app.
    exclude_checks: frozenset[str] = frozenset()
    # App-relative API paths that the CORS check should probe in addition to
    # the start page.
    cors_paths: tuple[str, ...] = ()
    # Regexes (matched against the app-relative path) that must never be
    # requested, e.g. because the app counts unauthenticated requests as
    # failed logins and would ban the scanner's IP.
    no_probe_paths: tuple[str, ...] = ()
    order: int = 100


@dataclass(frozen=True)
class Detection:
    """Result of an app detector: the app answers at this URL."""

    product: str
    version: str | None = None


DetectFunc = Callable[["ScanContext"], Awaitable[Detection | None]]

_CHECKS: dict[str, CheckSpec] = {}
_APPS: dict[str, AppProfile] = {}
_DETECTORS: dict[str, DetectFunc] = {}


def check(
    id: str,
    *,
    title: str,
    category: str,
    severity: Severity,
    description: str = "",
    apps: Iterable[str] | None = None,
    timeout: float | None = None,
) -> Callable[[CheckFunc], CheckFunc]:
    if category not in CATEGORIES:
        raise ValueError(f"Unknown category {category!r} for check {id!r}")

    def decorator(func: CheckFunc) -> CheckFunc:
        if id in _CHECKS:
            raise ValueError(f"Duplicate check id {id!r}")
        _CHECKS[id] = CheckSpec(
            id=id,
            title=title,
            category=category,
            severity=severity,
            func=func,
            description=description or (func.__doc__ or "").strip(),
            apps=frozenset(apps) if apps is not None else None,
            timeout=timeout,
        )
        return func

    return decorator


def register_app(profile: AppProfile) -> AppProfile:
    if profile.id in _APPS:
        raise ValueError(f"Duplicate app id {profile.id!r}")
    _APPS[profile.id] = profile
    return profile


def detector(app_id: str) -> Callable[[DetectFunc], DetectFunc]:
    """Register how to recognise an app. Used by auto-detection and the app's detect check.

    Detectors must only send requests that are harmless for *every* app,
    because auto-detection runs all of them against an unknown target.
    They return None when the app is not found and must not raise.
    """

    def decorator(func: DetectFunc) -> DetectFunc:
        if app_id in _DETECTORS:
            raise ValueError(f"Duplicate detector for {app_id!r}")
        _DETECTORS[app_id] = func
        return func

    return decorator


def get_detector(app_id: str) -> DetectFunc | None:
    return _DETECTORS.get(app_id)


def all_detectors() -> dict[str, DetectFunc]:
    return dict(_DETECTORS)


def get_app(app_id: str) -> AppProfile | None:
    return _APPS.get(app_id)


def all_apps() -> list[AppProfile]:
    return sorted(_APPS.values(), key=lambda a: (a.order, a.name.lower()))


def all_checks() -> list[CheckSpec]:
    return list(_CHECKS.values())


def checks_for(app: AppProfile) -> list[CheckSpec]:
    """Checks that run for an app, in display order (category, then registration)."""
    category_rank = {key: i for i, key in enumerate(CATEGORIES)}
    selected = [
        spec
        for spec in _CHECKS.values()
        if (spec.apps is None or app.id in spec.apps) and spec.id not in app.exclude_checks
    ]
    # sorted() is stable, so registration order is kept within a category.
    return sorted(selected, key=lambda s: category_rank[s.category])


@dataclass
class _Loaded:
    done: bool = False
    modules: list[str] = field(default_factory=list)


_loaded = _Loaded()


def load_plugins() -> None:
    """Import every module in seccheck.checks and seccheck.apps exactly once."""
    if _loaded.done:
        return
    import importlib
    import pkgutil

    from .. import apps, checks

    for package in (checks, apps):
        for mod in pkgutil.iter_modules(package.__path__):
            if mod.name.startswith("_"):
                continue
            name = f"{package.__name__}.{mod.name}"
            importlib.import_module(name)
            _loaded.modules.append(name)
    _loaded.done = True
