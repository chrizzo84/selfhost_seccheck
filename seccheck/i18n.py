"""Translations.

English is the source language: user-facing strings are written in English
and wrapped in ``_()``. Translations live in ``seccheck/locales/<lang>/*.json``
as ``{"English msgid": "translation"}``; all JSON files of a language are
merged, so every module group can keep its own file.

    from ..i18n import _

    _("Certificate expires in {days} days.", days=12)

The active language is a context variable. The API sets it per request
(Accept-Language), the scheduler from the notification settings; asyncio
tasks and threads started afterwards inherit it.

Rules (enforced by tests/test_i18n.py):
- The first argument of ``N_()`` is a string literal; ``_()`` takes a literal or
  a variable holding an ``N_()``-marked string, never an f-string or a built string.
- Placeholders use ``{name}`` and are passed as keyword arguments.
- Modules importing ``_`` must not use ``_`` as a throwaway variable.
- Strings defined at import time (constants, dict labels) are marked with
  ``N_()`` and translated with ``_()`` where they are used. Check titles,
  descriptions, app names/descriptions and category labels are translated
  automatically when they are sent to the client.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from contextvars import ContextVar
from functools import cache
from pathlib import Path
from typing import Any

from . import config

LANGUAGES = {"en": "English", "de": "Deutsch"}
SOURCE_LANGUAGE = "en"
LOCALES_DIR = Path(__file__).resolve().parent / "locales"


def normalize(value: str | None) -> str:
    """Pick a supported language from a code or an Accept-Language header."""
    if not value:
        return config.DEFAULT_LANGUAGE
    for part in value.split(","):
        code = part.split(";")[0].strip().lower().split("-")[0]
        if code in LANGUAGES:
            return code
    return config.DEFAULT_LANGUAGE


_DEFAULT = normalize(config.DEFAULT_LANGUAGE)
_current: ContextVar[str] = ContextVar("seccheck_language", default=_DEFAULT)


@cache
def catalog(lang: str) -> dict[str, str]:
    merged: dict[str, str] = {}
    folder = LOCALES_DIR / lang
    if folder.is_dir():
        for path in sorted(folder.glob("*.json")):
            merged.update(json.loads(path.read_text(encoding="utf-8")))
    return merged


def get_language() -> str:
    return _current.get()


def set_language(lang: str | None) -> None:
    _current.set(normalize(lang))


@contextlib.contextmanager
def language(lang: str | None) -> Iterator[None]:
    token = _current.set(normalize(lang))
    try:
        yield
    finally:
        # An async generator may be finished in another context; then the
        # variable simply stays set there, which is harmless.
        with contextlib.suppress(ValueError):
            _current.reset(token)


def _(msgid: str, /, **params: Any) -> str:
    """Translate ``msgid`` into the active language and fill in placeholders."""
    lang = _current.get()
    text = msgid if lang == SOURCE_LANGUAGE else catalog(lang).get(msgid, msgid)
    return text.format(**params) if params else text


def N_(msgid: str, /) -> str:
    """Mark a string for translation without translating it yet."""
    return msgid
