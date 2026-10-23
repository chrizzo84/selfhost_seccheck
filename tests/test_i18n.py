"""Keeps translations complete and the source language English."""

from __future__ import annotations

import ast
import json
import re
import string
from pathlib import Path

import pytest

from seccheck.core.registry import CATEGORIES, all_apps, all_checks, load_plugins
from seccheck.i18n import LANGUAGES, SOURCE_LANGUAGE, _, catalog, language

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "seccheck"
STATIC_LOCALES = ROOT / "static" / "locales"
UMLAUT = re.compile(r"[äöüÄÖÜß]")
TRANSLATED_LANGUAGES = [lang for lang in LANGUAGES if lang != SOURCE_LANGUAGE]


def _python_files() -> list[Path]:
    return sorted(p for p in PACKAGE.rglob("*.py") if "locales" not in p.parts)


def _imports_underscore(tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module
        and node.module.endswith("i18n")
        and any(a.name == "_" for a in node.names)
        for node in ast.walk(tree)
    )


def _marked_msgids() -> tuple[set[str], list[str]]:
    """All literals passed to _() / N_(), plus violations of the call rules."""
    msgids: set[str] = set()
    problems: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        rel = path.relative_to(ROOT)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"_", "N_"}:
                arg = node.args[0] if node.args else None
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    msgids.add(arg.value)
                elif node.func.id == "N_" or isinstance(arg, (ast.JoinedStr, ast.BinOp, ast.Call)) or arg is None:
                    # _(variable) is fine for strings marked with N_() elsewhere;
                    # built strings can never match a catalog entry.
                    problems.append(f"{rel}:{node.lineno}: {node.func.id}() needs a string literal, not a built string")
        if _imports_underscore(tree):
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id == "_" and isinstance(node.ctx, ast.Store):
                    problems.append(f"{rel}:{node.lineno}: '_' is reassigned, which shadows the translation function")
    return msgids, problems


def _registry_msgids() -> set[str]:
    load_plugins()
    ids = set(CATEGORIES.values())
    for spec in all_checks():
        ids.add(spec.title)
        if spec.description:
            ids.add(spec.description)
    for app in all_apps():
        ids.update({app.name, app.description})
    return ids


def _placeholders(text: str) -> set[str]:
    return {name for _lit, name, _spec, _conv in string.Formatter().parse(text) if name}


def test_translation_calls_follow_the_rules() -> None:
    _msgids, problems = _marked_msgids()
    assert not problems, "\n".join(problems)


def test_source_strings_are_english() -> None:
    """German literals left in the code would never be translated."""
    offenders = []
    for path in _python_files():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and UMLAUT.search(node.value):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}: {node.value[:60]!r}")
    assert not offenders, "Non-English source strings:\n" + "\n".join(offenders)


@pytest.mark.parametrize("lang", TRANSLATED_LANGUAGES)
def test_catalog_is_complete_and_has_no_leftovers(lang: str) -> None:
    marked, _problems = _marked_msgids()
    needed = marked | _registry_msgids()
    entries = catalog(lang)
    missing = sorted(m for m in needed if m not in entries)
    unused = sorted(k for k in entries if k not in needed)
    assert not missing, f"Missing {lang} translations:\n" + "\n".join(missing)
    assert not unused, f"Unused {lang} catalog entries:\n" + "\n".join(unused)


@pytest.mark.parametrize("lang", TRANSLATED_LANGUAGES)
def test_shared_msgids_are_translated_identically(lang: str) -> None:
    """Catalog files are merged; a msgid in two files must not get two translations."""
    seen: dict[str, tuple[str, str]] = {}
    conflicts = []
    for path in sorted((PACKAGE / "locales" / lang).glob("*.json")):
        for msgid, text in json.loads(path.read_text(encoding="utf-8")).items():
            if msgid in seen and seen[msgid][1] != text:
                conflicts.append(f"{msgid!r}: {seen[msgid][0]}={seen[msgid][1]!r} vs {path.name}={text!r}")
            seen.setdefault(msgid, (path.name, text))
    assert not conflicts, "Conflicting translations:\n" + "\n".join(conflicts)


@pytest.mark.parametrize("lang", TRANSLATED_LANGUAGES)
def test_placeholders_match(lang: str) -> None:
    wrong = [
        f"{msgid!r} -> {text!r}" for msgid, text in catalog(lang).items() if _placeholders(msgid) != _placeholders(text)
    ]
    assert not wrong, "Placeholder mismatch:\n" + "\n".join(wrong)


def test_frontend_locales_match() -> None:
    files = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in STATIC_LOCALES.glob("*.json")}
    assert set(files) == set(LANGUAGES)
    reference = files[SOURCE_LANGUAGE]
    for lang, entries in files.items():
        assert set(entries) == set(reference), f"static/locales/{lang}.json keys differ from {SOURCE_LANGUAGE}.json"
        for key, text in entries.items():
            assert _placeholders(text) == _placeholders(reference[key]), f"{lang}:{key} placeholders differ"


def test_translation_switches_with_language() -> None:
    with language("de"):
        assert _("Certificate details") == catalog("de")["Certificate details"]
    assert _("Certificate details") == "Certificate details"
