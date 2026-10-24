"""SQLite persistence for scan targets, scan history and settings.

All methods are synchronous; async code calls them via asyncio.to_thread and
FastAPI runs plain ``def`` endpoints in its thread pool. One connection is
shared behind a lock, which is plenty for a single-user tool.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import config
from .cve.matching import merge

SCHEDULES: dict[str, timedelta | None] = {
    "off": None,
    "6h": timedelta(hours=6),
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY,
    app TEXT NOT NULL,
    url TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    schedule TEXT NOT NULL DEFAULT 'off',
    notify INTEGER NOT NULL DEFAULT 1,
    accepted TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    UNIQUE (app, url)
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    trigger TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    grade TEXT NOT NULL,
    score INTEGER NOT NULL,
    rating TEXT NOT NULL,
    results TEXT NOT NULL,
    fixes TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_by_target ON scans (target_id, finished_at);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- CVE feed: one row per vulnerability and product. "sources" holds what each
-- source said (source key -> entry), "data" the merged record for display.
CREATE TABLE IF NOT EXISTS cve_vulns (
    product TEXT NOT NULL,
    id TEXT NOT NULL,
    sources TEXT NOT NULL,
    data TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (product, id)
);
CREATE TABLE IF NOT EXISTS cve_sync (
    source TEXT PRIMARY KEY,
    synced_at TEXT,
    attempted_at TEXT NOT NULL,
    error TEXT
);
CREATE TABLE IF NOT EXISTS cve_kev (
    cve_id TEXT PRIMARY KEY,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cve_epss (
    cve_id TEXT PRIMARY KEY,
    score REAL NOT NULL,
    percentile REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cve_watch (
    id INTEGER PRIMARY KEY,
    product TEXT NOT NULL,
    version TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
-- Last evaluated product/version per subject ("target:3", "watch:1") and the
-- vulnerabilities it was affected by then, to alert only on changes.
CREATE TABLE IF NOT EXISTS cve_subjects (
    subject TEXT PRIMARY KEY,
    product TEXT NOT NULL,
    version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cve_matches (
    subject TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    kev INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (subject, vuln_id)
);
"""

# Columns added after the first release: (table, column, definition).
MIGRATIONS = [
    ("targets", "product", "TEXT"),
    ("targets", "version", "TEXT"),
    ("targets", "detected_at", "TEXT"),
]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _target(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["notify"] = bool(data["notify"])
    data["accepted"] = json.loads(data["accepted"])
    return data


def _scan(row: sqlite3.Row, *, full: bool = True) -> dict[str, Any]:
    data = dict(row)
    data["rating"] = json.loads(data["rating"])
    if full:
        data["results"] = json.loads(data["results"])
        data["fixes"] = json.loads(data["fixes"])
    else:
        data.pop("results", None)
        data.pop("fixes", None)
    return data


class Store:
    def __init__(self, path: Path | str):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute("PRAGMA foreign_keys = ON")
            self._db.execute("PRAGMA journal_mode = WAL")
            self._db.executescript(SCHEMA)
            for table, column, definition in MIGRATIONS:
                columns = {row["name"] for row in self._db.execute(f"PRAGMA table_info({table})")}
                if column not in columns:
                    self._db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _query(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, params).fetchall()

    def _write(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self._lock, self._db:
            return self._db.execute(sql, params).lastrowid or 0

    # --- targets ----------------------------------------------------------

    def get_or_create_target(self, app: str, url: str) -> dict[str, Any]:
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO targets (app, url, created_at) VALUES (?, ?, ?)", (app, url, _now())
            )
            row = self._db.execute("SELECT * FROM targets WHERE app = ? AND url = ?", (app, url)).fetchone()
        return _target(row)

    def get_target(self, target_id: int) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM targets WHERE id = ?", (target_id,))
        return _target(rows[0]) if rows else None

    def list_targets(self, history: int = 12) -> list[dict[str, Any]]:
        targets = [_target(r) for r in self._query("SELECT * FROM targets ORDER BY label = '', label, url")]
        for t in targets:
            rows = self._query(
                "SELECT id, finished_at, grade, score, rating FROM scans WHERE target_id = ? "
                "ORDER BY finished_at DESC LIMIT ?",
                (t["id"], history),
            )
            t["last_scan"] = None
            if rows:
                last = dict(rows[0])
                last["counts"] = json.loads(last.pop("rating"))["counts"]
                t["last_scan"] = last
            t["history"] = [
                {"finished_at": r["finished_at"], "score": r["score"], "grade": r["grade"]} for r in reversed(rows)
            ]
        return targets

    def update_target(self, target_id: int, **fields: Any) -> dict[str, Any] | None:
        allowed = {"label", "schedule", "notify", "accepted"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if "schedule" in updates and updates["schedule"] not in SCHEDULES:
            raise ValueError(f"Unknown schedule: {updates['schedule']}")
        if "accepted" in updates:
            updates["accepted"] = json.dumps(sorted(set(updates["accepted"])))
        if "notify" in updates:
            updates["notify"] = int(bool(updates["notify"]))
        if updates:
            assignments = ", ".join(f"{k} = ?" for k in updates)
            self._write(f"UPDATE targets SET {assignments} WHERE id = ?", (*updates.values(), target_id))
        return self.get_target(target_id)

    def set_target_software(self, target_id: int, product: str | None, version: str | None) -> bool:
        """Remember what a scan detected. Returns True when product or version changed."""
        with self._lock, self._db:
            row = self._db.execute("SELECT product, version FROM targets WHERE id = ?", (target_id,)).fetchone()
            changed = row is not None and (row["product"], row["version"]) != (product, version)
            self._db.execute(
                "UPDATE targets SET product = ?, version = ?, detected_at = ? WHERE id = ?",
                (product, version, _now(), target_id),
            )
        return changed

    def delete_target(self, target_id: int) -> None:
        self._write("DELETE FROM targets WHERE id = ?", (target_id,))

    def due_targets(self, now: datetime | None = None) -> list[dict[str, Any]]:
        now = now or datetime.now(UTC)
        due = []
        for row in self._query("SELECT * FROM targets WHERE schedule != 'off'"):
            target = _target(row)
            interval = SCHEDULES.get(target["schedule"])
            if interval is None:
                continue
            last = self._query(
                "SELECT finished_at FROM scans WHERE target_id = ? ORDER BY finished_at DESC LIMIT 1",
                (target["id"],),
            )
            if not last or datetime.fromisoformat(last[0]["finished_at"]) + interval <= now:
                due.append(target)
        return due

    # --- scans ------------------------------------------------------------

    def add_scan(
        self,
        target_id: int,
        *,
        trigger: str,
        started_at: str,
        finished_at: str,
        rating: dict[str, Any],
        results: list[dict[str, Any]],
        fixes: dict[str, str],
    ) -> int:
        return self._write(
            "INSERT INTO scans (target_id, trigger, started_at, finished_at, grade, score, rating, results, fixes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                target_id,
                trigger,
                started_at,
                finished_at,
                rating["grade"],
                rating["score"],
                json.dumps(rating, ensure_ascii=False),
                json.dumps(results, ensure_ascii=False),
                json.dumps(fixes, ensure_ascii=False),
            ),
        )

    def update_scan(
        self, scan_id: int, *, rating: dict[str, Any], results: list[dict[str, Any]], fixes: dict[str, str]
    ) -> None:
        self._write(
            "UPDATE scans SET grade = ?, score = ?, rating = ?, results = ?, fixes = ? WHERE id = ?",
            (
                rating["grade"],
                rating["score"],
                json.dumps(rating, ensure_ascii=False),
                json.dumps(results, ensure_ascii=False),
                json.dumps(fixes, ensure_ascii=False),
                scan_id,
            ),
        )

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return _scan(rows[0]) if rows else None

    def latest_scan(self, target_id: int) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM scans WHERE target_id = ? ORDER BY finished_at DESC LIMIT 1", (target_id,))
        return _scan(rows[0]) if rows else None

    def previous_scan(self, scan: dict[str, Any]) -> dict[str, Any] | None:
        rows = self._query(
            "SELECT * FROM scans WHERE target_id = ? AND finished_at < ? ORDER BY finished_at DESC LIMIT 1",
            (scan["target_id"], scan["finished_at"]),
        )
        return _scan(rows[0]) if rows else None

    def list_scans(self, target_id: int, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT * FROM scans WHERE target_id = ? ORDER BY finished_at DESC LIMIT ?", (target_id, limit)
        )
        return [_scan(r, full=False) for r in rows]

    # --- settings ---------------------------------------------------------

    def get_setting(self, key: str, default: Any = None) -> Any:
        rows = self._query("SELECT value FROM settings WHERE key = ?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def set_setting(self, key: str, value: Any) -> None:
        self._write(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value, ensure_ascii=False)),
        )

    # --- CVE feed -----------------------------------------------------------

    def cve_upsert(self, product: str, source: str, entries: list[dict[str, Any]], *, replace: bool = False) -> int:
        """Store what ``source`` says about ``product``'s vulnerabilities. Returns the number of new ones.

        Entries of one vulnerability from different sources are merged into one
        row; a row first stored under its GHSA id moves to the CVE id once one
        is assigned. ``replace`` means ``entries`` is the source's complete list,
        so the source is removed from vulnerabilities that are no longer in it.
        """
        with self._lock, self._db:
            rows = {
                r["id"]: {"sources": json.loads(r["sources"]), "first_seen": r["first_seen"]}
                for r in self._db.execute("SELECT id, sources, first_seen FROM cve_vulns WHERE product = ?", (product,))
            }
            alias_of: dict[str, str] = {}
            for vuln_id, row in rows.items():
                for entry in row["sources"].values():
                    for alias in (entry["id"], *entry.get("aliases", [])):
                        alias_of.setdefault(alias, vuln_id)

            touched: set[str] = set()
            seen: set[str] = set()
            new = 0
            for entry in entries:
                ids = {entry["id"], *entry.get("aliases", [])}
                existing = {alias_of[i] for i in ids if i in alias_of and alias_of[i] in rows}
                cves = sorted(i for i in ids | existing if i.startswith("CVE-"))
                vuln_id = cves[0] if cves else entry["id"]
                merged: dict[str, Any] = {}
                first_seen = _now()
                for old in existing:
                    merged.update(rows[old]["sources"])
                    first_seen = min(first_seen, rows[old]["first_seen"])
                    if old != vuln_id:
                        rows.pop(old)
                        touched.add(old)
                if entry.get("withdrawn"):
                    merged.pop(source, None)
                else:
                    merged[source] = entry
                    seen.add(vuln_id)
                if not existing and not entry.get("withdrawn"):
                    new += 1
                rows[vuln_id] = {"sources": merged, "first_seen": first_seen}
                touched.add(vuln_id)
                for alias in ids | existing:
                    alias_of[alias] = vuln_id

            if replace:
                for vuln_id, row in rows.items():
                    if source in row["sources"] and vuln_id not in seen:
                        row["sources"].pop(source)
                        touched.add(vuln_id)

            for vuln_id in touched:
                row = rows.get(vuln_id)
                if not row or not row["sources"]:
                    self._db.execute("DELETE FROM cve_vulns WHERE product = ? AND id = ?", (product, vuln_id))
                    continue
                self._db.execute(
                    "INSERT INTO cve_vulns (product, id, sources, data, first_seen) VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT (product, id) DO UPDATE SET sources = excluded.sources, data = excluded.data",
                    (
                        product,
                        vuln_id,
                        json.dumps(row["sources"], ensure_ascii=False),
                        json.dumps(merge(vuln_id, row["sources"]), ensure_ascii=False),
                        row["first_seen"],
                    ),
                )
        return new

    def cve_vulns(self, products: list[str]) -> list[dict[str, Any]]:
        if not products:
            return []
        marks = ", ".join("?" for _p in products)
        rows = self._query(f"SELECT * FROM cve_vulns WHERE product IN ({marks})", tuple(products))
        return [
            {
                "product": r["product"],
                "id": r["id"],
                "sources": json.loads(r["sources"]),
                "data": json.loads(r["data"]),
                "first_seen": r["first_seen"],
            }
            for r in rows
        ]

    def cve_ids(self) -> list[str]:
        return [r["id"] for r in self._query("SELECT DISTINCT id FROM cve_vulns WHERE id LIKE 'CVE-%' ORDER BY id")]

    def cve_sync_state(self) -> dict[str, dict[str, Any]]:
        return {r["source"]: dict(r) for r in self._query("SELECT * FROM cve_sync")}

    def set_cve_sync(self, source: str, *, synced_at: str | None, error: str | None) -> None:
        self._write(
            "INSERT INTO cve_sync (source, synced_at, attempted_at, error) VALUES (?, ?, ?, ?) "
            "ON CONFLICT (source) DO UPDATE SET synced_at = excluded.synced_at, "
            "attempted_at = excluded.attempted_at, error = excluded.error",
            (source, synced_at, _now(), error),
        )

    def set_cve_kev(self, catalog: dict[str, dict[str, Any]]) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM cve_kev")
            self._db.executemany(
                "INSERT INTO cve_kev (cve_id, data) VALUES (?, ?)",
                [(cve, json.dumps(data, ensure_ascii=False)) for cve, data in catalog.items()],
            )

    def cve_kev(self) -> dict[str, dict[str, Any]]:
        return {r["cve_id"]: json.loads(r["data"]) for r in self._query("SELECT * FROM cve_kev")}

    def set_cve_epss(self, scores: dict[str, tuple[float, float]]) -> None:
        with self._lock, self._db:
            self._db.executemany(
                "INSERT INTO cve_epss (cve_id, score, percentile) VALUES (?, ?, ?) "
                "ON CONFLICT (cve_id) DO UPDATE SET score = excluded.score, percentile = excluded.percentile",
                [(cve, score, pct) for cve, (score, pct) in scores.items()],
            )

    def cve_epss(self) -> dict[str, dict[str, float]]:
        return {
            r["cve_id"]: {"score": r["score"], "percentile": r["percentile"]}
            for r in self._query("SELECT * FROM cve_epss")
        }

    def cve_targets(self) -> list[dict[str, Any]]:
        rows = self._query("SELECT id, app, url, label, product, version FROM targets ORDER BY label = '', label, url")
        return [dict(r) for r in rows]

    def list_watch(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._query("SELECT * FROM cve_watch ORDER BY product, version")]

    def add_watch(self, product: str, version: str, label: str = "") -> dict[str, Any]:
        watch_id = self._write(
            "INSERT INTO cve_watch (product, version, label, created_at) VALUES (?, ?, ?, ?)",
            (product, version, label, _now()),
        )
        return dict(self._query("SELECT * FROM cve_watch WHERE id = ?", (watch_id,))[0])

    def update_watch(self, watch_id: int, *, version: str | None = None, label: str | None = None) -> None:
        if version is not None:
            self._write("UPDATE cve_watch SET version = ? WHERE id = ?", (version, watch_id))
        if label is not None:
            self._write("UPDATE cve_watch SET label = ? WHERE id = ?", (label, watch_id))

    def get_watch(self, watch_id: int) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM cve_watch WHERE id = ?", (watch_id,))
        return dict(rows[0]) if rows else None

    def delete_watch(self, watch_id: int) -> None:
        self._write("DELETE FROM cve_watch WHERE id = ?", (watch_id,))

    def cve_subject(self, subject: str) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM cve_subjects WHERE subject = ?", (subject,))
        return dict(rows[0]) if rows else None

    def cve_matches(self, subject: str) -> dict[str, dict[str, Any]]:
        rows = self._query("SELECT * FROM cve_matches WHERE subject = ?", (subject,))
        return {r["vuln_id"]: dict(r) for r in rows}

    def set_cve_matches(self, subject: str, product: str, version: str, matches: dict[str, dict[str, Any]]) -> None:
        """Replace a subject's matches; ``matches`` maps vuln id -> {"severity", "kev"}."""
        with self._lock, self._db:
            known = {
                r["vuln_id"]: r["first_seen"]
                for r in self._db.execute("SELECT vuln_id, first_seen FROM cve_matches WHERE subject = ?", (subject,))
            }
            self._db.execute("DELETE FROM cve_matches WHERE subject = ?", (subject,))
            self._db.executemany(
                "INSERT INTO cve_matches (subject, vuln_id, severity, kev, first_seen) VALUES (?, ?, ?, ?, ?)",
                [
                    (subject, vuln_id, m["severity"], int(bool(m["kev"])), known.get(vuln_id, _now()))
                    for vuln_id, m in matches.items()
                ],
            )
            self._db.execute(
                "INSERT INTO cve_subjects (subject, product, version) VALUES (?, ?, ?) "
                "ON CONFLICT (subject) DO UPDATE SET product = excluded.product, version = excluded.version",
                (subject, product, version),
            )

    def prune_cve_subjects(self, keep: set[str]) -> None:
        with self._lock, self._db:
            for (subject,) in self._db.execute("SELECT subject FROM cve_subjects").fetchall():
                if subject not in keep:
                    self._db.execute("DELETE FROM cve_subjects WHERE subject = ?", (subject,))
                    self._db.execute("DELETE FROM cve_matches WHERE subject = ?", (subject,))

    def cve_match_counts(self) -> dict[str, dict[str, int]]:
        """subject -> {"total", "kev"} from the last evaluation."""
        rows = self._query("SELECT subject, COUNT(*) AS total, SUM(kev) AS kev FROM cve_matches GROUP BY subject")
        return {r["subject"]: {"total": r["total"], "kev": r["kev"] or 0} for r in rows}


@lru_cache(maxsize=1)
def get_store() -> Store:
    return Store(config.DATA_DIR / "seccheck.db")
