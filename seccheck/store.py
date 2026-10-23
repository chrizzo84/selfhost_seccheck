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
"""


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


@lru_cache(maxsize=1)
def get_store() -> Store:
    return Store(config.DATA_DIR / "seccheck.db")
