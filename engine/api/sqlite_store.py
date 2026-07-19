"""
sqlite_store.py
===============
Durable, transactional persistence for jobs and the report index (Wave 4,
FUR-OPS-001/002). The pre-Wave-4 state was in-process job memory (lost on
restart) and an append-only filesystem index (no cross-process locking). This
module backs both with SQLite — transactional, crash-safe, and safe across
processes — using the standard library only.

SQLite here is the same interface a Postgres backend would implement, so the
production swap is a connection string, not a rewrite: identical method
signatures, parameterised SQL, one row per job / index entry.

WAL mode + a short busy-timeout make concurrent readers/writers safe for the
single-box deployment; the schema and queries are Postgres-portable.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


class DurableJobStore:
    """Crash-safe job records — survive a process restart (FUR-OPS-001)."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._conn = _connect(self.path)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS jobs (
                   job_id TEXT PRIMARY KEY,
                   owner TEXT,
                   status TEXT NOT NULL,
                   phase TEXT NOT NULL,
                   processed INTEGER NOT NULL DEFAULT 0,
                   total INTEGER NOT NULL DEFAULT 0,
                   result TEXT,
                   error TEXT,
                   created_at REAL NOT NULL,
                   updated_at REAL NOT NULL
               )"""
        )
        self._conn.commit()

    def create(self, job_id: str, owner: str | None, created_at: float) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO jobs (job_id, owner, status, phase, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?)",
                (job_id, owner, "queued", "queued", created_at, created_at),
            )

    def update(self, job_id: str, updated_at: float, **fields: Any) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        vals = [json.dumps(v) if k == "result" and v is not None else v
                for k, v in fields.items()]
        with self._conn:
            self._conn.execute(
                f"UPDATE jobs SET {cols}, updated_at=? WHERE job_id=?",
                (*vals, updated_at, job_id),
            )

    def get(self, job_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["result"] = json.loads(d["result"]) if d.get("result") else None
        return d

    def recover_stuck(self, updated_at: float) -> int:
        """On startup, mark jobs left 'running' by a crash as errored (recovery)."""
        with self._conn:
            cur = self._conn.execute(
                "UPDATE jobs SET status='error', phase='error', "
                "error='interrupted by restart', updated_at=? "
                "WHERE status IN ('queued','running')",
                (updated_at,),
            )
            return cur.rowcount

    def prune(self, keep: int = 500) -> None:
        with self._conn:
            self._conn.execute(
                "DELETE FROM jobs WHERE job_id NOT IN "
                "(SELECT job_id FROM jobs ORDER BY created_at DESC LIMIT ?)",
                (keep,),
            )


class DurableIndex:
    """Transactional report index — replaces the append-only JSONL (FUR-OPS-002)."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._conn = _connect(self.path)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS report_index (
                   report_id TEXT PRIMARY KEY,
                   generated_at TEXT,
                   window_end TEXT,
                   total_logs INTEGER,
                   successful_logs INTEGER,
                   total_violations INTEGER,
                   payload TEXT NOT NULL
               )"""
        )
        self._conn.commit()

    def upsert(self, entry: dict[str, Any]) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO report_index "
                "(report_id, generated_at, window_end, total_logs, successful_logs, "
                " total_violations, payload) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(report_id) DO UPDATE SET payload=excluded.payload",
                (entry["report_id"], entry.get("generated_at"), entry.get("window_end"),
                 entry.get("total_logs"), entry.get("successful_logs"),
                 entry.get("total_violations"), json.dumps(entry, sort_keys=True)),
            )

    def entries(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT payload FROM report_index ORDER BY COALESCE(window_end, generated_at), report_id"
        ).fetchall()
        return [json.loads(r["payload"]) for r in rows]

    def latest(self, n: int = 1) -> list[dict[str, Any]]:
        return self.entries()[-n:]
