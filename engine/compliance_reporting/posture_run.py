"""
posture_run.py
==============
The unified posture-run record (Wave-H). A single, durable, tenant-scoped record
that links every stage of one end-to-end posture run so the whole chain is
independently traceable:

    connector collection → raw snapshot → immutable evidence →
    population reconciliation → config assertions → verified report → findings

Each `PostureRun` carries the linked IDs across those stages — the collection
manifest sha, the snapshot's immutable evidence sha, the assertion evaluation
summary, the verified report id, the opened finding ids, and the affected control
ids — so an auditor can walk from a control verdict back to the exact evidence
and collection that produced it, and forward to the remediation findings.

Backed by SQLite (WAL), mirroring the other durable stores.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any


class PostureRunStore:
    """Durable, per-tenant store of linked-ID posture runs."""

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "posture_runs.db"
        self._lock = Lock()
        self._conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS posture_runs (
                   run_id TEXT NOT NULL,
                   tenant TEXT NOT NULL,
                   completed_at TEXT,
                   report_id TEXT,
                   status TEXT NOT NULL,
                   run_json TEXT NOT NULL,
                   PRIMARY KEY (tenant, run_id)
               )"""
        )
        self._conn.commit()

    def save(self, run: dict[str, Any]) -> dict[str, Any]:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO posture_runs "
                "(run_id, tenant, completed_at, report_id, status, run_json) VALUES (?,?,?,?,?,?)",
                (run["run_id"], run["tenant"], run.get("completed_at"), run.get("report_id"),
                 run.get("status", "completed"), json.dumps(run, sort_keys=True)),
            )
        return run

    def get(self, tenant: str, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            r = self._conn.execute(
                "SELECT run_json FROM posture_runs WHERE tenant=? AND run_id=?",
                (tenant, run_id)).fetchone()
        return json.loads(r["run_json"]) if r else None

    def list(self, tenant: str, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT run_json FROM posture_runs WHERE tenant=? "
                "ORDER BY completed_at DESC, run_id LIMIT ?", (tenant, limit)).fetchall()
        return [json.loads(r["run_json"]) for r in rows]

    def latest(self, tenant: str) -> dict[str, Any] | None:
        runs = self.list(tenant, limit=1)
        return runs[0] if runs else None
