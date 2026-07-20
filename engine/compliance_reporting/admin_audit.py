"""
admin_audit.py
=============
Complete administrative audit log (Wave-I / Epic 6). Every privileged action is
recorded as an append-only, **hash-chained** entry so the log is tamper-evident:
each entry commits to the previous entry's hash, so any insertion, deletion, or
edit anywhere in the chain is detectable by re-walking it.

Per-tenant chains (tenant isolation + independent verification). Backed by
SQLite (WAL); the Postgres + RLS production schema is shipped in deploy/db.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any


def _entry_hash(tenant: str, seq: int, actor: str, action: str, target: str,
                outcome: str, details: dict[str, Any], at: str, prev_hash: str) -> str:
    basis = json.dumps({
        "tenant": tenant, "seq": seq, "actor": actor, "action": action, "target": target,
        "outcome": outcome, "details": details, "at": at, "prev_hash": prev_hash,
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(basis.encode()).hexdigest()


class AdminAuditLog:
    """Durable, per-tenant, append-only, hash-chained administrative audit log."""

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "admin_audit.db"
        self._lock = Lock()
        self._conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS admin_audit (
                   tenant TEXT NOT NULL,
                   seq INTEGER NOT NULL,
                   actor TEXT NOT NULL,
                   action TEXT NOT NULL,
                   target TEXT NOT NULL,
                   outcome TEXT NOT NULL,
                   details TEXT NOT NULL,
                   at TEXT NOT NULL,
                   prev_hash TEXT NOT NULL,
                   entry_hash TEXT NOT NULL,
                   PRIMARY KEY (tenant, seq)
               )"""
        )
        self._conn.commit()

    def _row(self, r: sqlite3.Row) -> dict[str, Any]:
        return {
            "tenant": r["tenant"], "seq": r["seq"], "actor": r["actor"], "action": r["action"],
            "target": r["target"], "outcome": r["outcome"], "details": json.loads(r["details"]),
            "at": r["at"], "prev_hash": r["prev_hash"], "entry_hash": r["entry_hash"],
        }

    def append(self, *, tenant: str, actor: str, action: str, at: str, target: str = "",
               outcome: str = "ok", details: dict[str, Any] | None = None) -> dict[str, Any]:
        details = details or {}
        with self._lock, self._conn:
            last = self._conn.execute(
                "SELECT seq, entry_hash FROM admin_audit WHERE tenant=? ORDER BY seq DESC LIMIT 1",
                (tenant,)).fetchone()
            seq = (last["seq"] + 1) if last else 1
            prev_hash = last["entry_hash"] if last else ""
            h = _entry_hash(tenant, seq, actor, action, target, outcome, details, at, prev_hash)
            self._conn.execute(
                "INSERT INTO admin_audit (tenant, seq, actor, action, target, outcome, details, "
                "at, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (tenant, seq, actor, action, target, outcome, json.dumps(details, sort_keys=True),
                 at, prev_hash, h),
            )
        return {"tenant": tenant, "seq": seq, "actor": actor, "action": action, "target": target,
                "outcome": outcome, "details": details, "at": at, "prev_hash": prev_hash,
                "entry_hash": h}

    def list(self, tenant: str, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM admin_audit WHERE tenant=? ORDER BY seq DESC LIMIT ?",
                (tenant, limit)).fetchall()
        return [self._row(r) for r in rows]

    def verify(self, tenant: str) -> dict[str, Any]:
        """Re-walk the chain; detect any tamper (edit/insert/delete)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM admin_audit WHERE tenant=? ORDER BY seq", (tenant,)).fetchall()
        prev_hash = ""
        expected_seq = 1
        for r in rows:
            if r["seq"] != expected_seq:
                return {"ok": False, "checked": expected_seq - 1, "break_at": r["seq"],
                        "reason": "sequence gap (deleted/reordered entry)"}
            if r["prev_hash"] != prev_hash:
                return {"ok": False, "checked": expected_seq - 1, "break_at": r["seq"],
                        "reason": "broken chain link"}
            recomputed = _entry_hash(r["tenant"], r["seq"], r["actor"], r["action"], r["target"],
                                     r["outcome"], json.loads(r["details"]), r["at"], r["prev_hash"])
            if recomputed != r["entry_hash"]:
                return {"ok": False, "checked": expected_seq - 1, "break_at": r["seq"],
                        "reason": "entry hash mismatch (tampered content)"}
            prev_hash = r["entry_hash"]
            expected_seq += 1
        return {"ok": True, "checked": len(rows), "break_at": None, "reason": None}
