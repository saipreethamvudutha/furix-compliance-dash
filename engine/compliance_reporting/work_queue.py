"""
work_queue.py
============
A durable work queue + worker (Wave-I / Epic 6). Today the connector scheduler
runs collections synchronously inside the API request. A real deployment wants an
async worker plane so long collections don't block requests and survive restarts.

This is a SQLite-backed, lease-based queue (the interface-compatible substrate;
Postgres `SELECT ... FOR UPDATE SKIP LOCKED` is the multi-worker upgrade shipped
in deploy/db):

* `enqueue` a tenant-scoped job,
* `claim` leases one queued job to a worker for `lease_seconds` (atomic — two
  workers never get the same job),
* `complete` / `fail` (with bounded exponential backoff + max attempts → dead),
* `requeue_expired` returns crashed-worker jobs (lease elapsed) to the queue.

`Worker.run_once` claims + runs one job via an injected handler; time is injected
so scheduling is deterministic in tests.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from threading import Lock
from typing import Any, Callable

QUEUED = "queued"
RUNNING = "running"
DONE = "done"
FAILED = "failed"
DEAD = "dead"


class WorkQueue:
    def __init__(self, root: Path | str, *, max_attempts: int = 3, base_backoff: int = 30):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "work_queue.db"
        self.max_attempts = max_attempts
        self.base_backoff = base_backoff
        self._lock = Lock()
        self._conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS jobs (
                   job_id TEXT PRIMARY KEY,
                   tenant TEXT NOT NULL,
                   kind TEXT NOT NULL,
                   payload TEXT NOT NULL,
                   status TEXT NOT NULL,
                   attempts INTEGER NOT NULL DEFAULT 0,
                   run_after INTEGER NOT NULL DEFAULT 0,
                   lease_expires INTEGER,
                   worker TEXT,
                   last_error TEXT,
                   enqueued_at INTEGER NOT NULL
               )"""
        )
        self._conn.commit()

    def _row(self, r: sqlite3.Row) -> dict[str, Any]:
        return {
            "job_id": r["job_id"], "tenant": r["tenant"], "kind": r["kind"],
            "payload": json.loads(r["payload"]), "status": r["status"],
            "attempts": r["attempts"], "run_after": r["run_after"],
            "lease_expires": r["lease_expires"], "worker": r["worker"],
            "last_error": r["last_error"], "enqueued_at": r["enqueued_at"],
        }

    def enqueue(self, *, tenant: str, kind: str, payload: dict[str, Any], now: int,
                run_after: int | None = None, job_id: str | None = None) -> dict[str, Any]:
        job_id = job_id or ("job-" + uuid.uuid5(uuid.NAMESPACE_URL,
                                                f"{tenant}|{kind}|{now}|{json.dumps(payload, sort_keys=True)}").hex[:20])
        with self._lock, self._conn:
            existing = self._conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if existing:
                return self._row(existing)  # idempotent
            self._conn.execute(
                "INSERT INTO jobs (job_id, tenant, kind, payload, status, attempts, run_after, "
                "enqueued_at) VALUES (?,?,?,?,?,?,?,?)",
                (job_id, tenant, kind, json.dumps(payload, sort_keys=True), QUEUED, 0,
                 run_after if run_after is not None else now, now),
            )
        return self.get(job_id)  # type: ignore[return-value]

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            r = self._conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return self._row(r) if r else None

    def claim(self, *, worker: str, now: int, lease_seconds: int = 300) -> dict[str, Any] | None:
        """Atomically lease the oldest runnable queued job to a worker."""
        with self._lock, self._conn:
            r = self._conn.execute(
                "SELECT * FROM jobs WHERE status=? AND run_after<=? ORDER BY enqueued_at LIMIT 1",
                (QUEUED, now)).fetchone()
            if not r:
                return None
            self._conn.execute(
                "UPDATE jobs SET status=?, worker=?, lease_expires=?, attempts=attempts+1 "
                "WHERE job_id=? AND status=?",
                (RUNNING, worker, now + lease_seconds, r["job_id"], QUEUED))
        return self.get(r["job_id"])

    def complete(self, job_id: str) -> dict[str, Any]:
        with self._lock, self._conn:
            self._conn.execute("UPDATE jobs SET status=?, lease_expires=NULL WHERE job_id=?",
                               (DONE, job_id))
        return self.get(job_id)  # type: ignore[return-value]

    def fail(self, job_id: str, *, error: str, now: int) -> dict[str, Any]:
        """Fail a running job: retry with backoff, or mark DEAD past max attempts."""
        with self._lock, self._conn:
            r = self._conn.execute("SELECT attempts FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            attempts = r["attempts"] if r else 0
            if attempts >= self.max_attempts:
                self._conn.execute(
                    "UPDATE jobs SET status=?, last_error=?, lease_expires=NULL WHERE job_id=?",
                    (DEAD, error[:500], job_id))
            else:
                backoff = self.base_backoff * (2 ** (attempts - 1))
                self._conn.execute(
                    "UPDATE jobs SET status=?, last_error=?, run_after=?, lease_expires=NULL, "
                    "worker=NULL WHERE job_id=?",
                    (QUEUED, error[:500], now + backoff, job_id))
        return self.get(job_id)  # type: ignore[return-value]

    def requeue_expired(self, *, now: int) -> int:
        """Return crashed-worker jobs (lease elapsed) to the queue."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE jobs SET status=?, worker=NULL, lease_expires=NULL "
                "WHERE status=? AND lease_expires IS NOT NULL AND lease_expires<?",
                (QUEUED, RUNNING, now))
            return cur.rowcount

    def stats(self, tenant: str | None = None) -> dict[str, int]:
        q = "SELECT status, COUNT(*) c FROM jobs"
        args: tuple = ()
        if tenant:
            q += " WHERE tenant=?"
            args = (tenant,)
        q += " GROUP BY status"
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return {r["status"]: r["c"] for r in rows}


class Worker:
    """Claims + runs one job via a handler(job)->None (raises to fail)."""

    def __init__(self, queue: WorkQueue, handler: Callable[[dict[str, Any]], None],
                 *, name: str = "worker-1"):
        self.queue = queue
        self.handler = handler
        self.name = name

    def run_once(self, *, now: int, lease_seconds: int = 300) -> dict[str, Any] | None:
        job = self.queue.claim(worker=self.name, now=now, lease_seconds=lease_seconds)
        if not job:
            return None
        try:
            self.handler(job)
            return self.queue.complete(job["job_id"])
        except Exception as e:  # noqa: BLE001
            return self.queue.fail(job["job_id"], error=str(e), now=now)
