"""
connector_registry.py
======================
Scheduled connector jobs + connector health (Wave-G). A durable, per-tenant
registry of collection connectors (e.g. the AWS Organizations/IAM collector),
each with a cadence, last-run outcome, and a derived **health** state that the
dashboard's connector-health page renders.

The registry is SQLite-backed (transactional, multi-process-safe). The
`ConnectorScheduler` decides which jobs are DUE and runs them via an injected
runner (so the collection machinery and its credentials live in the API layer,
and the scheduler stays pure and testable). Time is injected (`now` epoch
seconds) so scheduling is deterministic in tests.

Health
------
* **healthy**   — last run ok, population reconciled, manifest signed, and fresh
                  (last run within 2× the cadence).
* **degraded**  — last run ok but reconciliation failed, manifest unsigned, or
                  the data is stale (overdue by > 2× cadence).
* **failed**    — the last run raised.
* **unknown**   — never run.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Callable


def _iso(epoch: int | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


@dataclass
class ConnectorHealth:
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"


def derive_health(row: dict[str, Any], now: int) -> str:
    if row["last_run_at"] is None:
        return ConnectorHealth.UNKNOWN
    if row["last_status"] == "error":
        return ConnectorHealth.FAILED
    stale = now - row["last_run_at"] > 2 * max(row["schedule_seconds"], 1)
    if not row["last_reconciled"] or not row["last_signed"] or stale:
        return ConnectorHealth.DEGRADED
    return ConnectorHealth.HEALTHY


class ConnectorRegistry:
    """Durable per-tenant registry of scheduled connector jobs."""

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "connectors.db"
        self._lock = Lock()
        self._conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS connectors (
                   connector_id TEXT NOT NULL,
                   tenant TEXT NOT NULL,
                   kind TEXT NOT NULL,
                   schedule_seconds INTEGER NOT NULL,
                   enabled INTEGER NOT NULL DEFAULT 1,
                   config TEXT NOT NULL DEFAULT '{}',
                   next_run_at INTEGER,
                   last_run_at INTEGER,
                   last_status TEXT,
                   last_error TEXT,
                   last_manifest_sha TEXT,
                   last_signed INTEGER NOT NULL DEFAULT 0,
                   last_reconciled INTEGER NOT NULL DEFAULT 0,
                   PRIMARY KEY (tenant, connector_id)
               )"""
        )
        self._conn.commit()

    def _row(self, r: sqlite3.Row) -> dict[str, Any]:
        return {
            "connector_id": r["connector_id"], "tenant": r["tenant"], "kind": r["kind"],
            "schedule_seconds": r["schedule_seconds"], "enabled": bool(r["enabled"]),
            "config": json.loads(r["config"]),
            "next_run_at": r["next_run_at"], "last_run_at": r["last_run_at"],
            "last_status": r["last_status"], "last_error": r["last_error"],
            "last_manifest_sha": r["last_manifest_sha"],
            "last_signed": bool(r["last_signed"]), "last_reconciled": bool(r["last_reconciled"]),
        }

    def register(self, *, tenant: str, connector_id: str, kind: str, schedule_seconds: int,
                 now: int, enabled: bool = True, config: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create or update a connector job (idempotent upsert). Schedules the
        first run immediately (next_run_at = now)."""
        with self._lock, self._conn:
            existing = self._get_locked(tenant, connector_id)
            next_run = existing["next_run_at"] if existing else now
            self._conn.execute(
                """INSERT INTO connectors
                   (connector_id, tenant, kind, schedule_seconds, enabled, config, next_run_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(tenant, connector_id) DO UPDATE SET
                     kind=excluded.kind, schedule_seconds=excluded.schedule_seconds,
                     enabled=excluded.enabled, config=excluded.config""",
                (connector_id, tenant, kind, schedule_seconds, int(enabled),
                 json.dumps(config or {}, sort_keys=True), next_run),
            )
        return self.get(tenant, connector_id)  # type: ignore[return-value]

    def _get_locked(self, tenant: str, connector_id: str) -> dict[str, Any] | None:
        r = self._conn.execute(
            "SELECT * FROM connectors WHERE tenant=? AND connector_id=?",
            (tenant, connector_id)).fetchone()
        return self._row(r) if r else None

    def get(self, tenant: str, connector_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._get_locked(tenant, connector_id)

    def list(self, tenant: str, *, now: int | None = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM connectors WHERE tenant=? ORDER BY connector_id", (tenant,)).fetchall()
        out = [self._row(r) for r in rows]
        for row in out:
            row["health"] = derive_health(row, now) if now is not None else (
                ConnectorHealth.UNKNOWN if row["last_run_at"] is None else row["last_status"])
            row["last_run_at_iso"] = _iso(row["last_run_at"])
            row["next_run_at_iso"] = _iso(row["next_run_at"])
        return out

    def due(self, tenant: str, now: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM connectors WHERE tenant=? AND enabled=1 AND next_run_at<=? "
                "ORDER BY next_run_at", (tenant, now)).fetchall()
        return [self._row(r) for r in rows]

    def record_run(self, tenant: str, connector_id: str, *, now: int,
                   manifest: dict[str, Any] | None, error: str | None) -> dict[str, Any]:
        """Record a run outcome and schedule the next run (now + cadence)."""
        with self._lock, self._conn:
            row = self._get_locked(tenant, connector_id)
            if not row:
                raise KeyError(f"unknown connector {connector_id} for tenant {tenant}")
            next_run = now + row["schedule_seconds"]
            if error is not None:
                self._conn.execute(
                    "UPDATE connectors SET last_run_at=?, next_run_at=?, last_status='error', "
                    "last_error=?, last_signed=0, last_reconciled=0 "
                    "WHERE tenant=? AND connector_id=?",
                    (now, next_run, error[:500], tenant, connector_id))
            else:
                m = manifest or {}
                self._conn.execute(
                    "UPDATE connectors SET last_run_at=?, next_run_at=?, last_status='ok', "
                    "last_error=NULL, last_manifest_sha=?, last_signed=?, last_reconciled=? "
                    "WHERE tenant=? AND connector_id=?",
                    (now, next_run, m.get("resource_sha256"),
                     int(bool(m.get("signature"))), int(bool(m.get("reconciled"))),
                     tenant, connector_id))
        return self.get(tenant, connector_id)  # type: ignore[return-value]


# Runner: (job) -> manifest dict. Raises on collection failure.
Runner = Callable[[dict[str, Any]], dict[str, Any]]


class ConnectorScheduler:
    """Runs due connector jobs via an injected runner; records health outcomes."""

    def __init__(self, registry: ConnectorRegistry):
        self.registry = registry

    def run_one(self, tenant: str, connector_id: str, runner: Runner, *, now: int) -> dict[str, Any]:
        job = self.registry.get(tenant, connector_id)
        if not job:
            raise KeyError(f"unknown connector {connector_id}")
        try:
            manifest = runner(job)
            return self.registry.record_run(tenant, connector_id, now=now,
                                            manifest=manifest, error=None)
        except Exception as e:  # noqa: BLE001 - record failure as health, re-raise nothing
            return self.registry.record_run(tenant, connector_id, now=now,
                                            manifest=None, error=str(e))

    def tick(self, tenant: str, runner: Runner, *, now: int) -> list[dict[str, Any]]:
        """Run every due job once; return their updated records."""
        results = []
        for job in self.registry.due(tenant, now):
            results.append(self.run_one(tenant, job["connector_id"], runner, now=now))
        return results
