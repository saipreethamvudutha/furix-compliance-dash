"""
audit_period.py
==============
Audit-period workflow (Wave-I / Epic 5). A formal assessment window with a
scope boundary, evidence requests, reviewer sign-off, and freeze/reopen control:

    OPEN ──add evidence requests / fulfil them──▶ (still OPEN)
    OPEN | IN_REVIEW | REOPENED ──sign-off──▶ SIGNED_OFF  (FROZEN)
    SIGNED_OFF ──reopen (admin)──▶ REOPENED  (unfrozen; the frozen snapshot is
                                              retained as an immutable version)

Sign-off captures an **immutable audit snapshot** — the full audit package,
content-addressed and written to the write-once evidence store — so a frozen
period's evidence can never change, and reopening preserves the prior signed
snapshot as a historical version. Backed by SQLite (WAL).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from threading import Lock
from typing import Any

OPEN = "open"
IN_REVIEW = "in_review"
SIGNED_OFF = "signed_off"
REOPENED = "reopened"

_EDITABLE_STATES = {OPEN, IN_REVIEW, REOPENED}


class AuditPeriodError(Exception):
    """Invalid audit-period operation (bad state / unknown id)."""


def _new_id(prefix: str, *parts: str) -> str:
    return prefix + "-" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


class AuditPeriodStore:
    """Durable, per-tenant store of audit periods + their evidence requests and
    sign-offs."""

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "audit_periods.db"
        self._lock = Lock()
        self._conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS audit_periods (
                   period_id TEXT NOT NULL,
                   tenant TEXT NOT NULL,
                   status TEXT NOT NULL,
                   created_at TEXT,
                   period_json TEXT NOT NULL,
                   PRIMARY KEY (tenant, period_id)
               )"""
        )
        self._conn.commit()

    # ── low level ────────────────────────────────────────────────────────────────
    def _get_locked(self, tenant: str, period_id: str) -> dict[str, Any] | None:
        r = self._conn.execute(
            "SELECT period_json FROM audit_periods WHERE tenant=? AND period_id=?",
            (tenant, period_id)).fetchone()
        return json.loads(r["period_json"]) if r else None

    def _save_locked(self, period: dict[str, Any]) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO audit_periods (period_id, tenant, status, created_at, period_json) "
            "VALUES (?,?,?,?,?)",
            (period["period_id"], period["tenant"], period["status"],
             period.get("created_at"), json.dumps(period, sort_keys=True)),
        )

    def _require_editable(self, period: dict[str, Any]) -> None:
        if period["status"] not in _EDITABLE_STATES:
            raise AuditPeriodError(
                f"audit period is {period['status']} (frozen) — reopen it to make changes")

    # ── public API ───────────────────────────────────────────────────────────────
    def create(self, *, tenant: str, name: str, boundary: str, start_date: str,
               end_date: str, created_by: str, created_at: str) -> dict[str, Any]:
        period_id = _new_id("period", tenant, name, start_date, end_date, created_at)
        period = {
            "period_id": period_id, "tenant": tenant, "name": name, "boundary": boundary,
            "start_date": start_date, "end_date": end_date, "status": OPEN, "frozen": False,
            "created_by": created_by, "created_at": created_at,
            "evidence_requests": [], "signoffs": [], "reopenings": [],
        }
        with self._lock, self._conn:
            if self._get_locked(tenant, period_id):
                return self._get_locked(tenant, period_id)  # idempotent
            self._save_locked(period)
        return period

    def get(self, tenant: str, period_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._get_locked(tenant, period_id)

    def list(self, tenant: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT period_json FROM audit_periods WHERE tenant=? "
                "ORDER BY created_at DESC, period_id", (tenant,)).fetchall()
        return [json.loads(r["period_json"]) for r in rows]

    def _mutate(self, tenant: str, period_id: str, fn) -> dict[str, Any]:
        with self._lock, self._conn:
            period = self._get_locked(tenant, period_id)
            if not period:
                raise AuditPeriodError(f"unknown audit period {period_id}")
            fn(period)
            self._save_locked(period)
        return self.get(tenant, period_id)  # type: ignore[return-value]

    def add_evidence_request(self, tenant: str, period_id: str, *, control_id: str,
                             note: str, requested_by: str, requested_at: str) -> dict[str, Any]:
        def _fn(period):
            self._require_editable(period)
            req_id = _new_id("evreq", period_id, control_id, requested_at,
                             str(len(period["evidence_requests"])))
            period["evidence_requests"].append({
                "req_id": req_id, "control_id": control_id, "note": note,
                "status": "requested", "requested_by": requested_by, "requested_at": requested_at,
                "evidence_ref": None, "fulfilled_by": None, "fulfilled_at": None,
            })
        return self._mutate(tenant, period_id, _fn)

    def fulfill_evidence_request(self, tenant: str, period_id: str, req_id: str, *,
                                 evidence_ref: str, actor: str, at: str) -> dict[str, Any]:
        def _fn(period):
            self._require_editable(period)
            req = next((r for r in period["evidence_requests"] if r["req_id"] == req_id), None)
            if req is None:
                raise AuditPeriodError(f"unknown evidence request {req_id}")
            req.update({"status": "provided", "evidence_ref": evidence_ref,
                        "fulfilled_by": actor, "fulfilled_at": at})
        return self._mutate(tenant, period_id, _fn)

    def record_signoff(self, tenant: str, period_id: str, *, reviewer: str, at: str,
                       snapshot_sha256: str, snapshot_uri: str, report_id: str | None = None,
                       signature: dict[str, Any] | None = None) -> dict[str, Any]:
        """Freeze the period with an immutable, period-scoped, (optionally
        asymmetrically-)signed snapshot reference."""
        def _fn(period):
            if period["status"] not in _EDITABLE_STATES:
                raise AuditPeriodError(f"cannot sign off a period in state {period['status']!r}")
            period["signoffs"].append({
                "reviewer": reviewer, "at": at,
                "snapshot_sha256": snapshot_sha256, "snapshot_uri": snapshot_uri,
                "report_id": report_id, "signature": signature,
            })
            period["status"] = SIGNED_OFF
            period["frozen"] = True
        return self._mutate(tenant, period_id, _fn)

    def record_reopen(self, tenant: str, period_id: str, *, actor: str, at: str,
                      reason: str) -> dict[str, Any]:
        def _fn(period):
            if period["status"] != SIGNED_OFF:
                raise AuditPeriodError(f"cannot reopen a period in state {period['status']!r}")
            period["reopenings"].append({"by": actor, "at": at, "reason": reason})
            period["status"] = REOPENED
            period["frozen"] = False
            # the prior signed snapshot stays in `signoffs` as a historical version
        return self._mutate(tenant, period_id, _fn)
