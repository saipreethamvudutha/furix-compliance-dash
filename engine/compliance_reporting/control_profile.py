"""
control_profile.py
==================
The editable GRC metadata for a control (Wave-I / Epic 4 — compliance workspace).

Furix computes the deterministic *verdict* for every control (pass/at-risk from
events + config posture). But a real compliance workspace also carries the human
governance context an auditor asks for: who owns the control, whether it is
applicable (and why), how it is implemented, how it is verified, and on what
cadence it must be re-tested. That editable metadata lives here, per tenant per
control, separate from the computed verdict — the workspace view joins the two.

Every write records who changed it and when (feeds the administrative audit log
in Epic 6). Backed by SQLite (WAL), like the other durable stores.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any

APPLICABILITY = ("applicable", "not_applicable", "inherited")
VERIFICATION_METHODS = ("automated", "manual", "hybrid")

# editable fields (everything else on the workspace view is computed)
_EDITABLE = ("owner", "applicability", "applicability_rationale", "implementation_narrative",
             "verification_method", "verification_description", "test_cadence_days")

_DEFAULTS: dict[str, Any] = {
    "owner": "", "applicability": "applicable", "applicability_rationale": "",
    "implementation_narrative": "", "verification_method": "automated",
    "verification_description": "", "test_cadence_days": 90,
}


class ControlProfileError(Exception):
    """Invalid control-profile update."""


class ControlProfileStore:
    """Durable, per-tenant store of editable control governance metadata."""

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "control_profiles.db"
        self._lock = Lock()
        self._conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS control_profiles (
                   tenant TEXT NOT NULL,
                   control_id TEXT NOT NULL,
                   profile_json TEXT NOT NULL,
                   updated_at TEXT,
                   updated_by TEXT,
                   PRIMARY KEY (tenant, control_id)
               )"""
        )
        self._conn.commit()

    def _row(self, tenant: str, control_id: str, r: sqlite3.Row | None) -> dict[str, Any]:
        prof = dict(_DEFAULTS)
        if r:
            prof.update(json.loads(r["profile_json"]))
            prof["updated_at"] = r["updated_at"]
            prof["updated_by"] = r["updated_by"]
        else:
            prof["updated_at"] = None
            prof["updated_by"] = None
        prof["control_id"] = control_id
        prof["tenant"] = tenant
        prof["configured"] = r is not None
        return prof

    def get(self, tenant: str, control_id: str) -> dict[str, Any]:
        """Return the profile (with defaults filled in) — never None."""
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM control_profiles WHERE tenant=? AND control_id=?",
                (tenant, control_id)).fetchone()
        return self._row(tenant, control_id, r)

    def all(self, tenant: str) -> dict[str, dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM control_profiles WHERE tenant=?", (tenant,)).fetchall()
        return {r["control_id"]: self._row(tenant, r["control_id"], r) for r in rows}

    def update(self, tenant: str, control_id: str, patch: dict[str, Any], *,
               updated_by: str, updated_at: str) -> dict[str, Any]:
        """Validate + persist an update to the editable fields (partial patch)."""
        clean: dict[str, Any] = {}
        for k, v in patch.items():
            if k not in _EDITABLE:
                continue  # ignore computed/unknown fields
            if k == "applicability" and v not in APPLICABILITY:
                raise ControlProfileError(f"applicability must be one of {APPLICABILITY}")
            if k == "verification_method" and v not in VERIFICATION_METHODS:
                raise ControlProfileError(f"verification_method must be one of {VERIFICATION_METHODS}")
            if k == "test_cadence_days":
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    raise ControlProfileError("test_cadence_days must be an integer") from None
                if v < 1:
                    raise ControlProfileError("test_cadence_days must be >= 1")
            clean[k] = v

        with self._lock, self._conn:
            r = self._conn.execute(
                "SELECT profile_json FROM control_profiles WHERE tenant=? AND control_id=?",
                (tenant, control_id)).fetchone()
            merged = {k: _DEFAULTS[k] for k in _EDITABLE}
            if r:
                merged.update({k: v for k, v in json.loads(r["profile_json"]).items() if k in _EDITABLE})
            merged.update(clean)
            self._conn.execute(
                "INSERT INTO control_profiles (tenant, control_id, profile_json, updated_at, updated_by) "
                "VALUES (?,?,?,?,?) ON CONFLICT(tenant, control_id) DO UPDATE SET "
                "profile_json=excluded.profile_json, updated_at=excluded.updated_at, "
                "updated_by=excluded.updated_by",
                (tenant, control_id, json.dumps(merged, sort_keys=True), updated_at, updated_by),
            )
        return self.get(tenant, control_id)
