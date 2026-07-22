"""
legal_hold.py
=============
Legal-hold registry for evidence (FUR-CMP-008).

A legal hold (litigation / audit hold) freezes evidence against retention expiry
and deletion. Unlike the immutable evidence envelope, a hold is MUTABLE state —
it is placed and later released — so it cannot live in the write-once object. It
is a separate per-tenant JSON registry keyed by the evidence sha256.

An active hold OVERRIDES retention: evidence under hold is never past-retention
and must not be purged. Release is itself recorded (who/when/why) so the hold
lifecycle is auditable.
"""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any


class LegalHoldError(Exception):
    """A legal-hold operation was invalid (e.g. releasing a non-existent hold)."""


class LegalHoldStore:
    """Per-tenant, file-backed registry of legal holds on evidence objects."""

    def __init__(self, root: Path | str):
        self.root = Path(root) / "evidence"
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "legal_holds.json"
        self._lock = Lock()

    # ── internals ──────────────────────────────────────────────────────────────
    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, sort_keys=True, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    # ── operations ─────────────────────────────────────────────────────────────
    def place(self, sha256: str, *, reason: str, actor: str, at: str) -> dict:
        """Place (or re-affirm) an active hold on an evidence object."""
        if not reason.strip():
            raise LegalHoldError("a legal hold requires a reason")
        with self._lock:
            data = self._load()
            rec = {
                "sha256": sha256,
                "active": True,
                "reason": reason,
                "placed_by": actor,
                "placed_at": at,
            }
            data[sha256] = rec
            self._save(data)
            return rec

    def release(self, sha256: str, *, actor: str, at: str, reason: str = "") -> dict:
        """Release an active hold; the record is retained (soft) for audit."""
        with self._lock:
            data = self._load()
            rec = data.get(sha256)
            if not rec or not rec.get("active"):
                raise LegalHoldError(f"no active legal hold for {sha256}")
            rec = {
                **rec,
                "active": False,
                "released_by": actor,
                "released_at": at,
                "release_reason": reason,
            }
            data[sha256] = rec
            self._save(data)
            return rec

    def get(self, sha256: str) -> dict | None:
        return self._load().get(sha256)

    def is_held(self, sha256: str) -> bool:
        rec = self._load().get(sha256)
        return bool(rec and rec.get("active"))

    def list(self, *, active_only: bool = True) -> list[dict]:
        items = list(self._load().values())
        items.sort(key=lambda r: r.get("placed_at", ""))
        return [r for r in items if r.get("active")] if active_only else items
