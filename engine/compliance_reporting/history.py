"""
history.py
==========
Durable, integrity-checked persistence for compliance reports — the layer
that turns single snapshots into a compliance *history* (trends, diffs,
"were we better last month?").

Storage layout under a root directory:

    <root>/reports/<report_id>.json     one canonical report per file
    <root>/batches/<report_id>.json     optional raw batch (for later full
                                        re-verification via verify_report)
    <root>/index.jsonl                  append-only summary index, one line
                                        per stored report

Durability rules (deliberately stricter than convenience):
  * Every write is atomic: temp file + os.replace, fsync'd. A crash mid-save
    never leaves a half-written report.
  * save() refuses a report whose integrity hash does not recompute — a
    corrupt report can never enter the store.
  * save() is idempotent: report_id is derived from content, so saving the
    same batch twice is a no-op; a *different* report claiming an existing
    id is rejected loudly (that would mean a hash collision or tampering).
  * load() re-verifies the integrity hash — a report tampered ON DISK is
    refused with IntegrityError, not silently returned.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .report_builder import _UUID_NAMESPACE, _sha256_of


class IntegrityError(Exception):
    """A stored or supplied report failed its cryptographic self-check."""


@dataclass(frozen=True)
class IndexEntry:
    """One line of the store index — enough to trend without loading reports."""

    report_id: str
    generated_at: str
    window_end: str  # last _run_timestamp in the batch — the honest time axis
    total_logs: int
    successful_logs: int
    total_violations: int
    # framework_id -> at_risk_pct (share of MONITORED requirements with
    # observed violations). Schema 1.x stored compliance_pct here — the field
    # is renamed so the trend can never be misread as a compliance score.
    framework_at_risk_pct: dict[str, float | None]

    @property
    def sort_key(self) -> tuple[str, str, str]:
        # Order history by the DATA period first (window_end), then by
        # generation time, then id. Two reports generated back-to-back in the
        # same second still sort by which batch's data is newer.
        return (self.window_end or self.generated_at, self.generated_at, self.report_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "window_end": self.window_end,
            "total_logs": self.total_logs,
            "successful_logs": self.successful_logs,
            "total_violations": self.total_violations,
            "framework_at_risk_pct": self.framework_at_risk_pct,
        }

    @classmethod
    def from_report(cls, report: Mapping[str, Any]) -> "IndexEntry":
        # window moved to run_metadata in schema 2.0 (volatile, outside the
        # content hash); fall back to the 1.x location for stored reports.
        window = (
            (report.get("run_metadata") or {}).get("window")
            or (report["batch"].get("window") or {})
        )
        return cls(
            report_id=report["report_id"],
            generated_at=report["generated_at"],
            window_end=window.get("last_run_timestamp") or "",
            total_logs=report["batch"]["total_logs"],
            successful_logs=report["batch"]["successful_logs"],
            total_violations=report["summary"]["total_violations"],
            framework_at_risk_pct={
                fw["framework_id"]: fw.get("at_risk_pct") for fw in report["frameworks"]
            },
        )


def check_report_integrity(report: Mapping[str, Any]) -> None:
    """
    Recompute the content hash and derived report_id; raise IntegrityError
    on any mismatch. This is the store's admission and readmission test —
    it needs no batch, so it can run anywhere, anytime.
    """
    try:
        claimed_hash = report["integrity"]["content_sha256"]
        claimed_id = report["report_id"]
    except (KeyError, TypeError) as exc:
        raise IntegrityError(f"report is missing integrity fields: {exc}") from exc

    from .report_builder import VOLATILE_KEYS  # single source for hash exclusions
    payload = {k: report[k] for k in report if k not in VOLATILE_KEYS}
    actual_hash = _sha256_of(payload)
    if actual_hash != claimed_hash:
        raise IntegrityError(
            f"content hash mismatch: stored {claimed_hash[:16]}…, recomputed {actual_hash[:16]}…"
        )
    expected_id = str(uuid.uuid5(_UUID_NAMESPACE, actual_hash))
    if claimed_id != expected_id:
        raise IntegrityError(
            f"report_id {claimed_id} is not uuid5(content hash) — expected {expected_id}"
        )


def _atomic_write(path: Path, text: str) -> None:
    """Write via temp file + fsync + os.replace so readers never see a torn file."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class ReportStore:
    """Filesystem-backed report history. Safe to share across processes."""

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.reports_dir = self.root / "reports"
        self.batches_dir = self.root / "batches"
        self.index_path = self.root / "index.jsonl"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.batches_dir.mkdir(parents=True, exist_ok=True)

    # ── write path ────────────────────────────────────────────────────────────
    def save(
        self,
        report: Mapping[str, Any],
        batch: Iterable[Mapping[str, Any]] | None = None,
    ) -> Path:
        """
        Persist a verified report (and optionally its raw batch, enabling
        full re-verification later). Returns the report file path.

        Idempotent: an identical report already stored is a no-op. A
        DIFFERENT report under the same id raises IntegrityError.
        """
        check_report_integrity(report)
        report_id = report["report_id"]
        path = self.reports_dir / f"{report_id}.json"
        serialized = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True)

        if path.exists():
            # Idempotency is by CONTENT HASH, not raw bytes: report_id =
            # uuid5(content_sha256), so a matching id ⟹ identical content even if
            # `generated_at` differs (e.g. re-ingesting the same logs later). Only
            # a genuine hash divergence (collision/tampering) is an error.
            existing = json.loads(path.read_text(encoding="utf-8"))
            existing_hash = existing.get("integrity", {}).get("content_sha256")
            if existing_hash != report["integrity"]["content_sha256"]:
                raise IntegrityError(
                    f"store already holds a different document for {report_id}"
                )
            return path  # same content — keep the first-stored copy, no-op

        _atomic_write(path, serialized)
        if batch is not None:
            _atomic_write(
                self.batches_dir / f"{report_id}.json",
                json.dumps(list(batch), ensure_ascii=False, sort_keys=True),
            )
        self._append_index(IndexEntry.from_report(report))
        return path

    def _append_index(self, entry: IndexEntry) -> None:
        # Append-only; rebuildable from the reports themselves at any time.
        with open(self.index_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    # ── read path ─────────────────────────────────────────────────────────────
    def load(self, report_id: str) -> dict[str, Any]:
        """Load one report, re-verifying its integrity hash from disk."""
        path = self.reports_dir / f"{report_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"no stored report {report_id}")
        report = json.loads(path.read_text(encoding="utf-8"))
        check_report_integrity(report)  # refuses on-disk tampering
        return report

    def load_batch(self, report_id: str) -> list[dict[str, Any]] | None:
        """Return the archived raw batch for a report, if one was stored."""
        path = self.batches_dir / f"{report_id}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def entries(self) -> list[IndexEntry]:
        """All index entries, oldest first (by generated_at, then id)."""
        if not self.index_path.exists():
            return []
        rows: dict[str, IndexEntry] = {}
        for line in self.index_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            d = json.loads(line)
            rows[d["report_id"]] = IndexEntry(
                report_id=d["report_id"],
                generated_at=d["generated_at"],
                window_end=d.get("window_end", ""),
                total_logs=d["total_logs"],
                successful_logs=d["successful_logs"],
                total_violations=d["total_violations"],
                # accept 1.x lines ("framework_pct") from stores written
                # before the rename; values are surfaced under the new key
                framework_at_risk_pct=d.get("framework_at_risk_pct", d.get("framework_pct", {})),
            )
        return sorted(rows.values(), key=lambda e: e.sort_key)

    def latest(self, n: int = 1) -> list[IndexEntry]:
        """The n most recent entries, newest last."""
        return self.entries()[-n:]

    def rebuild_index(self) -> int:
        """
        Regenerate index.jsonl from the report files themselves (recovery
        path if the index is lost or suspect). Returns the entry count.
        """
        entries: list[IndexEntry] = []
        for path in sorted(self.reports_dir.glob("*.json")):
            report = json.loads(path.read_text(encoding="utf-8"))
            check_report_integrity(report)
            entries.append(IndexEntry.from_report(report))
        entries.sort(key=lambda e: e.sort_key)
        _atomic_write(
            self.index_path,
            "".join(json.dumps(e.to_dict(), sort_keys=True) + "\n" for e in entries),
        )
        return len(entries)

    # ── trend ─────────────────────────────────────────────────────────────────
    def trend(self) -> list[dict[str, Any]]:
        """
        Time-ordered posture series straight from the index — the data
        behind a "compliance over time" chart, no report loads required.
        """
        return [e.to_dict() for e in self.entries()]
