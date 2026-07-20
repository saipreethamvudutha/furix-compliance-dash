"""
attestation_store.py
====================
Tenant-scoped, durable submission/approval store for signed manual attestations
(Wave-F). This is the human workflow behind the mandatory-verification change:
an attester **submits** a signed attestation, a second party (admin) **approves**
it, and only APPROVED attestations are allowed to back a control PASS in a report.

Fail-closed at every step:

* **Submission** rejects an attestation whose signature does not verify against
  the tenant key ring — an unverifiable attestation never enters the store.
* An attestation is stored per **tenant**; a submission whose `tenant` field
  disagrees with the target tenant is rejected (no cross-tenant smuggling).
* Only **APPROVED** attestations are returned by `approved_attestations()`, which
  is what feeds `build_report`. A SUBMITTED (pending) or REJECTED attestation can
  never drive a PASS.
* Approval is separated from submission (segregation of duty): the API layer
  restricts approval to the `admin` role.

Backed by SQLite (WAL) for transactional, multi-process-safe writes, mirroring
`FindingStore`. The attestation id is the content hash of the signed payload, so
re-submitting the identical attestation is idempotent.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any, Mapping

from .attestation import AttestationKeyRing, canonical_payload, verify_attestation

SUBMITTED = "submitted"
APPROVED = "approved"
REJECTED = "rejected"


class AttestationError(Exception):
    """Raised on an invalid submission or an illegal state transition."""


def attestation_id(att: Mapping[str, Any]) -> str:
    """Deterministic id = hash of the signed payload + signature (idempotent)."""
    import hashlib

    basis = canonical_payload(att) + "|" + str(att.get("signature", ""))
    return "att-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24]


class AttestationStore:
    """Durable, tenant-scoped attestation submission/approval store."""

    def __init__(self, root: Path | str, *, required_approvals: int | None = None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "attestations.db"
        # Two-person rule: an attestation needs this many DISTINCT approvers, none
        # of whom is the submitter — so at least (1 + required_approvals) people
        # touch it. Default 1 (submitter + one independent approver = two people);
        # raise FURIX_ATTEST_REQUIRED_APPROVALS for higher assurance.
        if required_approvals is None:
            required_approvals = int(os.environ.get("FURIX_ATTEST_REQUIRED_APPROVALS", "1"))
        self.required_approvals = max(1, required_approvals)
        self._lock = Lock()
        self._conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS attestations (
                   att_id TEXT PRIMARY KEY,
                   tenant TEXT NOT NULL,
                   spec_id TEXT NOT NULL,
                   status TEXT NOT NULL,
                   submitted_by TEXT NOT NULL,
                   submitted_at TEXT NOT NULL,
                   decided_by TEXT,
                   decided_at TEXT,
                   decision_reason TEXT,
                   approvals TEXT NOT NULL DEFAULT '[]',
                   required_approvals INTEGER NOT NULL DEFAULT 1,
                   verification_status TEXT NOT NULL,
                   verification_reasons TEXT NOT NULL,
                   attestation_json TEXT NOT NULL
               )"""
        )
        self._conn.commit()

    # ── low level ────────────────────────────────────────────────────────────────
    def _row(self, row: sqlite3.Row) -> dict[str, Any]:
        approvals = json.loads(row["approvals"])
        return {
            "att_id": row["att_id"], "tenant": row["tenant"], "spec_id": row["spec_id"],
            "status": row["status"], "submitted_by": row["submitted_by"],
            "submitted_at": row["submitted_at"], "decided_by": row["decided_by"],
            "decided_at": row["decided_at"], "decision_reason": row["decision_reason"],
            "approvals": approvals, "approvals_count": len(approvals),
            "required_approvals": row["required_approvals"],
            "verification": {"status": row["verification_status"],
                             "reasons": json.loads(row["verification_reasons"])},
            "attestation": json.loads(row["attestation_json"]),
        }

    def _get_locked(self, tenant: str, att_id: str) -> dict[str, Any] | None:
        r = self._conn.execute(
            "SELECT * FROM attestations WHERE att_id=? AND tenant=?", (att_id, tenant)
        ).fetchone()
        return self._row(r) if r else None

    # ── public API ───────────────────────────────────────────────────────────────
    def submit(self, att: Mapping[str, Any], *, tenant: str, keyring: AttestationKeyRing,
               submitted_by: str, submitted_at: str, as_of: str | None = None) -> dict[str, Any]:
        """
        Validate and store a submitted attestation. Fail-closed: the signature
        MUST verify against the tenant key ring and the attestation's `tenant`
        field must match — otherwise the submission is rejected and nothing is
        stored. Idempotent on the exact same signed attestation.
        """
        if att.get("tenant") != tenant:
            raise AttestationError(
                f"attestation tenant {att.get('tenant')!r} does not match target tenant {tenant!r}")
        status, reasons = verify_attestation(att, keyring, tenant=tenant, as_of=as_of)
        if status != "verified":
            raise AttestationError(f"attestation failed verification: {', '.join(reasons)}")

        att_id = attestation_id(att)
        with self._lock, self._conn:
            existing = self._get_locked(tenant, att_id)
            if existing:
                return existing  # idempotent re-submit
            self._conn.execute(
                "INSERT INTO attestations (att_id, tenant, spec_id, status, submitted_by, "
                "submitted_at, decided_by, decided_at, decision_reason, approvals, "
                "required_approvals, verification_status, verification_reasons, attestation_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (att_id, tenant, att.get("spec_id"), SUBMITTED, submitted_by, submitted_at,
                 None, None, None, "[]", self.required_approvals, status, json.dumps(reasons),
                 json.dumps(dict(att), sort_keys=True)),
            )
        return self._require(tenant, att_id)

    def approve(self, att_id: str, *, tenant: str, approved_by: str, decided_at: str,
                reason: str = "") -> dict[str, Any]:
        """
        Record an approval under the TWO-PERSON rule (segregation of duty):

        * the submitter can NEVER approve their own attestation,
        * each distinct approver counts once,
        * the attestation only becomes APPROVED once `required_approvals` DISTINCT
          non-submitter approvals are recorded.

        Until then it stays SUBMITTED (pending) and therefore cannot back a PASS.
        """
        with self._lock, self._conn:
            current = self._get_locked(tenant, att_id)
            if not current:
                raise AttestationError(f"unknown attestation {att_id} for tenant {tenant}")
            if current["status"] != SUBMITTED:
                raise AttestationError(f"cannot approve attestation in state {current['status']!r}")
            if approved_by == current["submitted_by"]:
                raise AttestationError(
                    "self-approval is forbidden — an attestation must be approved by someone "
                    "other than its submitter (two-person rule)")
            approvals = current["approvals"]
            if any(a["by"] == approved_by for a in approvals):
                raise AttestationError(f"{approved_by} has already approved this attestation")
            approvals.append({"by": approved_by, "at": decided_at, "reason": reason})
            reached = len(approvals) >= current["required_approvals"]
            self._conn.execute(
                "UPDATE attestations SET approvals=?, status=?, decided_by=?, decided_at=?, "
                "decision_reason=? WHERE att_id=? AND tenant=?",
                (json.dumps(approvals), APPROVED if reached else SUBMITTED,
                 approved_by if reached else None, decided_at if reached else None,
                 reason if reached else None, att_id, tenant),
            )
        return self._require(tenant, att_id)

    def reject(self, att_id: str, *, tenant: str, rejected_by: str, decided_at: str,
               reason: str = "") -> dict[str, Any]:
        """Reject a SUBMITTED attestation (SUBMITTED → REJECTED). A single
        reviewer may reject; approval requires the two-person rule above."""
        with self._lock, self._conn:
            current = self._get_locked(tenant, att_id)
            if not current:
                raise AttestationError(f"unknown attestation {att_id} for tenant {tenant}")
            if current["status"] != SUBMITTED:
                raise AttestationError(f"cannot reject attestation in state {current['status']!r}")
            self._conn.execute(
                "UPDATE attestations SET status=?, decided_by=?, decided_at=?, decision_reason=? "
                "WHERE att_id=? AND tenant=?",
                (REJECTED, rejected_by, decided_at, reason, att_id, tenant),
            )
        return self._require(tenant, att_id)

    def get(self, tenant: str, att_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._get_locked(tenant, att_id)

    def _require(self, tenant: str, att_id: str) -> dict[str, Any]:
        rec = self.get(tenant, att_id)
        if rec is None:  # pragma: no cover - defensive
            raise AttestationError(f"attestation {att_id} vanished")
        return rec

    def list(self, tenant: str, *, status: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if status:
                rows = self._conn.execute(
                    "SELECT * FROM attestations WHERE tenant=? AND status=? "
                    "ORDER BY submitted_at DESC, att_id", (tenant, status)).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM attestations WHERE tenant=? "
                    "ORDER BY submitted_at DESC, att_id", (tenant,)).fetchall()
        return [self._row(r) for r in rows]

    def approved_attestations(self, tenant: str) -> list[dict[str, Any]]:
        """The signed attestation payloads that are APPROVED for this tenant —
        the ONLY attestations allowed to back a control PASS in a report."""
        return [rec["attestation"] for rec in self.list(tenant, status=APPROVED)]
