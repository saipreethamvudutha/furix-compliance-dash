"""
manual_evidence.py
==================
Manual / operational evidence assertions (Wave-E, addresses the audit's P2:
config-posture covers 13/18 CIS control families; the rest need people/process
evidence). Controls 9, 14, 15, 17, 18 (email/browser protection, security
training, vendor review, incident exercises, penetration testing) cannot be
proven by scanning config — they require a **signed attestation** from an
accountable owner on a recurring cadence.

Model
-----
A `ManualAssertionSpec` declares what must be attested, the control it
evidences, and how often (cadence). Without a current attestation the control
is `MANUAL_PENDING` — honestly "awaiting human evidence", never PASS. An
attestation carries the attester, statement, evidence reference and a date; if
it is older than the cadence it is stale and the control returns to pending.

Attestations are content-addressed and evaluated deterministically against an
explicit `as_of` (no wall-clock), so the result is reproducible.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

MANUAL_PENDING = "manual_pending"
PASS = "pass"
STALE = "stale"


@dataclass(frozen=True)
class ManualAssertionSpec:
    spec_id: str
    title: str
    control_edges: tuple[str, ...]
    severity: str
    cadence_days: int
    rationale: str
    mode: str = "manual"
    predicate_kind: str = "attestation"

    def evaluator_hash(self) -> str:
        basis = {"spec_id": self.spec_id, "control_edges": list(self.control_edges),
                 "cadence_days": self.cadence_days, "mode": self.mode,
                 "predicate_kind": self.predicate_kind}
        return hashlib.sha256(
            json.dumps(basis, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


MANUAL_ASSERTION_CATALOG: dict[str, ManualAssertionSpec] = {s.spec_id: s for s in (
    ManualAssertionSpec("MAN-EMAIL-BROWSER", "Email & browser protections attested",
                        ("Control 9",), "medium", 365,
                        "DNS/URL filtering + safe-attachment controls confirmed (CIS 9)."),
    ManualAssertionSpec("MAN-SEC-TRAINING", "Security awareness training completed",
                        ("Control 14",), "medium", 365,
                        "Annual workforce security-awareness training completed (CIS 14)."),
    ManualAssertionSpec("MAN-VENDOR-REVIEW", "Service-provider reviews performed",
                        ("Control 15",), "high", 365,
                        "Critical vendors risk-reviewed on cadence (CIS 15)."),
    ManualAssertionSpec("MAN-INCIDENT-EXERCISE", "Incident-response exercise conducted",
                        ("Control 17",), "high", 365,
                        "Tabletop / IR exercise conducted and documented (CIS 17)."),
    ManualAssertionSpec("MAN-PENTEST", "Penetration test performed",
                        ("Control 18",), "high", 365,
                        "Independent penetration test performed on cadence (CIS 18)."),
)}

MANUAL_CONTROLS: frozenset[str] = frozenset(
    c for s in MANUAL_ASSERTION_CATALOG.values() for c in s.control_edges)


def attestation_sha256(att: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(
        {k: att.get(k) for k in ("spec_id", "attester", "statement", "evidence_ref", "attested_at")},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def evaluate_manual(attestations: list[Mapping[str, Any]] | None,
                    as_of: str | None = None) -> list[dict[str, Any]]:
    """
    Evaluate the manual assertions against provided attestations. Each result is
    PASS (a current, in-cadence attestation exists), STALE (attestation older
    than cadence), or MANUAL_PENDING (no attestation) — never PASS without one.
    """
    by_spec: dict[str, Mapping[str, Any]] = {}
    for a in (attestations or []):
        sid = a.get("spec_id")
        if sid in MANUAL_ASSERTION_CATALOG:
            # keep the most recent attestation per spec
            if sid not in by_spec or str(a.get("attested_at", "")) > str(by_spec[sid].get("attested_at", "")):
                by_spec[sid] = a

    results: list[dict[str, Any]] = []
    for spec in MANUAL_ASSERTION_CATALOG.values():
        att = by_spec.get(spec.spec_id)
        if not att:
            status, reason = MANUAL_PENDING, "no_attestation"
            evidence: list[dict[str, Any]] = []
        else:
            stale = _is_stale(att.get("attested_at"), as_of, spec.cadence_days)
            status = STALE if stale else PASS
            reason = "attestation_stale" if stale else "attested"
            evidence = [{
                "attester": att.get("attester"), "statement": att.get("statement"),
                "evidence_ref": att.get("evidence_ref"), "attested_at": att.get("attested_at"),
                "attestation_sha256": attestation_sha256(att),
                "raw_uri": f"furix-attestation://{attestation_sha256(att)}",
            }]
        results.append({
            "spec_id": spec.spec_id, "title": spec.title, "control_ids": list(spec.control_edges),
            "severity": spec.severity, "mode": spec.mode, "predicate_kind": spec.predicate_kind,
            "evaluator_hash": spec.evaluator_hash(), "cadence_days": spec.cadence_days,
            "status": status, "status_reason": reason, "rationale": spec.rationale,
            "evidence": evidence,
        })
    results.sort(key=lambda r: r["spec_id"])
    return results


def _is_stale(attested_at: str | None, as_of: str | None, cadence_days: int) -> bool:
    if not attested_at or not as_of:
        return False
    try:
        return datetime.fromisoformat(as_of) - datetime.fromisoformat(attested_at) > timedelta(days=cadence_days)
    except ValueError:
        return False
