"""
assertions.py
=============
Versioned AssertionSpec / AssertionRun models (FUR-CMP-008/003).

An **AssertionSpec** is the versioned definition of a control check: what it
applies to, the predicate it evaluates, its cadence and freshness expectation,
and which controls it evidences. The current rule pack is *detection-only* —
each POL rule is a negative predicate ("this bad thing was observed"), so no
spec can positively PASS yet. That limitation is encoded honestly in the spec's
`mode` and `predicate_kind`, not hidden.

An **AssertionRun** is one evaluation of a spec over a batch/window: the
population it saw (expected/observed/errored…), the resulting status with
reason codes, the evidence it references, and an `evaluator_hash` that pins
exactly which logic produced the verdict. Two runs of the same spec over the
same evidence must produce the same evaluator_hash.

These are derived from the existing TEST_CATALOG so the whole engine keeps one
source of truth for the 15 rules; this module adds the assurance-grade metadata
around them without duplicating the rules.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .registry import TEST_CATALOG
from .versions import RULE_PACK_VERSION


@dataclass(frozen=True)
class AssertionSpec:
    spec_id: str                     # == the POL rule id
    title: str
    control_edges: tuple[str, ...]   # controls this assertion evidences
    severity: str
    mode: str = "detection_only"     # detection_only | positive (future)
    predicate_kind: str = "negative"  # negative = "bad thing observed"
    subject_type: str = "log_event"
    cadence: str = "on_ingest"
    freshness_slo_seconds: int = 0   # 0 = evaluated only when evidence arrives
    policy_version: str = RULE_PACK_VERSION

    def evaluator_hash(self) -> str:
        """Content hash of the spec's decision-affecting fields (FUR-CMP-003)."""
        basis = {
            "spec_id": self.spec_id,
            "control_edges": list(self.control_edges),
            "mode": self.mode,
            "predicate_kind": self.predicate_kind,
            "subject_type": self.subject_type,
            "policy_version": self.policy_version,
        }
        return hashlib.sha256(
            json.dumps(basis, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = {
            "spec_id": self.spec_id,
            "title": self.title,
            "control_edges": list(self.control_edges),
            "severity": self.severity,
            "mode": self.mode,
            "predicate_kind": self.predicate_kind,
            "subject_type": self.subject_type,
            "cadence": self.cadence,
            "freshness_slo_seconds": self.freshness_slo_seconds,
            "policy_version": self.policy_version,
            "evaluator_hash": self.evaluator_hash(),
        }
        return d


# One spec per POL rule — the assurance metadata layered over TEST_CATALOG.
ASSERTION_CATALOG: dict[str, AssertionSpec] = {
    spec.test_id: AssertionSpec(
        spec_id=spec.test_id,
        title=spec.title,
        control_edges=spec.control_ids,
        severity=spec.severity,
    )
    for spec in TEST_CATALOG.values()
}


def assertion_run(
    spec_id: str,
    *,
    status: str,
    status_reason: str,
    occurrences: int,
    population: dict[str, Any],
    evidence_refs: list[str],
) -> dict[str, Any]:
    """Build the AssertionRun view attached to a test in a report."""
    spec = ASSERTION_CATALOG[spec_id]
    return {
        "spec_id": spec_id,
        "policy_version": spec.policy_version,
        "mode": spec.mode,
        "predicate_kind": spec.predicate_kind,
        "evaluator_hash": spec.evaluator_hash(),
        "status": status,
        "status_reason": status_reason,
        "occurrences": occurrences,
        "population": population,
        "evidence_refs": evidence_refs,
    }
