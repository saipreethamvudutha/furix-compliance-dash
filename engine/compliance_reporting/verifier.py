"""
verifier.py
===========
Independent verification of a compliance report, with named verification
levels (FUR-CMP-003). The point: you should not have to trust the report
builder — this module recomputes the report's claims through a deliberately
separate, simpler code path and cross-checks them. It also enforces the
assurance gates: no PASS/compliant state may exist without a positive
predicate (none exist in the current detection-only rule pack), and silence
may never promote posture.

Verification levels — the result reports exactly what was achieved:

  NOT_VERIFIED            verification did not complete
  INTEGRITY_VERIFIED      hashes, references and structure reconcile
                          (report alone — no batch available)
  ROLLUP_VERIFIED         + statuses and counters independently recomputed
                          from the stored batch's assertion results
  EVALUATION_REPRODUCED   + an injected analyzer re-ran the versioned
                          evaluation from the raw log lines and produced the
                          same content hash

Check families, each yielding coded failures:

  STRUCT-*   required keys/types exist (a minimal structural schema)
  REF-*      referential integrity (every id points at something real)
  GATE-*     assurance gates (no unsupported pass; silence never promotes)
  RECOMP-*   independent recomputation of statuses/counters/percentages
  CONS-*     conservation laws (totals reconcile end to end)
  HASH-*     integrity hash and deterministic report_id recompute
  REPRO-*    full evaluation reproduction from raw logs (level 3 only)

Usage:
    result = verify_report(report, batch)
    result.ok        → bool
    result.level     → achieved verification level string
    result.failures  → [(code, message), ...]
    result.checks_run → int
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from .registry import CONTROL_CATALOG, TEST_CATALOG, TESTS_BY_CONTROL
from .report_builder import (
    _UUID_NAMESPACE,
    VOLATILE_KEYS,
    canonical_json,
    is_failed_result,
    normalize_batch,
    rollup_requirement_status,
)

LEVEL_NOT_VERIFIED = "NOT_VERIFIED"
LEVEL_INTEGRITY = "INTEGRITY_VERIFIED"
LEVEL_ROLLUP = "ROLLUP_VERIFIED"
LEVEL_REPRODUCED = "EVALUATION_REPRODUCED"

# Human copy for each level — the dashboard shows THIS, never an overclaim.
LEVEL_DESCRIPTIONS = {
    LEVEL_NOT_VERIFIED: "verification did not complete",
    LEVEL_INTEGRITY: "hashes and references reconcile",
    LEVEL_ROLLUP: "statuses and counters independently recomputed from stored findings",
    LEVEL_REPRODUCED: "evaluation independently re-run from raw evidence",
}


@dataclass
class VerificationResult:
    checks_run: int = 0
    failures: list[tuple[str, str]] = field(default_factory=list)
    level: str = LEVEL_NOT_VERIFIED

    @property
    def ok(self) -> bool:
        return not self.failures

    def check(self, code: str, condition: bool, message: str) -> None:
        self.checks_run += 1
        if not condition:
            self.failures.append((code, message))

    def summary(self) -> str:
        status = "PASSED" if self.ok else "FAILED"
        lines = [
            f"Verification {status} [{self.level}] — "
            f"{self.checks_run} checks, {len(self.failures)} failure(s)"
        ]
        lines.extend(f"  ✗ [{code}] {msg}" for code, msg in self.failures)
        return "\n".join(lines)


# ── independent recomputation (kept intentionally naive) ─────────────────────
def _recompute_from_batch(batch: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """
    Second implementation of the rollup: plain loops, no shared helpers with
    report_builder beyond batch normalisation and the static catalogs.
    """
    entries = normalize_batch(batch)
    ok_entries = [e for e in entries if not is_failed_result(e["result"])]

    fired: dict[str, int] = {t: 0 for t in TEST_CATALOG}
    finding_uuids: set[str] = set()
    total_findings = 0
    for entry in ok_entries:
        for pf in entry["result"].get("policy_findings", []) or []:
            total_findings += 1
            rule = pf.get("rule_id", "")
            if rule in fired:
                fired[rule] += 1
            if pf.get("finding_uuid"):
                finding_uuids.add(pf["finding_uuid"])

    # Detection-only semantics: fired → fail, else unknown. NEVER pass.
    test_status = {t: ("fail" if n else "unknown") for t, n in fired.items()}

    control_status: dict[str, str] = {}
    for ctrl in CONTROL_CATALOG:
        mapped = TESTS_BY_CONTROL[ctrl]
        if not mapped:
            control_status[ctrl] = "not_monitored"
        elif any(test_status[t] == "fail" for t in mapped):
            control_status[ctrl] = "at_risk"
        else:
            control_status[ctrl] = "unknown"

    return {
        "total_logs": len(entries),
        "successful_logs": len(ok_entries),
        "failed_logs": len(entries) - len(ok_entries),
        "total_findings": total_findings,
        "fired": fired,
        "test_status": test_status,
        "control_status": control_status,
        "finding_uuids": finding_uuids,
    }


def _verify_structure(v: VerificationResult, report: Mapping[str, Any]) -> bool:
    """STRUCT + REF + GATE + HASH checks — possible from the report alone."""
    for key in ("schema_version", "versions", "batch", "summary", "tests",
                "controls", "frameworks", "integrity", "report_id", "generated_at"):
        v.check("STRUCT-KEY", key in report, f"missing top-level key: {key}")
    if not v.ok:
        return False  # can't meaningfully continue on a malformed document

    tests = report["tests"]
    controls = report["controls"]
    frameworks = report["frameworks"]
    v.check("STRUCT-TESTS", isinstance(tests, list) and len(tests) == len(TEST_CATALOG),
            f"expected {len(TEST_CATALOG)} tests, found {len(tests)}")
    v.check("STRUCT-CTRLS", isinstance(controls, list) and len(controls) == len(CONTROL_CATALOG),
            f"expected {len(CONTROL_CATALOG)} controls, found {len(controls)}")
    v.check("STRUCT-FWKS", isinstance(frameworks, list) and len(frameworks) == 4,
            f"expected 4 frameworks, found {len(frameworks)}")

    # ── REF: referential integrity ────────────────────────────────────────────
    test_ids = [t["test_id"] for t in tests]
    v.check("REF-TEST-DUP", len(test_ids) == len(set(test_ids)), "duplicate test_id in report")
    v.check("REF-TEST-CAT", set(test_ids) == set(TEST_CATALOG),
            "report tests do not match the policy-rule catalog")

    ctrl_ids = [c["control_id"] for c in controls]
    v.check("REF-CTRL-DUP", len(ctrl_ids) == len(set(ctrl_ids)), "duplicate control_id in report")
    v.check("REF-CTRL-CAT", set(ctrl_ids) == set(CONTROL_CATALOG),
            "report controls do not match the CIS catalog")

    for t in tests:
        for ctrl in t["control_ids"]:
            v.check("REF-TEST-CTRL", ctrl in CONTROL_CATALOG,
                    f"{t['test_id']} references unknown control {ctrl!r}")

    control_set = set(ctrl_ids)
    for fw in frameworks:
        for req in fw["requirements"]:
            unknown = [c for c in req["via_controls"] if c not in control_set]
            v.check("REF-FW-CTRL", not unknown,
                    f"{fw['framework_id']}:{req['requirement_id']} cites unknown controls {unknown}")

    # ── GATE: assurance gates (FUR-CMP-001/006) ───────────────────────────────
    # No test may claim "pass" without a positive predicate. The current rule
    # pack is detection-only, so ANY pass is an unsupported claim.
    for t in tests:
        if t.get("evaluation_mode", "detection_only") == "detection_only":
            v.check("GATE-NO-PASS", t["status"] != "pass",
                    f"{t['test_id']} claims 'pass' but is a detection-only rule "
                    "with no positive predicate")
    # No control may claim "compliant" unless every mapped test passed.
    tests_by_id = {t["test_id"]: t for t in tests}
    for c in controls:
        if c["status"] == "compliant":
            mapped = TESTS_BY_CONTROL.get(c["control_id"], ())
            all_pass = bool(mapped) and all(
                tests_by_id[t]["status"] == "pass" for t in mapped if t in tests_by_id
            )
            v.check("GATE-NO-COMPLIANT", all_pass,
                    f"{c['control_id']} claims 'compliant' without all mapped tests passing")
    # No requirement may outrank its contributors (silence never promotes).
    ctrl_status_map = {c["control_id"]: c["status"] for c in controls}
    for fw in frameworks:
        for req in fw["requirements"]:
            statuses = [ctrl_status_map[c] for c in req["via_controls"] if c in ctrl_status_map]
            v.check("GATE-REQ-ROLLUP",
                    req["status"] == rollup_requirement_status(statuses),
                    f"{fw['framework_id']}:{req['requirement_id']} status "
                    f"{req['status']!r} not derivable from contributors {statuses}")

    # ── EVID + ASSERT: evidence pointers and assertion runs (FUR-CMP-007/008) ──
    from .assertions import ASSERTION_CATALOG  # local import avoids load cycle
    from .evidence import evidence_uri
    for t in tests:
        for ev in t.get("evidence", []):
            sha = ev.get("log_sha256", "")
            uri = ev.get("raw_uri", "")
            if sha:
                v.check("EVID-URI", uri == evidence_uri(sha),
                        f"{t['test_id']} evidence raw_uri {uri!r} != uri for {sha[:12]}")
            else:
                v.check("EVID-URI", uri == "",
                        f"{t['test_id']} evidence has a raw_uri without a log_sha256")
        a = t.get("assertion")
        if a is not None:
            spec = ASSERTION_CATALOG.get(t["test_id"])
            v.check("ASSERT-HASH", spec is not None and a["evaluator_hash"] == spec.evaluator_hash(),
                    f"{t['test_id']} assertion evaluator_hash does not match the spec")
            refs = sorted({e["raw_uri"] for e in t.get("evidence", []) if e.get("raw_uri")})
            v.check("ASSERT-REFS", a["evidence_refs"] == refs,
                    f"{t['test_id']} assertion.evidence_refs do not match its evidence rows")
            v.check("ASSERT-STATUS", a["status"] == t["status"],
                    f"{t['test_id']} assertion status disagrees with the test status")

    # ── HASH: integrity + deterministic id ────────────────────────────────────
    payload = {k: report[k] for k in report if k not in VOLATILE_KEYS}
    expected_hash = _sha256_of(payload)
    v.check("HASH-CONTENT", report["integrity"]["content_sha256"] == expected_hash,
            "integrity.content_sha256 does not match recomputed content hash")
    v.check("HASH-REPORT-ID",
            report["report_id"] == str(uuid.uuid5(_UUID_NAMESPACE, expected_hash)),
            "report_id is not uuid5(namespace, content_sha256)")
    return True


def _verify_rollup(
    v: VerificationResult, report: Mapping[str, Any], batch: Iterable[Mapping[str, Any]]
) -> None:
    """RECOMP + CONS checks — requires the stored batch."""
    truth = _recompute_from_batch(batch)
    tests, controls, frameworks = report["tests"], report["controls"], report["frameworks"]

    b = report["batch"]
    v.check("RECOMP-LOGS", b["total_logs"] == truth["total_logs"],
            f"total_logs {b['total_logs']} != recomputed {truth['total_logs']}")
    v.check("RECOMP-OK", b["successful_logs"] == truth["successful_logs"],
            f"successful_logs {b['successful_logs']} != recomputed {truth['successful_logs']}")
    v.check("RECOMP-FAILED", b["failed_logs"] == truth["failed_logs"],
            f"failed_logs {b['failed_logs']} != recomputed {truth['failed_logs']}")

    # ── POP: completeness manifest reconciles with the batch (FUR-CMP-007) ─────
    pop = report.get("population", {})
    v.check("POP-EXPECTED", pop.get("expected") == truth["total_logs"],
            "population.expected != total logs")
    v.check("POP-OBSERVED", pop.get("observed") == truth["successful_logs"],
            "population.observed != successful logs")
    v.check("POP-ERRORED", pop.get("errored") == truth["failed_logs"],
            "population.errored != failed logs")
    v.check("POP-RECONCILE", pop.get("reconciled") is True,
            "population manifest does not reconcile (observed+errored+excluded+dup != expected)")

    for t in tests:
        tid = t["test_id"]
        v.check("RECOMP-TEST-N", t["occurrences"] == truth["fired"][tid],
                f"{tid} occurrences {t['occurrences']} != recomputed {truth['fired'][tid]}")
        v.check("RECOMP-TEST-S", t["status"] == truth["test_status"][tid],
                f"{tid} status {t['status']!r} != recomputed {truth['test_status'][tid]!r}")
        v.check("RECOMP-TEST-EV", len(t["evidence"]) == t["occurrences"],
                f"{tid} evidence rows {len(t['evidence'])} != occurrences {t['occurrences']}")
        for ev in t["evidence"]:
            v.check("REF-EV-UUID", ev["finding_uuid"] in truth["finding_uuids"],
                    f"{tid} evidence cites finding_uuid absent from batch: {ev['finding_uuid']}")
            expected = _sha256_of({k: ev[k] for k in ev if k != "evidence_sha256"})
            v.check("HASH-EVIDENCE", ev["evidence_sha256"] == expected,
                    f"{tid} evidence sha mismatch for {ev['finding_uuid']}")

    for c in controls:
        cid = c["control_id"]
        v.check("RECOMP-CTRL-S", c["status"] == truth["control_status"][cid],
                f"{cid} status {c['status']!r} != recomputed {truth['control_status'][cid]!r}")

    # framework counters + posture tuple recompute from the report's own rows
    for fw in frameworks:
        counts = {"compliant": 0, "at_risk": 0, "unknown": 0, "not_monitored": 0}
        monitored_reqs = 0
        for req in fw["requirements"]:
            counts[req["status"]] = counts.get(req["status"], 0) + 1
            if req["status"] != "not_monitored":
                monitored_reqs += 1
            expected_cov = sum(
                1 for c in req["via_controls"]
                if truth["control_status"].get(c, "not_monitored") != "not_monitored"
            )
            v.check("RECOMP-REQ-COV", req["monitored_controls"] == expected_cov,
                    f"{fw['framework_id']}:{req['requirement_id']} monitored_controls "
                    f"{req['monitored_controls']} != recomputed {expected_cov}")

        v.check("RECOMP-FW-N",
                (fw["requirements_compliant"], fw["requirements_at_risk"],
                 fw["requirements_unknown"], fw["requirements_not_monitored"],
                 fw["requirements_total"])
                == (counts["compliant"], counts["at_risk"], counts["unknown"],
                    counts["not_monitored"], len(fw["requirements"])),
                f"{fw['framework_id']} requirement counters do not reconcile")

        total = len(fw["requirements"])
        expected_coverage = round(100.0 * monitored_reqs / total, 1) if total else 0.0
        v.check("RECOMP-FW-COV", fw["coverage_pct"] == expected_coverage,
                f"{fw['framework_id']} coverage_pct {fw['coverage_pct']} != recomputed {expected_coverage}")
        expected_at_risk = (
            round(100.0 * counts["at_risk"] / monitored_reqs, 1) if monitored_reqs else None
        )
        v.check("RECOMP-FW-RISK", fw["at_risk_pct"] == expected_at_risk,
                f"{fw['framework_id']} at_risk_pct {fw['at_risk_pct']} != recomputed {expected_at_risk}")
        expected_pct = (
            round(100.0 * counts["compliant"] / monitored_reqs, 1)
            if counts["compliant"] else None
        )
        v.check("RECOMP-FW-PCT", fw["compliance_pct"] == expected_pct,
                f"{fw['framework_id']} compliance_pct {fw['compliance_pct']} != recomputed {expected_pct}")

    # ── CONS: conservation laws ───────────────────────────────────────────────
    s = report["summary"]
    v.check("CONS-VIOLATIONS", s["total_violations"] == truth["total_findings"],
            f"summary.total_violations {s['total_violations']} != policy findings in batch {truth['total_findings']}")
    v.check("CONS-TEST-SUM", sum(t["occurrences"] for t in tests) == s["total_violations"],
            "sum of test occurrences != summary.total_violations")
    v.check("CONS-SEV-SUM", sum(s["violations_by_severity"].values()) == s["total_violations"],
            "violations_by_severity does not sum to total_violations")
    v.check("CONS-AT-RISK",
            set(s["controls_at_risk"]) == {c for c, st in truth["control_status"].items() if st == "at_risk"},
            "summary.controls_at_risk does not match recomputed at-risk set")
    v.check("CONS-UNKNOWN",
            set(s["controls_unknown"]) == {c for c, st in truth["control_status"].items() if st == "unknown"},
            "summary.controls_unknown does not match recomputed unknown set")


# ── public API ────────────────────────────────────────────────────────────────
def verify_report(
    report: Mapping[str, Any],
    batch: Iterable[Mapping[str, Any]] | None = None,
    *,
    raw_logs: Sequence_or_None = None,
    reanalyzer: Callable[[str, str], Mapping[str, Any]] | None = None,
    registry: Any = None,
) -> VerificationResult:
    """
    Verify a report to the deepest level the available inputs allow:

      report only                → INTEGRITY_VERIFIED
      + batch                    → ROLLUP_VERIFIED
      + raw_logs and reanalyzer  → EVALUATION_REPRODUCED (re-runs the
                                   evaluation and compares content hashes)

    The achieved level is on result.level; failures downgrade to NOT_VERIFIED.
    """
    v = VerificationResult()

    if not _verify_structure(v, report):
        return v  # missing top-level keys — nothing else is checkable

    # Run every applicable check family even after failures: a tampered report
    # should yield the FULL diagnostic picture, not just the first mismatch.
    if batch is not None:
        _verify_rollup(v, report, batch)

    if not v.ok:
        v.level = LEVEL_NOT_VERIFIED
        return v
    v.level = LEVEL_ROLLUP if batch is not None else LEVEL_INTEGRITY
    if batch is None:
        return v

    if raw_logs is not None and reanalyzer is not None:
        from .report_builder import build_report  # local import to avoid cycle at module load
        from .registry import FrameworkRegistry
        # The crosswalk is part of the hashed payload — reproduction must use
        # the SAME registry the original report was built with.
        reproduced = build_report(
            [{"log_type": lt, "result": dict(reanalyzer(raw, lt))} for lt, raw in raw_logs],
            registry=registry or FrameworkRegistry.from_snapshot(),
            generated_at=report["generated_at"],
        )
        v.check("REPRO-HASH",
                reproduced["integrity"]["content_sha256"] == report["integrity"]["content_sha256"],
                "re-evaluated content hash differs from the report under verification")
        if v.ok:
            v.level = LEVEL_REPRODUCED
        else:
            v.level = LEVEL_NOT_VERIFIED

    return v


# typing helper (kept simple to avoid importing typing.Sequence at call sites)
Sequence_or_None = Any


def _sha256_of(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
