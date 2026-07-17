"""
verifier.py
===========
Independent verification of a compliance report against the raw batch it was
built from. The point: you should not have to trust the report builder —
this module recomputes the report's claims through a deliberately separate,
simpler code path and cross-checks them.

Five families of checks, each yielding coded failures:

  STRUCT-*   required keys/types exist (a minimal structural schema)
  REF-*      referential integrity (every id points at something real)
  RECOMP-*   independent recomputation of statuses/counters/percentages
  CONS-*     conservation laws (totals reconcile end to end)
  HASH-*     integrity hash and deterministic report_id recompute

Usage:
    result = verify_report(report, batch)
    result.ok        → bool
    result.failures  → [(code, message), ...]
    result.checks_run → int
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .registry import CONTROL_CATALOG, TEST_CATALOG, TESTS_BY_CONTROL
from .report_builder import (
    _UUID_NAMESPACE,
    canonical_json,
    is_failed_result,
    normalize_batch,
)


@dataclass
class VerificationResult:
    checks_run: int = 0
    failures: list[tuple[str, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures

    def check(self, code: str, condition: bool, message: str) -> None:
        self.checks_run += 1
        if not condition:
            self.failures.append((code, message))

    def summary(self) -> str:
        status = "PASSED" if self.ok else "FAILED"
        lines = [f"Verification {status} — {self.checks_run} checks, {len(self.failures)} failure(s)"]
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

    test_status = {
        t: ("fail" if n else ("pass" if ok_entries else "no_data"))
        for t, n in fired.items()
    }

    control_status: dict[str, str] = {}
    for ctrl in CONTROL_CATALOG:
        mapped = TESTS_BY_CONTROL[ctrl]
        if not mapped:
            control_status[ctrl] = "not_monitored"
        elif any(test_status[t] == "fail" for t in mapped):
            control_status[ctrl] = "at_risk"
        else:
            control_status[ctrl] = "compliant"

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


# ── public API ────────────────────────────────────────────────────────────────
def verify_report(
    report: Mapping[str, Any], batch: Iterable[Mapping[str, Any]]
) -> VerificationResult:
    v = VerificationResult()

    # ── STRUCT: shape ─────────────────────────────────────────────────────────
    for key in ("schema_version", "batch", "summary", "tests", "controls",
                "frameworks", "integrity", "report_id", "generated_at"):
        v.check("STRUCT-KEY", key in report, f"missing top-level key: {key}")
    if not v.ok:
        return v  # can't meaningfully continue on a malformed document

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

    # ── RECOMP: independent recomputation ─────────────────────────────────────
    truth = _recompute_from_batch(batch)

    b = report["batch"]
    v.check("RECOMP-LOGS", b["total_logs"] == truth["total_logs"],
            f"total_logs {b['total_logs']} != recomputed {truth['total_logs']}")
    v.check("RECOMP-OK", b["successful_logs"] == truth["successful_logs"],
            f"successful_logs {b['successful_logs']} != recomputed {truth['successful_logs']}")
    v.check("RECOMP-FAILED", b["failed_logs"] == truth["failed_logs"],
            f"failed_logs {b['failed_logs']} != recomputed {truth['failed_logs']}")

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

    # framework percentages recompute from the report's own requirement rows,
    # then requirement statuses recompute from control statuses
    ctrl_status_map = {c["control_id"]: c["status"] for c in controls}
    for fw in frameworks:
        compliant = at_risk = unmonitored = 0
        for req in fw["requirements"]:
            statuses = [ctrl_status_map[c] for c in req["via_controls"]]
            if any(s == "at_risk" for s in statuses):
                expected = "at_risk"
            elif any(s == "compliant" for s in statuses):
                expected = "compliant"
            else:
                expected = "not_monitored"
            v.check("RECOMP-REQ-S", req["status"] == expected,
                    f"{fw['framework_id']}:{req['requirement_id']} status {req['status']!r} != derived {expected!r}")
            compliant += req["status"] == "compliant"
            at_risk += req["status"] == "at_risk"
            unmonitored += req["status"] == "not_monitored"

        v.check("RECOMP-FW-N",
                (fw["requirements_compliant"], fw["requirements_at_risk"],
                 fw["requirements_not_monitored"], fw["requirements_total"])
                == (compliant, at_risk, unmonitored, len(fw["requirements"])),
                f"{fw['framework_id']} requirement counters do not reconcile")
        monitored = compliant + at_risk
        expected_pct = round(100.0 * compliant / monitored, 1) if monitored else None
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

    # ── HASH: integrity + deterministic id ────────────────────────────────────
    payload = {k: report[k] for k in report
               if k not in ("integrity", "report_id", "generated_at")}
    expected_hash = _sha256_of(payload)
    v.check("HASH-CONTENT", report["integrity"]["content_sha256"] == expected_hash,
            "integrity.content_sha256 does not match recomputed content hash")
    v.check("HASH-REPORT-ID",
            report["report_id"] == str(uuid.uuid5(_UUID_NAMESPACE, expected_hash)),
            "report_id is not uuid5(namespace, content_sha256)")

    return v


def _sha256_of(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
