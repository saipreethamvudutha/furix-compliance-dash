"""
report_builder.py
=================
Turns one batch of pipeline results into a canonical compliance report —
the Vanta/Drata three-layer rollup (test → control → framework) adapted to
Furix's event-based model:

  test status    : "fail"  the policy rule fired on ≥1 log in the batch
                   "pass"  the rule was evaluated on ≥1 successful log, never fired
                   "no_data"  no successful log in the batch
  control status : "at_risk"       ≥1 mapped test failed
                   "compliant"     monitored, no mapped test failed
                   "not_monitored" no policy rule covers this control
  framework req  : worst status of its contributing controls

Honest denominators: compliance_pct is compliant / monitored (at_risk +
compliant). not_monitored requirements are counted and shown, never folded
into the percentage.

Determinism: content_sha256 is computed over the payload minus volatile
metadata; report_id = UUIDv5 of that hash. Same batch in → identical report.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .registry import (
    CONTROL_CATALOG,
    TEST_CATALOG,
    TESTS_BY_CONTROL,
    FrameworkRegistry,
    severity_rank,
)

REPORT_SCHEMA_VERSION = "1.0"
# Fixed namespace for deriving deterministic report ids (uuid5 of content hash)
_UUID_NAMESPACE = uuid.UUID("6b6f1d8e-4a5b-4f0e-9c33-a1b2c3d4e5f6")
_EVIDENCE_VALUE_MAX = 300  # chars of triggered_value retained per evidence item

STATUS_PASS, STATUS_FAIL, STATUS_NO_DATA = "pass", "fail", "no_data"
CTRL_COMPLIANT, CTRL_AT_RISK, CTRL_NOT_MONITORED = "compliant", "at_risk", "not_monitored"


# ── batch normalisation ───────────────────────────────────────────────────────
def normalize_batch(batch: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """
    Accept both shapes the pipeline produces and return a uniform list of
    {"log_type": str, "result": dict} entries:

      * wrapped entries from complete_log_pipeline_run():
            {"log_type": ..., "result": {...}, "elapsed_sec": ...}
      * bare result dicts from run_full_pipeline()
    """
    normalized: list[dict[str, Any]] = []
    for entry in batch:
        if not isinstance(entry, Mapping):
            raise TypeError(f"Batch entries must be mappings, got {type(entry).__name__}")
        if "result" in entry and isinstance(entry["result"], Mapping):
            result = dict(entry["result"])
            log_type = entry.get("log_type") or result.get("findings", {}).get("log_type", "unknown")
        else:
            result = dict(entry)
            log_type = result.get("findings", {}).get("log_type", "unknown") if isinstance(result.get("findings"), Mapping) else "unknown"
        normalized.append({"log_type": str(log_type), "result": result})
    return normalized


# Stages that leave a usable verdict (findings + policy + control mapping) behind.
# "rag_retrieval" only means the optional evidence-text layer was unavailable — the
# deterministic compliance result is intact, so it counts as a (degraded) success.
_NON_FATAL_STAGES = {None, "rag_retrieval"}


def is_failed_result(result: Mapping[str, Any]) -> bool:
    """A result is failed if its stage is fatal, or it has no findings at all."""
    if result.get("_failure_stage") not in _NON_FATAL_STAGES:
        return True
    return not result.get("findings")


# ── evidence extraction ───────────────────────────────────────────────────────
def _evidence_items(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Flatten every policy finding across successful logs into evidence rows.
    Each row is self-describing and carries its own sha256 so any single item
    can later be shown untampered.
    """
    items: list[dict[str, Any]] = []
    for idx, entry in enumerate(entries):
        result = entry["result"]
        if is_failed_result(result):
            continue
        for pf in result.get("policy_findings", []) or []:
            row = {
                "log_index": idx,
                "log_type": entry["log_type"],
                "test_id": pf.get("rule_id", "UNKNOWN"),
                "finding_uuid": pf.get("finding_uuid", ""),
                "severity": pf.get("severity", "low"),
                "triggered_field": pf.get("triggered_field", ""),
                "triggered_value": str(pf.get("triggered_value", ""))[:_EVIDENCE_VALUE_MAX],
                "timestamp": pf.get("timestamp", ""),
            }
            row["evidence_sha256"] = _sha256_of(row)
            items.append(row)
    return items


# ── layer 1: tests ────────────────────────────────────────────────────────────
def _build_tests(evidence: list[dict[str, Any]], evaluated_any: bool) -> list[dict[str, Any]]:
    by_test: dict[str, list[dict[str, Any]]] = {}
    for item in evidence:
        by_test.setdefault(item["test_id"], []).append(item)

    tests: list[dict[str, Any]] = []
    for test_id in sorted(TEST_CATALOG):
        spec = TEST_CATALOG[test_id]
        fired = by_test.get(test_id, [])
        if fired:
            status = STATUS_FAIL
        elif evaluated_any:
            status = STATUS_PASS
        else:
            status = STATUS_NO_DATA
        tests.append(
            {
                "test_id": test_id,
                "title": spec.title,
                "severity": spec.severity,
                "control_ids": list(spec.control_ids),
                "status": status,
                "occurrences": len(fired),
                "evidence": sorted(fired, key=lambda e: (e["log_index"], e["finding_uuid"])),
            }
        )
    return tests


# ── layer 2: controls ─────────────────────────────────────────────────────────
def _attack_by_control(entries: list[dict[str, Any]]) -> dict[str, list[dict[str, str]]]:
    """
    Aggregate the ATT&CK/Sigma provenance (findings.attack_pivot.trace) per CIS
    control across the batch: {control_id: [{technique_id, technique_name,
    rule_id, rule_title, level}]}, de-duplicated and deterministically sorted.
    """
    by_ctrl: dict[str, dict[tuple[str, str], dict[str, str]]] = {}
    for entry in entries:
        result = entry["result"]
        if is_failed_result(result):
            continue
        trace = ((result.get("findings") or {}).get("attack_pivot") or {}).get("trace") or []
        for row in trace:
            cid = row.get("control_id")
            if not cid:
                continue
            key = (row.get("technique_id", ""), row.get("rule_id", ""))
            by_ctrl.setdefault(cid, {})[key] = {
                "technique_id": row.get("technique_id", ""),
                "technique_name": row.get("technique_name", ""),
                "rule_id": row.get("rule_id", ""),
                "rule_title": row.get("rule_title", ""),
                "level": row.get("rule_level", ""),
            }
    return {
        cid: [rows[k] for k in sorted(rows)]
        for cid, rows in by_ctrl.items()
    }


def _build_controls(
    tests: list[dict[str, Any]], entries: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    tests_by_id = {t["test_id"]: t for t in tests}
    attack_by_control = _attack_by_control(entries)

    # How often did detection map each control, independent of rule firing?
    observation_counts: dict[str, int] = {c: 0 for c in CONTROL_CATALOG}
    for entry in entries:
        result = entry["result"]
        if is_failed_result(result):
            continue
        mapped = (result.get("compliance_mapping") or {}).get("cis_controls") or []
        for ctrl in mapped:
            if ctrl in observation_counts:
                observation_counts[ctrl] += 1

    controls: list[dict[str, Any]] = []
    for control_id, title in CONTROL_CATALOG.items():
        mapped_test_ids = TESTS_BY_CONTROL[control_id]
        failing = [t for t in mapped_test_ids if tests_by_id[t]["status"] == STATUS_FAIL]
        passing = [t for t in mapped_test_ids if tests_by_id[t]["status"] == STATUS_PASS]

        if not mapped_test_ids:
            status = CTRL_NOT_MONITORED
        elif failing:
            status = CTRL_AT_RISK
        else:
            status = CTRL_COMPLIANT

        worst = ""
        if failing:
            worst = max(
                (tests_by_id[t]["severity"] for t in failing), key=severity_rank
            )

        controls.append(
            {
                "control_id": control_id,
                "title": title,
                "status": status,
                "failing_tests": failing,
                "passing_tests": passing,
                "violation_count": sum(tests_by_id[t]["occurrences"] for t in failing),
                "worst_severity": worst,
                "observation_count": observation_counts[control_id],
                "attack": attack_by_control.get(control_id, []),
            }
        )
    return controls


# ── layer 3: frameworks ───────────────────────────────────────────────────────
def _rollup_framework(
    framework_id: str,
    name: str,
    requirement_edges: Mapping[str, tuple[str, ...]],
    controls: list[dict[str, Any]],
) -> dict[str, Any]:
    control_status = {c["control_id"]: c["status"] for c in controls}

    requirements: list[dict[str, Any]] = []
    counts = {CTRL_COMPLIANT: 0, CTRL_AT_RISK: 0, CTRL_NOT_MONITORED: 0}
    for req_id, contributing in sorted(requirement_edges.items()):
        statuses = [control_status[c] for c in contributing if c in control_status]
        if any(s == CTRL_AT_RISK for s in statuses):
            status = CTRL_AT_RISK
        elif any(s == CTRL_COMPLIANT for s in statuses):
            status = CTRL_COMPLIANT
        else:
            status = CTRL_NOT_MONITORED
        counts[status] += 1
        requirements.append(
            {"requirement_id": req_id, "status": status, "via_controls": list(contributing)}
        )

    monitored = counts[CTRL_COMPLIANT] + counts[CTRL_AT_RISK]
    pct = round(100.0 * counts[CTRL_COMPLIANT] / monitored, 1) if monitored else None
    return {
        "framework_id": framework_id,
        "name": name,
        "requirements_total": len(requirements),
        "requirements_compliant": counts[CTRL_COMPLIANT],
        "requirements_at_risk": counts[CTRL_AT_RISK],
        "requirements_not_monitored": counts[CTRL_NOT_MONITORED],
        "compliance_pct": pct,
        "requirements": requirements,
    }


def _build_frameworks(
    controls: list[dict[str, Any]], registry: FrameworkRegistry
) -> list[dict[str, Any]]:
    cis_edges = {c: (c,) for c in CONTROL_CATALOG}  # CIS requirements ARE the controls
    return [
        _rollup_framework("cis_v8", "CIS Controls v8.1", cis_edges, controls),
        _rollup_framework("nist_csf_2_0", "NIST CSF 2.0", registry.nist_requirements(), controls),
        _rollup_framework("hipaa_security_rule", "HIPAA Security Rule", registry.hipaa_requirements(), controls),
        _rollup_framework("pci_dss_4_0", "PCI DSS 4.0", registry.pci_requirements(), controls),
    ]


# ── canonicalisation / integrity ──────────────────────────────────────────────
def canonical_json(obj: Any) -> str:
    """Stable serialisation used for hashing and determinism checks."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_of(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


# ── public API ────────────────────────────────────────────────────────────────
def build_report(
    batch: Iterable[Mapping[str, Any]],
    *,
    registry: FrameworkRegistry | None = None,
    generated_at: str | None = None,
    engine_version: str = "2.0.0",
) -> dict[str, Any]:
    """
    Build the canonical compliance report for one batch of pipeline results.

    Args:
        batch: wrapped entries from complete_log_pipeline_run() or bare
               run_full_pipeline() result dicts (mixed is fine).
        registry: framework crosswalk; defaults to FrameworkRegistry.from_live()
               (live furix_det edges when reachable, bundled snapshot otherwise).
        generated_at: ISO timestamp override (volatile — excluded from the
               content hash; injectable for reproducible tests).
        engine_version: surfaced in metadata.

    Returns a plain dict, ready for json.dumps / render_html_report /
    verify_report.
    """
    registry = registry or FrameworkRegistry.from_live()
    entries = normalize_batch(batch)

    successes = [e for e in entries if not is_failed_result(e["result"])]
    failures = [e for e in entries if is_failed_result(e["result"])]

    log_type_counts: dict[str, int] = {}
    for e in entries:
        log_type_counts[e["log_type"]] = log_type_counts.get(e["log_type"], 0) + 1

    run_stamps = sorted(
        s for s in (e["result"].get("_run_timestamp") for e in successes) if s
    )

    evidence = _evidence_items(entries)
    tests = _build_tests(evidence, evaluated_any=bool(successes))
    controls = _build_controls(tests, entries)
    frameworks = _build_frameworks(controls, registry)

    violations_by_severity: dict[str, int] = {}
    for item in evidence:
        violations_by_severity[item["severity"]] = violations_by_severity.get(item["severity"], 0) + 1

    payload = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "engine_version": engine_version,
        "crosswalk_provenance": registry.provenance,
        "batch": {
            "total_logs": len(entries),
            "successful_logs": len(successes),
            "failed_logs": len(failures),
            "log_types": dict(sorted(log_type_counts.items())),
            "window": {
                "first_run_timestamp": run_stamps[0] if run_stamps else None,
                "last_run_timestamp": run_stamps[-1] if run_stamps else None,
            },
        },
        "summary": {
            "tests_total": len(tests),
            "tests_failed": sum(1 for t in tests if t["status"] == STATUS_FAIL),
            "tests_passed": sum(1 for t in tests if t["status"] == STATUS_PASS),
            "total_violations": len(evidence),
            "violations_by_severity": dict(sorted(violations_by_severity.items())),
            "controls_at_risk": sorted(
                c["control_id"] for c in controls if c["status"] == CTRL_AT_RISK
            ),
            "controls_not_monitored": sorted(
                c["control_id"] for c in controls if c["status"] == CTRL_NOT_MONITORED
            ),
        },
        "tests": tests,
        "controls": controls,
        "frameworks": frameworks,
    }

    content_sha256 = _sha256_of(payload)
    report = dict(payload)
    report["integrity"] = {
        "content_sha256": content_sha256,
        "canonicalization": "json(sort_keys, separators=(',',':'), utf-8) over report minus integrity/report_id/generated_at",
    }
    report["report_id"] = str(uuid.uuid5(_UUID_NAMESPACE, content_sha256))
    report["generated_at"] = generated_at or datetime.now(timezone.utc).isoformat(timespec="microseconds")
    return report
