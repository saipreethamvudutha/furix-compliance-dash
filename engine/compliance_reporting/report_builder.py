"""
report_builder.py
=================
Turns one batch of pipeline results into a canonical compliance report using
an honest assurance-state model (Assurance Kernel v2, FUR-CMP-001/002/006).

Status vocabulary
-----------------
  test (assertion) : "fail"     the policy rule fired on ≥1 log in the batch
                     "unknown"  the rule did not fire. Detection-only rules can
                                NEVER produce "pass": a detector not firing
                                means "not observed in these events", not
                                "positively verified". Reason codes:
                                  not_observed  rule evaluated ≥1 log, no hit
                                  no_data       no successful log in the batch
                     "pass"     RESERVED — requires a positive predicate over
                                an expected population with fresh evidence
                                (AssertionSpecs, Wave 1+). Unreachable today.
  control          : "at_risk"        ≥1 mapped test failed
                     "unknown"        monitored, nothing fired — NOT proof of
                                      compliance, only "no violations observed"
                     "not_monitored"  no policy rule covers this control
                     "compliant"      RESERVED — all mapped assertions pass
  framework req    : "at_risk" if any contributor at_risk; "unknown" if any
                     contributor monitored (silence never promotes posture);
                     "not_monitored" only when NO contributor is monitored.
                     Every requirement carries monitored/total contributor
                     coverage so partial monitoring is always visible.

Posture is a tuple — state counts + coverage_pct + at_risk_pct — never a
single "compliance percentage". compliance_pct is None until positive
assertions exist (kept in the schema so the field's absence can't be
misread as 100%).

Determinism (FUR-CMP-002): the content hash covers everything EXCEPT
run_metadata/generated_at/integrity/report_id. Volatile ingestion-time
values (run timestamps) live only in run_metadata. Same logs + same
versions → byte-identical hashed payload → same report_id.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .assertions import assertion_run
from .evidence import build_population_manifest, evidence_uri
from .registry import (
    CONTROL_CATALOG,
    TEST_CATALOG,
    TESTS_BY_CONTROL,
    FrameworkRegistry,
    severity_rank,
)
from .versions import ENGINE_VERSION, REPORT_SCHEMA_VERSION, VERSION_MANIFEST

# Fixed namespace for deriving deterministic report ids (uuid5 of content hash)
_UUID_NAMESPACE = uuid.UUID("6b6f1d8e-4a5b-4f0e-9c33-a1b2c3d4e5f6")
_EVIDENCE_VALUE_MAX = 300  # chars of triggered_value retained per evidence item

# test states
STATUS_FAIL, STATUS_UNKNOWN, STATUS_PASS = "fail", "unknown", "pass"
# control states
CTRL_AT_RISK, CTRL_UNKNOWN, CTRL_NOT_MONITORED, CTRL_COMPLIANT = (
    "at_risk", "unknown", "not_monitored", "compliant",
)
# fields excluded from the content hash (volatile, never verdict identity)
VOLATILE_KEYS = ("integrity", "report_id", "generated_at", "run_metadata")


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
    Each row is self-describing, carries the source log's sha256 (the seed of
    the evidence lineage chain) and its own row hash so any single item can
    later be shown untampered.
    """
    items: list[dict[str, Any]] = []
    for idx, entry in enumerate(entries):
        result = entry["result"]
        if is_failed_result(result):
            continue
        log_sha = str(
            result.get("log_sha256")
            or (result.get("findings") or {}).get("log_sha256")
            or ""
        )
        for pf in result.get("policy_findings", []) or []:
            row = {
                "log_index": idx,
                "log_type": entry["log_type"],
                "log_sha256": log_sha,
                # Resolvable pointer into the immutable evidence store
                # (FUR-CMP-007). "" when the raw line wasn't retained (legacy
                # or fixture batches) — the excerpt below is then all there is.
                "raw_uri": evidence_uri(log_sha) if log_sha else "",
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
def _build_tests(evidence: list[dict[str, Any]], logs_evaluated: int) -> list[dict[str, Any]]:
    by_test: dict[str, list[dict[str, Any]]] = {}
    for item in evidence:
        by_test.setdefault(item["test_id"], []).append(item)

    tests: list[dict[str, Any]] = []
    for test_id in sorted(TEST_CATALOG):
        spec = TEST_CATALOG[test_id]
        fired = by_test.get(test_id, [])
        if fired:
            status, reason = STATUS_FAIL, "violations_observed"
        elif logs_evaluated:
            # A detector that did not fire proves nothing positive (FUR-CMP-001).
            status, reason = STATUS_UNKNOWN, "not_observed"
        else:
            status, reason = STATUS_UNKNOWN, "no_data"
        evidence_rows = sorted(fired, key=lambda e: (e["log_index"], e["finding_uuid"]))
        evidence_refs = sorted({e["raw_uri"] for e in evidence_rows if e.get("raw_uri")})
        # Per-assertion population: how many logs this detector evaluated, and
        # how many matched. Detection-only, so "evaluated" is the observed set.
        population = {"evaluated": logs_evaluated, "matched": len(fired)}
        tests.append(
            {
                "test_id": test_id,
                "title": spec.title,
                "severity": spec.severity,
                "control_ids": list(spec.control_ids),
                "status": status,
                "status_reason": reason,
                "evaluation_mode": "detection_only",  # no positive predicate yet
                "logs_evaluated": logs_evaluated,
                "occurrences": len(fired),
                "evidence": evidence_rows,
                # AssertionRun view (FUR-CMP-008): pins the versioned logic
                # (evaluator_hash), the population, and the evidence it cites.
                "assertion": assertion_run(
                    test_id, status=status, status_reason=reason,
                    occurrences=len(fired), population=population,
                    evidence_refs=evidence_refs,
                ),
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


def _config_by_control(config_results: list[dict[str, Any]]) -> dict[str, dict[str, list[str]]]:
    """Group config-assertion outcomes per CIS control."""
    by_ctrl: dict[str, dict[str, list[str]]] = {}
    for res in config_results:
        bucket = {"pass": "passing", "fail": "failing"}.get(res["status"], "unknown")
        for cid in res["control_ids"]:
            slot = by_ctrl.setdefault(cid, {"passing": [], "failing": [], "unknown": []})
            slot[bucket].append(res["spec_id"])
    return by_ctrl


def _build_controls(
    tests: list[dict[str, Any]],
    entries: list[dict[str, Any]],
    config_results: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    tests_by_id = {t["test_id"]: t for t in tests}
    attack_by_control = _attack_by_control(entries)
    config_by_control = _config_by_control(config_results or [])
    config_specs = {r["spec_id"]: r for r in (config_results or [])}

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
        cfg = config_by_control.get(control_id, {"passing": [], "failing": [], "unknown": []})

        det_failing = [t for t in mapped_test_ids if tests_by_id[t]["status"] == STATUS_FAIL]
        det_unknown = [t for t in mapped_test_ids if tests_by_id[t]["status"] == STATUS_UNKNOWN]
        det_passing = [t for t in mapped_test_ids if tests_by_id[t]["status"] == STATUS_PASS]
        cfg_failing, cfg_passing, cfg_unknown = cfg["failing"], cfg["passing"], cfg["unknown"]

        monitored = bool(mapped_test_ids) or bool(cfg_failing or cfg_passing or cfg_unknown)
        any_failing = bool(det_failing or cfg_failing)
        any_positive_pass = bool(det_passing or cfg_passing)

        if not monitored:
            status = CTRL_NOT_MONITORED
        elif any_failing:
            status = CTRL_AT_RISK
        elif any_positive_pass and not cfg_unknown:
            # Positively demonstrated: ≥1 assertion verified the control is in
            # place, nothing failed, and config population is complete. This is
            # the ONLY path to `compliant`. Detection silence does NOT block it
            # (no attack observed is the normal good state), but an incomplete
            # config population (cfg_unknown) does.
            status = CTRL_COMPLIANT
        else:
            status = CTRL_UNKNOWN

        worst = ""
        sevs = [tests_by_id[t]["severity"] for t in det_failing]
        sevs += [config_specs[s]["severity"] for s in cfg_failing if s in config_specs]
        if sevs:
            worst = max(sevs, key=severity_rank)

        evidence_mode = "config+detection" if (cfg and mapped_test_ids) else (
            "config" if cfg_failing or cfg_passing or cfg_unknown else
            ("detection_only" if mapped_test_ids else "none"))

        controls.append(
            {
                "control_id": control_id,
                "title": title,
                "status": status,
                "evidence_mode": evidence_mode,
                "failing_tests": det_failing,
                "unknown_tests": det_unknown,
                "passing_tests": det_passing,
                "config_passing": cfg_passing,
                "config_failing": cfg_failing,
                "config_unknown": cfg_unknown,
                "violation_count": sum(tests_by_id[t]["occurrences"] for t in det_failing),
                "worst_severity": worst,
                "observation_count": observation_counts[control_id],
                "attack": attack_by_control.get(control_id, []),
            }
        )
    return controls


# ── layer 3: frameworks ───────────────────────────────────────────────────────
def rollup_requirement_status(statuses: list[str]) -> str:
    """
    Coverage-aware requirement rollup (FUR-CMP-006). Silence never promotes:
      * any contributor at_risk            → at_risk
      * else all contributors compliant    → compliant (needs ≥1, all positive)
      * else any contributor monitored     → unknown
      * else                               → not_monitored
    """
    if any(s == CTRL_AT_RISK for s in statuses):
        return CTRL_AT_RISK
    monitored = [s for s in statuses if s != CTRL_NOT_MONITORED]
    if monitored and all(s == CTRL_COMPLIANT for s in monitored):
        # Partial monitoring can never yield compliant: every contributor
        # must be monitored AND positively compliant.
        if len(monitored) == len(statuses):
            return CTRL_COMPLIANT
        return CTRL_UNKNOWN
    if monitored:
        return CTRL_UNKNOWN
    return CTRL_NOT_MONITORED


def _rollup_framework(
    framework_id: str,
    name: str,
    requirement_edges: Mapping[str, tuple[str, ...]],
    controls: list[dict[str, Any]],
) -> dict[str, Any]:
    control_status = {c["control_id"]: c["status"] for c in controls}

    requirements: list[dict[str, Any]] = []
    counts = {CTRL_COMPLIANT: 0, CTRL_AT_RISK: 0, CTRL_UNKNOWN: 0, CTRL_NOT_MONITORED: 0}
    for req_id, contributing in sorted(requirement_edges.items()):
        statuses = [control_status[c] for c in contributing if c in control_status]
        status = rollup_requirement_status(statuses)
        counts[status] += 1
        monitored_n = sum(1 for s in statuses if s != CTRL_NOT_MONITORED)
        requirements.append(
            {
                "requirement_id": req_id,
                "status": status,
                "via_controls": list(contributing),
                "monitored_controls": monitored_n,
                "total_controls": len(statuses),
            }
        )

    total = len(requirements)
    monitored_reqs = total - counts[CTRL_NOT_MONITORED]
    coverage_pct = round(100.0 * monitored_reqs / total, 1) if total else 0.0
    at_risk_pct = (
        round(100.0 * counts[CTRL_AT_RISK] / monitored_reqs, 1) if monitored_reqs else None
    )
    # compliance_pct requires positive assertions; None = "not computable from
    # detection-only evidence", NEVER a hidden 100%.
    compliance_pct = (
        round(100.0 * counts[CTRL_COMPLIANT] / monitored_reqs, 1)
        if counts[CTRL_COMPLIANT] else None
    )
    return {
        "framework_id": framework_id,
        "name": name,
        "requirements_total": total,
        "requirements_compliant": counts[CTRL_COMPLIANT],
        "requirements_at_risk": counts[CTRL_AT_RISK],
        "requirements_unknown": counts[CTRL_UNKNOWN],
        "requirements_not_monitored": counts[CTRL_NOT_MONITORED],
        "coverage_pct": coverage_pct,
        "at_risk_pct": at_risk_pct,
        "compliance_pct": compliance_pct,
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
    engine_version: str = ENGINE_VERSION,
    config_snapshot: Any = None,
    config_as_of: str | None = None,
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
        engine_version: surfaced in the version manifest.

    Returns a plain dict, ready for json.dumps / render_html_report /
    verify_report. The content hash covers everything except VOLATILE_KEYS,
    so identical input + identical versions → identical report_id.
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

    # Positive config-posture assertions (Wave 2): the only path to `compliant`.
    config_results: list[dict[str, Any]] = []
    if config_snapshot is not None:
        from .config_assertions import evaluate as _eval_config  # local import
        from .connectors import ConfigSnapshot, parse_snapshot
        snap = config_snapshot if isinstance(config_snapshot, ConfigSnapshot) else parse_snapshot(config_snapshot)
        config_results = _eval_config(snap, as_of=config_as_of)

    evidence = _evidence_items(entries)
    tests = _build_tests(evidence, logs_evaluated=len(successes))
    controls = _build_controls(tests, entries, config_results)
    frameworks = _build_frameworks(controls, registry)

    violations_by_severity: dict[str, int] = {}
    for item in evidence:
        violations_by_severity[item["severity"]] = violations_by_severity.get(item["severity"], 0) + 1

    versions = dict(VERSION_MANIFEST)
    versions["engine"] = engine_version

    payload = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "engine_version": engine_version,   # kept for backward compat; == versions.engine
        "versions": versions,
        "crosswalk_provenance": registry.provenance,
        "batch": {
            "total_logs": len(entries),
            "successful_logs": len(successes),
            "failed_logs": len(failures),
            "log_types": dict(sorted(log_type_counts.items())),
        },
        # Completeness manifest (FUR-CMP-007): reconciles the subjects the batch
        # was expected to cover vs what was observed vs errored, so partial
        # telemetry can never read as healthy.
        "population": build_population_manifest(
            expected=len(entries), observed=len(successes), errored=len(failures)
        ),
        "summary": {
            "tests_total": len(tests),
            "tests_failed": sum(1 for t in tests if t["status"] == STATUS_FAIL),
            "tests_unknown": sum(1 for t in tests if t["status"] == STATUS_UNKNOWN),
            "tests_passed": sum(1 for t in tests if t["status"] == STATUS_PASS),
            "total_violations": len(evidence),
            "violations_by_severity": dict(sorted(violations_by_severity.items())),
            "controls_compliant": sorted(
                c["control_id"] for c in controls if c["status"] == CTRL_COMPLIANT
            ),
            "controls_at_risk": sorted(
                c["control_id"] for c in controls if c["status"] == CTRL_AT_RISK
            ),
            "controls_unknown": sorted(
                c["control_id"] for c in controls if c["status"] == CTRL_UNKNOWN
            ),
            "controls_not_monitored": sorted(
                c["control_id"] for c in controls if c["status"] == CTRL_NOT_MONITORED
            ),
            "config_assertions_total": len(config_results),
            "config_assertions_passed": sum(1 for r in config_results if r["status"] == "pass"),
            "config_assertions_failed": sum(1 for r in config_results if r["status"] == "fail"),
        },
        "tests": tests,
        "config_assertions": config_results,
        "controls": controls,
        "frameworks": frameworks,
    }

    content_sha256 = _sha256_of(payload)
    report = dict(payload)
    report["integrity"] = {
        "content_sha256": content_sha256,
        "canonicalization": (
            "json(sort_keys, separators=(',',':'), utf-8) over report minus "
            + "/".join(VOLATILE_KEYS)
        ),
    }
    report["report_id"] = str(uuid.uuid5(_UUID_NAMESPACE, content_sha256))
    report["generated_at"] = generated_at or datetime.now(timezone.utc).isoformat(timespec="microseconds")
    # Volatile ingestion-time metadata — informational, never verdict identity.
    report["run_metadata"] = {
        "window": {
            "first_run_timestamp": run_stamps[0] if run_stamps else None,
            "last_run_timestamp": run_stamps[-1] if run_stamps else None,
        },
    }
    return report
