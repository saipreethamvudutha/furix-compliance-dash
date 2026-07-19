"""
fixtures.py
===========
Deterministic fixture batches that mirror run_full_pipeline()'s result shape
exactly (same keys the reporting layer consumes). Used by the test suite and
the demo runner — and useful as documentation of the contract between
pipeline.py and compliance_reporting.
"""

from __future__ import annotations

from typing import Any

_SCF_VERSION = "2026.2"


def _policy_finding(
    rule_id: str,
    title: str,
    cis_control: str,
    severity: str,
    triggered_field: str,
    triggered_value: str,
    uuid_suffix: str,
    nist_csf_ids: list[str] | None = None,
    hipaa_cfr: str = "164.308",
) -> dict[str, Any]:
    """Mirror of policy_engine.PolicyFinding.to_dict()."""
    return {
        "finding_uuid": f"00000000-0000-4000-8000-{uuid_suffix:>012}",
        "rule_id": rule_id,
        "title": title,
        "description": f"Fixture finding for {rule_id}",
        "verdict": "FAIL",
        "cis_control": cis_control,
        "nist_csf_ids": nist_csf_ids or ["PR.AA-01"],
        "hipaa_cfr": hipaa_cfr,
        "severity": severity,
        "triggered_field": triggered_field,
        "triggered_value": triggered_value,
        "scf_version": _SCF_VERSION,
        "timestamp": "2026-07-14T09:00:00+00:00",
    }


def _attack_trace(rows: list[tuple[str, str, str, str, str, str]]) -> dict[str, Any]:
    """Build a findings.attack_pivot block from (ctrl, ctrl_name, tid, tname, rule_id, rule_title, level) rows."""
    trace = [
        {"control_id": c, "control_name": cn, "technique_id": t, "technique_name": tn,
         "relationship": "mitigates", "rule_id": rid, "rule_title": rt, "rule_level": lvl}
        for (c, cn, t, tn, rid, rt, lvl) in rows
    ]
    return {
        "technique_ids": sorted({r["technique_id"] for r in trace}),
        "controls_from_pivot": sorted({r["control_id"] for r in trace}),
        "controls_added": [],
        "worst_level": "high",
        "trace": trace,
    }


def _result(
    log_type: str,
    severity: str,
    control_ids: list[str],
    policy_findings: list[dict[str, Any]],
    run_timestamp: str,
    failure_stage: str | None = None,
    attack_pivot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Minimal-but-faithful run_full_pipeline() result dict."""
    if failure_stage is not None:
        return {
            "findings": {},
            "investigation_query": "",
            "rag_results": [],
            "policy_findings": [],
            "policy_summary": {},
            "compliance_mapping": {"cis_controls": [], "nist_identifiers": [], "hipaa_citations": []},
            "_failure_stage": failure_stage,
            "_run_timestamp": run_timestamp,
            "_density": {},
        }
    # Deterministic per-log content hash — mirrors what the real pipeline sets
    # (pipeline.py computes sha256(raw_log)); lets fixtures exercise the
    # evidence-lineage path (raw_uri, evidence_refs) without a raw line.
    import hashlib
    log_sha256 = hashlib.sha256(f"{log_type}|{run_timestamp}".encode()).hexdigest()
    findings = {
        "log_type": log_type,
        "severity": severity,
        "log_sha256": log_sha256,
        "cis_controls_mapping": {"control_ids": control_ids},
    }
    if attack_pivot is not None:
        findings["attack_pivot"] = attack_pivot
    return {
        "findings": findings,
        "investigation_query": f"Fixture investigation query for {log_type}.",
        "rag_results": [],
        "policy_findings": policy_findings,
        "policy_summary": {
            "rules_evaluated": 15,
            "violations_found": len(policy_findings),
            "rules_fired": [pf["rule_id"] for pf in policy_findings],
        },
        "compliance_mapping": {
            "cis_controls": control_ids,
            "nist_identifiers": sorted({n for pf in policy_findings for n in pf["nist_csf_ids"]}),
            "hipaa_citations": sorted({pf["hipaa_cfr"] for pf in policy_findings if pf["hipaa_cfr"]}),
        },
        "_failure_stage": None,
        "_run_timestamp": run_timestamp,
        "_density": {"is_benign": not policy_findings},
    }


def demo_batch() -> list[dict[str, Any]]:
    """
    A 5-log batch exercising every reporting state:
      * cloudtrail — 3 violations (POL-001/009/015) → Controls 5,6,12,15 at risk
      * windows    — 2 violations (POL-006/013)     → Controls 10, 8 at risk
      * syslog     — 1 violation  (POL-004)          → Control 6 at risk
      * benign     — clean pass, mapped controls observed
      * broken     — det_analysis failure → counted, excluded from posture
    Entries use the wrapped complete_log_pipeline_run() shape.
    """
    cloudtrail = _result(
        "cloudtrail", "critical", ["Control 3", "Control 5", "Control 6", "Control 15"],
        [
            _policy_finding("POL-001", "Unauthorised Account Creation", "Control 5",
                            "high", "account_creation_detected",
                            "CreateUser backdoor_admin from 45.33.32.156", "1"),
            _policy_finding("POL-009", "Privilege Escalation from External Source",
                            "Control 6 + Control 12", "critical", "privilege_escalation_detected",
                            "AttachUserPolicy AdministratorAccess ← 45.33.32.156", "2",
                            nist_csf_ids=["PR.AA-01", "PR.IR-01"]),
            _policy_finding("POL-015", "Cloud Privileged Role Assignment",
                            "Control 6 + Control 15", "high", "cis_controls_mapping",
                            "AdministratorAccess attached to backdoor_admin", "3"),
        ],
        "2026-07-14T09:00:01+00:00",
        attack_pivot=_attack_trace([
            ("Control 5", "Account Management", "T1136.003", "Cloud Account Creation",
             "furix-0010-cloudtrail-createuser", "IAM User Created via CloudTrail", "high"),
            ("Control 6", "Access Control Management", "T1098", "Account Manipulation",
             "furix-0011-cloudtrail-admin-attach", "Administrator Policy Attached to IAM User", "critical"),
        ]),
    )
    windows = _result(
        "windows_evtx", "critical", ["Control 2", "Control 8", "Control 10"],
        [
            _policy_finding("POL-006", "Malware or C2 Activity Confirmed", "Control 10",
                            "critical", "primary_finding", "mimikatz.exe execution (EventID 4688)", "4",
                            nist_csf_ids=["DE.CM-09"]),
            _policy_finding("POL-013", "Audit Log Integrity Event", "Control 8",
                            "medium", "severity", "audit policy tampering detected", "5",
                            nist_csf_ids=["PR.PS-04"], hipaa_cfr="164.312"),
        ],
        "2026-07-14T09:00:02+00:00",
    )
    syslog = _result(
        "syslog", "medium", ["Control 6"],
        [
            _policy_finding("POL-004", "Failed Authentication Attempts", "Control 6",
                            "medium", "failed_logins", "12x failed password for root", "6"),
        ],
        "2026-07-14T09:00:03+00:00",
    )
    benign = _result(
        "benign_network", "informational", ["Control 13"], [],
        "2026-07-14T09:00:04+00:00",
    )
    broken = _result("generic", "", [], [], "2026-07-14T09:00:05+00:00",
                     failure_stage="det_analysis")

    return [
        {"log_type": "cloudtrail", "result": cloudtrail, "elapsed_sec": 2.31},
        {"log_type": "windows_evtx", "result": windows, "elapsed_sec": 1.87},
        {"log_type": "syslog", "result": syslog, "elapsed_sec": 1.42},
        {"log_type": "benign_network", "result": benign, "elapsed_sec": 0.96},
        {"log_type": "generic", "result": broken, "elapsed_sec": 0.11},
    ]


def demo_batch_remediated() -> list[dict[str, Any]]:
    """
    The "one week later, after remediation" batch: the cloud takeover and
    malware are gone, but brute-force attempts persist and a NEW audit-log
    integrity problem appeared. Diffed against demo_batch() this shows every
    transition kind: controls improving (5, 6→partially, 10, 12, 15), one
    still at risk (6 via POL-004), and a regression path when reversed.
    """
    syslog = _result(
        "syslog", "medium", ["Control 6"],
        [
            _policy_finding("POL-004", "Failed Authentication Attempts", "Control 6",
                            "medium", "failed_logins", "7x failed password for admin", "21"),
        ],
        "2026-07-21T09:00:01+00:00",
    )
    windows_clean = _result(
        "windows_evtx", "low", ["Control 8", "Control 10"], [],
        "2026-07-21T09:00:02+00:00",
    )
    cloudtrail_clean = _result(
        "cloudtrail", "low", ["Control 3", "Control 5", "Control 15"], [],
        "2026-07-21T09:00:03+00:00",
    )
    benign = _result(
        "benign_network", "informational", ["Control 13"], [],
        "2026-07-21T09:00:04+00:00",
    )
    return [
        {"log_type": "syslog", "result": syslog, "elapsed_sec": 1.38},
        {"log_type": "windows_evtx", "result": windows_clean, "elapsed_sec": 1.12},
        {"log_type": "cloudtrail", "result": cloudtrail_clean, "elapsed_sec": 1.55},
        {"log_type": "benign_network", "result": benign, "elapsed_sec": 0.91},
    ]
