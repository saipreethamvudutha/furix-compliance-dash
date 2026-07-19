"""
dashboard.py
============
Adapter: canonical Furix compliance report  →  the secureguard dashboard's
`ComplianceFramework[]` contract (src/lib/data/types.ts).

Target TypeScript shapes (exact keys):

    ComplianceFramework {
      id, name, shortName,
      totalControls, metControls, inProgressControls, gapControls,
      unknownControls, notMonitoredControls, naControls,
      coveragePct, atRiskPct, percentage (number | null),
      controls: ComplianceControl[]
    }
    ComplianceControl {
      id, reference, title, description, plainLanguage,
      status: "met" | "in_progress" | "gap" | "unknown"
            | "not_monitored" | "not_applicable",
      monitoredControls, totalMappedControls,
      systems: { name, status, detail }[],
      aiRecommendation?
    }

Status mapping (our rollup → dashboard) — honest and one-to-one (FUR-CMP-006):
    compliant      → met            (requires positive assertions; none exist yet)
    at_risk        → gap
    unknown        → unknown        (monitored, no violations observed — NOT met)
    not_monitored  → not_monitored  (never disguised as not_applicable: N/A
                                     requires an approved applicability
                                     decision, which does not exist here)

Every dashboard row (a framework requirement) is backed by the report's own
control→test→evidence chain, so `systems` and `aiRecommendation` are real,
deterministic, and traceable — never invented. Posture is a tuple (state
counts + coverage + at-risk share), never a lone percentage.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..registry import CONTROL_CATALOG

# our framework rollup status → dashboard ControlStatus
_STATUS_MAP = {
    "compliant": "met",
    "at_risk": "gap",
    "unknown": "unknown",
    "not_monitored": "not_monitored",
}

# framework_id → (dashboard id, full name, short name)
_FRAMEWORK_META = {
    "cis_v8": ("cis", "CIS Controls v8.1", "CIS v8.1"),
    "nist_csf_2_0": ("nist", "NIST Cybersecurity Framework 2.0", "NIST CSF"),
    "hipaa_security_rule": ("hipaa", "HIPAA Security Rule", "HIPAA"),
    "pci_dss_4_0": ("pci", "PCI DSS 4.0", "PCI-DSS"),
}

_MAX_SYSTEMS = 6  # cap evidence rows per requirement to keep the payload lean


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text.lower()).strip("-")


def _control_index(report: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """
    Build {control_id: {status, worst_severity, failing_tests, evidence[],
    config_pass[], config_fail[]}} by joining report.controls with the evidence
    on report.tests and the config assertions on report.config_assertions.
    """
    tests_by_id = {t["test_id"]: t for t in report.get("tests", [])}
    cfg_by_id = {r["spec_id"]: r for r in report.get("config_assertions", [])}
    index: dict[str, dict[str, Any]] = {}
    for c in report.get("controls", []):
        evidence: list[dict[str, Any]] = []
        for tid in c.get("failing_tests", []):
            t = tests_by_id.get(tid, {})
            evaluator_hash = (t.get("assertion") or {}).get("evaluator_hash", "")
            for ev in t.get("evidence", []):
                evidence.append({
                    "test_id": tid,
                    "test_title": t.get("title", tid),
                    "log_type": ev.get("log_type", "log"),
                    "log_index": ev.get("log_index"),
                    "severity": ev.get("severity", ""),
                    "detail": ev.get("triggered_value", ""),
                    # evidence lineage (FUR-CMP-007): resolvable pointer + the
                    # versioned logic that evaluated it, for reproduction.
                    "raw_uri": ev.get("raw_uri", ""),
                    "sha256": ev.get("log_sha256", ""),
                    "evaluator_hash": evaluator_hash,
                })
        config_pass = [cfg_by_id[s] for s in c.get("config_passing", []) if s in cfg_by_id]
        config_fail = [cfg_by_id[s] for s in c.get("config_failing", []) if s in cfg_by_id]
        index[c["control_id"]] = {
            "status": c["status"],
            "worst_severity": c.get("worst_severity", ""),
            "failing_tests": c.get("failing_tests", []),
            "evidence": evidence,
            "attack": c.get("attack", []),
            "config_pass": config_pass,
            "config_fail": config_fail,
        }
    return index


def _config_evidence_for(via_controls: list[str], cidx: dict[str, dict[str, Any]],
                         key: str) -> list[dict[str, str]]:
    """Positive/negative config-assertion evidence rows for a requirement's controls."""
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    passing = key == "config_pass"
    for ctrl in via_controls:
        for res in cidx.get(ctrl, {}).get(key, []):
            if res["spec_id"] in seen:
                continue
            seen.add(res["spec_id"])
            pop = res.get("population", {})
            row = {
                "name": res.get("resource_type", res["spec_id"]),
                "status": "met" if passing else "gap",
                "detail": (f"{res['spec_id']} — {res['title']} "
                           f"({pop.get('passing', 0)}/{pop.get('in_scope', 0)} resources)"),
                "evidenceUri": f"furix-assertion://{res['spec_id']}",
                "reproduce": (f"furix verify --assertion {res['spec_id']} "
                              f"--evaluator {res.get('evaluator_hash','')[:12]} "
                              f"--population {pop.get('observed',0)}/{pop.get('expected',0)}"),
            }
            out.append(row)
            if len(out) >= _MAX_SYSTEMS:
                return out
    return out


def _attack_for(via_controls: list[str], cidx: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    """Distinct ATT&CK technique/rule provenance across a requirement's controls."""
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for ctrl in via_controls:
        for a in cidx.get(ctrl, {}).get("attack", []):
            key = (a.get("technique_id", ""), a.get("rule_id", ""))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "techniqueId": a.get("technique_id", ""),
                "techniqueName": a.get("technique_name", ""),
                "ruleId": a.get("rule_id", ""),
                "ruleTitle": a.get("rule_title", ""),
                "level": a.get("level", ""),
            })
    return out


def _systems_for(via_controls: list[str], cidx: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    """Turn the evidence behind a requirement's contributing controls into `systems` rows."""
    systems: list[dict[str, str]] = []
    for ctrl in via_controls:
        info = cidx.get(ctrl, {})
        for ev in info.get("evidence", []):
            label = ev["log_type"]
            if ev.get("log_index") is not None:
                label = f"{ev['log_type']} #{ev['log_index']}"
            row = {
                "name": label,
                "status": "gap",
                "detail": f"{ev['test_id']} — {ev['detail']}"[:180] or ev["test_title"],
            }
            if ev.get("raw_uri"):
                row["evidenceUri"] = ev["raw_uri"]
                # a copyable command an auditor runs to reproduce this verdict
                # from the immutable evidence, without trusting the dashboard.
                row["reproduce"] = (
                    f"furix verify --evidence {ev['sha256'][:16]} "
                    f"--assertion {ev['test_id']} --evaluator {ev['evaluator_hash'][:12]}"
                )
            systems.append(row)
            if len(systems) >= _MAX_SYSTEMS:
                return systems
    return systems


def _recommendation(via_controls: list[str], cidx: dict[str, dict[str, Any]]) -> str | None:
    """Deterministic, provenance-backed remediation text for an at-risk requirement."""
    fired: list[str] = []
    for ctrl in via_controls:
        for tid in cidx.get(ctrl, {}).get("failing_tests", []):
            if tid not in fired:
                fired.append(tid)
    if not fired:
        return None
    controls_txt = ", ".join(via_controls)
    return (
        f"At risk via {controls_txt}: policy check(s) {', '.join(fired)} fired. "
        f"Investigate the flagged events and remediate the affected systems, "
        f"then re-ingest to confirm the control returns to compliant."
    )


def _requirement_title(framework_id: str, requirement_id: str, short: str) -> str:
    if framework_id == "cis_v8":
        return CONTROL_CATALOG.get(requirement_id, requirement_id)
    return f"{short} {requirement_id}"


def _plain_language(status: str, via_controls: list[str], violations: int) -> str:
    if status == "gap":
        return f"At risk — {violations} violation(s) across {', '.join(via_controls) or 'mapped controls'}."
    if status == "met":
        return "All mapped assertions positively passed for the expected population."
    if status == "unknown":
        return (
            "Monitored — no violations observed in this batch. Detection "
            "evidence alone cannot prove the control operates."
        )
    return "Not monitored — no detection rule covers this requirement yet."


def _finding_chip(via: list[str], findings: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """The remediation/exception status for an at-risk requirement, if any."""
    if not findings:
        return None
    for ctrl in via:
        f = findings.get(ctrl)
        if f:
            return {
                "state": f.get("state"),
                "owner": f.get("owner"),
                "dueDate": f.get("due_date"),
                "expired": bool(f.get("expired")),
                "exception": f.get("exception"),
                "findingId": f.get("finding_id"),
            }
    return None


def _framework_to_dashboard(fw: Mapping[str, Any], report: Mapping[str, Any],
                            cidx: dict[str, dict[str, Any]],
                            findings: Mapping[str, Any] | None = None) -> dict[str, Any]:
    fid = fw["framework_id"]
    dash_id, name, short = _FRAMEWORK_META.get(fid, (fid, fw.get("name", fid), fid))

    controls: list[dict[str, Any]] = []
    counts = {"met": 0, "in_progress": 0, "gap": 0, "unknown": 0,
              "not_monitored": 0, "not_applicable": 0}
    for req in fw.get("requirements", []):
        status = _STATUS_MAP.get(req["status"], "unknown")
        counts[status] += 1
        via = req.get("via_controls", [])
        violations = sum(cidx.get(c, {}).get("evidence", []).__len__() for c in via)
        row = {
            "id": f"{dash_id}-{_slug(req['requirement_id'])}",
            "reference": req["requirement_id"],
            "title": _requirement_title(fid, req["requirement_id"], short),
            "description": f"{name} requirement {req['requirement_id']}, mapped via {', '.join(via) or 'no control'}.",
            "plainLanguage": _plain_language(status, via, violations),
            "status": status,
            "monitoredControls": req.get("monitored_controls", 0),
            "totalMappedControls": req.get("total_controls", len(via)),
            "systems": (
                # gap → detection + config-failure evidence;
                # met → the positive config assertions that verified it.
                (_systems_for(via, cidx) + _config_evidence_for(via, cidx, "config_fail"))[:_MAX_SYSTEMS]
                if status == "gap"
                else _config_evidence_for(via, cidx, "config_pass") if status == "met"
                else []
            ),
        }
        rec = _recommendation(via, cidx) if status == "gap" else None
        if rec:
            row["aiRecommendation"] = rec
        attack = _attack_for(via, cidx)
        if attack:
            row["attack"] = attack
        if status == "gap":
            chip = _finding_chip(via, findings)
            if chip:
                row["finding"] = chip
        controls.append(row)

    compliance_pct = fw.get("compliance_pct")
    return {
        "id": dash_id,
        "name": name,
        "shortName": short,
        "totalControls": len(controls),
        "metControls": counts["met"],
        "inProgressControls": counts["in_progress"],
        "gapControls": counts["gap"],
        "unknownControls": counts["unknown"],
        "notMonitoredControls": counts["not_monitored"],
        "naControls": counts["not_applicable"],
        "coveragePct": round(fw.get("coverage_pct") or 0.0),
        "atRiskPct": (
            round(fw["at_risk_pct"]) if isinstance(fw.get("at_risk_pct"), (int, float)) else None
        ),
        # A compliance percentage requires positive assertions — null until
        # then, NEVER 0 (reads as "0% compliant") or a silent 100.
        "percentage": (
            round(compliance_pct) if isinstance(compliance_pct, (int, float)) else None
        ),
        "controls": controls,
    }


def report_to_frameworks(report: Mapping[str, Any],
                         findings: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    """
    Map a canonical report to the dashboard's `ComplianceFramework[]`. When a
    `findings` map (control_id → open finding) is supplied, at-risk rows are
    annotated with their remediation/exception status (Wave 5).
    """
    cidx = _control_index(report)
    return [_framework_to_dashboard(fw, report, cidx, findings) for fw in report.get("frameworks", [])]


def report_to_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    """Top-level KPIs for the dashboard header / home tiles."""
    frameworks = report_to_frameworks(report)
    b, s = report.get("batch", {}), report.get("summary", {})
    return {
        "report_id": report.get("report_id"),
        "generated_at": report.get("generated_at"),
        "total_logs": b.get("total_logs", 0),
        "successful_logs": b.get("successful_logs", 0),
        "failed_logs": b.get("failed_logs", 0),
        "total_violations": s.get("total_violations", 0),
        "population": report.get("population", {}),
        "frameworks": [
            {"id": f["id"], "name": f["name"], "shortName": f["shortName"],
             "percentage": f["percentage"], "coveragePct": f["coveragePct"],
             "atRiskPct": f["atRiskPct"], "gapControls": f["gapControls"],
             "unknownControls": f["unknownControls"],
             "notMonitoredControls": f["notMonitoredControls"],
             "totalControls": f["totalControls"]}
            for f in frameworks
        ],
        "versions": report.get("versions", {}),
        "integrity_sha256": report.get("integrity", {}).get("content_sha256", ""),
    }
