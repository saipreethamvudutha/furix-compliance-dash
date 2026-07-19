"""
test_adapter.py
===============
Validates the dashboard adapter against the secureguard TypeScript contract:
exact keys, the ControlStatus enum, reconciling counts, and that every at-risk
row's evidence traces back to real report findings (nothing invented).

    python3 -m compliance_reporting.adapters.test_adapter
"""

from __future__ import annotations

from ..fixtures import demo_batch
from ..registry import CONTROL_CATALOG, FrameworkRegistry
from ..report_builder import build_report
from .dashboard import report_to_frameworks, report_to_summary

_REGISTRY = FrameworkRegistry.from_snapshot()
_GEN_AT = "2026-07-16T12:00:00+00:00"

_FRAMEWORK_KEYS = {
    "id", "name", "shortName", "totalControls", "metControls",
    "inProgressControls", "gapControls", "unknownControls",
    "notMonitoredControls", "naControls", "coveragePct", "atRiskPct",
    "percentage", "controls",
}
_CONTROL_KEYS = {"id", "reference", "title", "description", "plainLanguage",
                 "status", "monitoredControls", "totalMappedControls", "systems"}
_CONTROL_STATUS = {"met", "in_progress", "gap", "unknown", "not_monitored", "not_applicable"}


def _report():
    return build_report(demo_batch(), registry=_REGISTRY, generated_at=_GEN_AT)


def test_frameworks_have_exact_shape():
    fws = report_to_frameworks(_report())
    assert len(fws) == 4
    ids = {f["id"] for f in fws}
    assert ids == {"cis", "nist", "hipaa", "pci"}
    for f in fws:
        assert _FRAMEWORK_KEYS <= set(f), f"missing keys: {_FRAMEWORK_KEYS - set(f)}"
        # no positive assertions exist → percentage must be None (never 0/100)
        assert f["percentage"] is None
        assert isinstance(f["coveragePct"], int)
        assert f["atRiskPct"] is None or isinstance(f["atRiskPct"], int)


def test_controls_have_exact_shape_and_valid_status():
    for f in report_to_frameworks(_report()):
        for c in f["controls"]:
            assert _CONTROL_KEYS <= set(c), f"missing keys: {_CONTROL_KEYS - set(c)}"
            assert c["status"] in _CONTROL_STATUS, c["status"]
            for sysrow in c["systems"]:
                assert {"name", "status", "detail"} <= set(sysrow)
                assert sysrow["status"] in _CONTROL_STATUS


def test_counts_reconcile():
    for f in report_to_frameworks(_report()):
        assert (
            f["totalControls"]
            == f["metControls"] + f["inProgressControls"] + f["gapControls"]
            + f["unknownControls"] + f["notMonitoredControls"] + f["naControls"]
            == len(f["controls"])
        )


def test_status_mapping_matches_report():
    report = _report()
    fw_by_id = {f["framework_id"]: f for f in report["frameworks"]}
    dash_by_id = {f["id"]: f for f in report_to_frameworks(report)}
    # CIS: at_risk→gap, unknown→unknown, not_monitored→not_monitored — honest,
    # one-to-one; not_monitored is NEVER disguised as not_applicable
    cis_report = fw_by_id["cis_v8"]
    cis_dash = dash_by_id["cis"]
    assert cis_dash["gapControls"] == cis_report["requirements_at_risk"]
    assert cis_dash["metControls"] == cis_report["requirements_compliant"] == 0
    assert cis_dash["unknownControls"] == cis_report["requirements_unknown"]
    assert cis_dash["notMonitoredControls"] == cis_report["requirements_not_monitored"]
    assert cis_dash["naControls"] == 0  # no approved applicability decisions exist
    assert cis_dash["percentage"] is None
    assert cis_dash["coveragePct"] == round(cis_report["coverage_pct"])


def test_cis_controls_use_real_titles():
    cis = next(f for f in report_to_frameworks(_report()) if f["id"] == "cis")
    by_ref = {c["reference"]: c for c in cis["controls"]}
    assert by_ref["Control 6"]["title"] == CONTROL_CATALOG["Control 6"]  # "Access Control Management"
    assert by_ref["Control 6"]["status"] == "gap"                        # POL-009/015 fired


def test_gap_rows_carry_traceable_evidence_and_recommendation():
    fws = report_to_frameworks(_report())
    saw_gap_with_evidence = False
    for f in fws:
        for c in f["controls"]:
            if c["status"] == "gap" and c["systems"]:
                saw_gap_with_evidence = True
                assert "aiRecommendation" in c and c["aiRecommendation"]
                # detail references a real POL rule id from the batch
                assert any("POL-" in s["detail"] for s in c["systems"])
    assert saw_gap_with_evidence, "expected at least one at-risk row backed by evidence"


def test_gap_rows_carry_evidence_lineage_and_reproduction():
    """FUR-CMP-007: at-risk rows expose a resolvable evidence URI and a
    copyable reproduction command an auditor can run."""
    fws = report_to_frameworks(_report())
    saw_lineage = False
    for f in fws:
        for c in f["controls"]:
            for s in c["systems"]:
                if s.get("evidenceUri"):
                    saw_lineage = True
                    assert s["evidenceUri"].startswith("furix-evidence://")
                    assert s["reproduce"].startswith("furix verify --evidence ")
    assert saw_lineage, "expected evidence lineage on at least one at-risk row"


def test_summary_carries_population_manifest():
    s = report_to_summary(_report())
    pop = s["population"]
    assert pop["expected"] == 5 and pop["observed"] == 4 and pop["errored"] == 1
    assert pop["reconciled"] is True


def test_met_controls_carry_positive_config_evidence():
    """Wave 2: with config posture, a met control shows the passing positive
    assertion(s) that verified it — and the framework percentage is earned."""
    from ..fixtures import demo_config_snapshot
    report = build_report(demo_batch(), registry=_REGISTRY, generated_at=_GEN_AT,
                          config_snapshot=demo_config_snapshot())
    cis = next(f for f in report_to_frameworks(report) if f["id"] == "cis")
    assert cis["metControls"] >= 2                     # Control 3 + 16
    assert isinstance(cis["percentage"], int) and cis["percentage"] > 0  # earned, not null
    by_ref = {c["reference"]: c for c in cis["controls"]}
    c16 = by_ref["Control 16"]
    assert c16["status"] == "met" and c16["systems"], "met control should carry positive evidence"
    assert all(s["status"] == "met" for s in c16["systems"])
    assert any("CFG-GH-" in s["detail"] for s in c16["systems"])
    assert c16["systems"][0]["evidenceUri"].startswith("furix-assertion://")


def test_met_and_na_rows_have_no_systems():
    for f in report_to_frameworks(_report()):
        for c in f["controls"]:
            if c["status"] in ("met", "not_applicable"):
                assert c["systems"] == []
                assert "aiRecommendation" not in c


def test_attack_provenance_surfaced_on_controls():
    fws = report_to_frameworks(_report())
    cis = next(f for f in fws if f["id"] == "cis")
    by_ref = {c["reference"]: c for c in cis["controls"]}
    # Control 5 & 6 carry the ATT&CK technique/rule that detected them
    c6 = by_ref["Control 6"]
    assert "attack" in c6 and c6["attack"], "expected ATT&CK provenance on Control 6"
    a = c6["attack"][0]
    assert {"techniqueId", "techniqueName", "ruleId", "ruleTitle", "level"} <= set(a)
    assert any(x["techniqueId"] == "T1098" for x in c6["attack"])
    # it also flows to the frameworks that map through those controls (NIST/PCI)
    nist = next(f for f in fws if f["id"] == "nist")
    assert any(c.get("attack") for c in nist["controls"]), "ATT&CK should reach NIST reqs via controls"


def test_controls_without_attack_omit_the_field():
    fws = report_to_frameworks(_report())
    cis = next(f for f in fws if f["id"] == "cis")
    by_ref = {c["reference"]: c for c in cis["controls"]}
    assert "attack" not in by_ref["Control 1"]  # not monitored, no detection


def test_summary_shape():
    s = report_to_summary(_report())
    for k in ("report_id", "total_logs", "total_violations", "frameworks", "integrity_sha256"):
        assert k in s
    assert len(s["frameworks"]) == 4
    assert s["total_violations"] == 6  # demo batch


def test_json_serialisable():
    import json
    json.loads(json.dumps(report_to_frameworks(_report())))
    json.loads(json.dumps(report_to_summary(_report())))


if __name__ == "__main__":
    import sys, traceback
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} adapter tests passed")
    sys.exit(1 if failed else 0)
