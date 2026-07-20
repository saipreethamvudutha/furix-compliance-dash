"""
test_oscal.py
=============
OSCAL 1.2.1 Assessment Results + POA&M emission and validation (Wave 5).

    python3 -m compliance_reporting.test_oscal
"""

from __future__ import annotations

import json

from .fixtures import demo_batch, demo_config_snapshot
from .oscal import build_assessment_results, build_poam, validate_oscal
from .registry import FrameworkRegistry
from .report_builder import build_report
from .versions import OSCAL_VERSION

_REG = FrameworkRegistry.from_snapshot()
_GEN = "2026-07-19T12:00:00+00:00"


def _report():
    return build_report(demo_batch(), registry=_REG, generated_at=_GEN,
                        config_snapshot=demo_config_snapshot())


def test_assessment_results_valid_and_versioned():
    ar = build_assessment_results(_report())
    assert ar["assessment-results"]["metadata"]["oscal-version"] == OSCAL_VERSION == "1.2.1"
    assert validate_oscal(ar) == [], validate_oscal(ar)


def test_assessment_results_have_a_finding_per_at_risk_control():
    report = _report()
    ar = build_assessment_results(report)
    at_risk = {c["control_id"] for c in report["controls"] if c["status"] == "at_risk"}
    titles = " ".join(f["title"] for f in ar["assessment-results"]["results"][0]["findings"])
    for cid in at_risk:
        assert cid in titles


def test_poam_carries_owner_due_and_exception():
    report = _report()
    findings = [
        {"finding_id": "f1", "control_id": "Control 5", "framework_id": "cis_v8",
         "severity": "high", "state": "risk_accepted", "owner": "secops",
         "due_date": "2026-08-19", "last_reason": "brute force",
         "exception": {"approver": "ciso", "rationale": "legacy",
                       "compensating_control": "isolation", "expiry": "2026-12-01T00:00:00+00:00"}},
        {"finding_id": "f2", "control_id": "Control 10", "framework_id": "cis_v8",
         "severity": "critical", "state": "open", "owner": "secops", "last_reason": "malware"},
    ]
    poam = build_poam(report, findings)
    assert validate_oscal(poam) == [], validate_oscal(poam)
    items = poam["plan-of-action-and-milestones"]["poam-items"]
    assert len(items) == 2
    props = {p["name"]: p["value"] for p in items[0]["props"]}
    assert props["owner"] == "secops" and props["risk-acceptance"] == "true"
    assert props["approver"] == "ciso" and props["expiry"].startswith("2026-12")


def test_closed_findings_excluded_from_poam():
    report = _report()
    findings = [{"finding_id": "f", "control_id": "Control 5", "severity": "low",
                 "state": "closed", "owner": "x"}]
    poam = build_poam(report, findings)
    assert poam["plan-of-action-and-milestones"]["poam-items"] == []


def test_validator_catches_bad_version_and_dangling_ref():
    ar = build_assessment_results(_report())
    bad = json.loads(json.dumps(ar))
    bad["assessment-results"]["metadata"]["oscal-version"] = "1.1.2"
    assert any("oscal-version" in e for e in validate_oscal(bad))

    bad2 = json.loads(json.dumps(ar))
    # point a related-observation at a uuid that doesn't exist
    bad2["assessment-results"]["results"][0]["findings"][0]["related-observations"][0][
        "observation-uuid"] = "00000000-0000-4000-8000-000000000000"
    assert any("references undefined uuid" in e for e in validate_oscal(bad2))


def test_validator_rejects_non_oscal_doc():
    assert validate_oscal({"not-oscal": {}})


def test_oscal_is_deterministic_and_json_serialisable():
    a = build_assessment_results(_report())
    b = build_assessment_results(_report())
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_bundled_schema_validates_real_documents():
    """The bundled OSCAL 1.2.1 schema validates a real AR and POA&M."""
    from .oscal import build_poam, validate_oscal_schema
    ar = validate_oscal_schema(build_assessment_results(_report()))
    if not ar["ran"]:
        print("  (skipped: jsonschema not installed)")
        return
    assert ar["ok"] and ar["errors"] == [], ar
    poam = validate_oscal_schema(build_poam(_report(), []))
    assert poam["ok"], poam


def test_schema_validation_catches_bad_document():
    """A doc that violates the schema (bad oscal-version) fails schema validation."""
    from .oscal import validate_oscal_schema
    ar = build_assessment_results(_report())
    if not validate_oscal_schema(ar)["ran"]:
        return  # jsonschema absent
    ar["assessment-results"]["metadata"]["oscal-version"] = "9.9.9"
    res = validate_oscal_schema(ar)
    assert res["ok"] is False and res["errors"]


def test_imports_are_not_dangling_internal_refs():
    ar = build_assessment_results(_report())["assessment-results"]
    # import-ap is an external href with remarks, not a dangling internal #uuid
    assert ar["import-ap"]["href"].startswith("https://")
    assert "remarks" in ar["import-ap"]


if __name__ == "__main__":
    import sys
    import traceback

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
    print(f"\n{len(tests) - failed}/{len(tests)} oscal tests passed")
    sys.exit(1 if failed else 0)
