"""
test_compliance_workspace.py
===========================
The compliance workspace (Wave-I / Epic 4): control governance profile joined
with the computed verdict, framework mappings, findings, exceptions, freshness,
and evidence lineage.

    python3 -m api.test_compliance_workspace
"""

from __future__ import annotations

import tempfile

from compliance_reporting.control_profile import ControlProfileError, ControlProfileStore
from compliance_reporting.history import ReportStore
from compliance_reporting.registry import FrameworkRegistry

from . import service

_REG = FrameworkRegistry.from_snapshot()
_NOW = "2026-07-19T12:00:00+00:00"


def _seeded_store():
    """A store with a real posture-run report + findings (demo-aws collection)."""
    store = ReportStore(tempfile.mkdtemp(prefix="furix_ws_"))
    out = service.collect_snapshot("acme", "demo-aws", {}, "s")
    service.run_posture(store, tenant="acme", snapshot=out["snapshot"], manifest=out["manifest"],
                        connector_id="demo-aws", registry=_REG, occurred_at=_NOW, data_mode="demo")
    return store


# ── profile store ─────────────────────────────────────────────────────────────
def test_profile_defaults_and_update():
    store = ReportStore(tempfile.mkdtemp(prefix="furix_cp_"))
    cps = ControlProfileStore(store.root)
    p = cps.get("acme", "Control 6")
    assert p["applicability"] == "applicable" and p["test_cadence_days"] == 90
    assert p["configured"] is False
    updated = cps.update("acme", "Control 6",
                         {"owner": "grc@acme", "test_cadence_days": 30,
                          "implementation_narrative": "MFA enforced org-wide"},
                         updated_by="admin", updated_at=_NOW)
    assert updated["owner"] == "grc@acme" and updated["test_cadence_days"] == 30
    assert updated["updated_by"] == "admin" and updated["configured"] is True


def test_profile_validation():
    cps = ControlProfileStore(ReportStore(tempfile.mkdtemp()).root)
    for bad in ({"applicability": "maybe"}, {"verification_method": "vibes"},
                {"test_cadence_days": 0}, {"test_cadence_days": "soon"}):
        try:
            cps.update("acme", "Control 1", bad, updated_by="x", updated_at=_NOW)
            raise AssertionError(f"accepted invalid {bad}")
        except ControlProfileError:
            pass


# ── workspace list ────────────────────────────────────────────────────────────
def test_list_workspace_joins_verdict_profile_and_frameworks():
    store = _seeded_store()
    ControlProfileStore(store.root).update("acme", "Control 6", {"owner": "grc@acme"},
                                           updated_by="admin", updated_at=_NOW)
    rows = service.list_control_workspace(store, "acme", registry=_REG, now=_NOW)
    by_id = {r["control_id"]: r for r in rows}
    assert len(rows) >= 18
    c6 = by_id["Control 6"]
    assert c6["owner"] == "grc@acme"
    assert c6["status"] in ("compliant", "at_risk", "unknown", "not_monitored")
    assert c6["framework_counts"]["nist_csf"] >= 1
    assert c6["evidence_freshness"] in ("fresh", "stale", "unknown")


def test_workspace_available_before_any_assessment():
    store = ReportStore(tempfile.mkdtemp(prefix="furix_ws0_"))
    rows = service.list_control_workspace(store, "acme", registry=_REG, now=_NOW)
    assert len(rows) >= 18  # from the crosswalk universe
    assert all(r["status"] == "unknown" and r["evidence_freshness"] == "unknown" for r in rows)


# ── workspace detail ──────────────────────────────────────────────────────────
def test_detail_has_mappings_findings_exceptions_and_lineage():
    store = _seeded_store()
    d = service.get_control_workspace(store, "acme", "Control 6", registry=_REG, now=_NOW)
    assert d["framework_mappings"]["nist_csf"] and d["framework_mappings"]["pci_dss"]
    assert "linked_findings" in d and "exceptions" in d
    lin = d["evidence_lineage"]
    assert lin["report_id"] and lin["posture_run"]["data_mode"] == "demo"
    assert len(lin["posture_run"]["snapshot_sha256"]) == 64


def test_detail_reflects_freshness_against_cadence():
    store = _seeded_store()  # assessed at _NOW (2026-07-19)
    ControlProfileStore(store.root).update("acme", "Control 6", {"test_cadence_days": 10},
                                           updated_by="admin", updated_at=_NOW)
    # 60 days later, a 10-day cadence is stale
    d = service.get_control_workspace(store, "acme", "Control 6", registry=_REG,
                                      now="2026-09-19T12:00:00+00:00")
    assert d["evidence_freshness"] == "stale"


def test_per_assertion_freshness_and_exact_producing_run():
    """Wave-J: freshness comes from the actual backing evidence, and the control
    links to the EXACT posture run that produced its verdict."""
    store = _seeded_store()
    # Control 5 is backed by the demo-aws CFG-AWS-KEY-ROTATION assertion
    d = service.get_control_workspace(store, "acme", "Control 5", registry=_REG, now=_NOW)
    # per-assertion freshness is surfaced with each assertion's evidence
    assert d["assertion_freshness"], "expected backing assertions with freshness"
    a0 = d["assertion_freshness"][0]
    assert "freshness" in a0 and a0["evidence"]
    assert a0["evidence"][0]["observed_at"]  # per-evidence observation time
    assert d["evidence_freshness"] in ("fresh", "stale", "unknown")
    assert d.get("oldest_evidence_at")  # derived from actual evidence, not report time

    # the linked posture run is the one that produced THIS report (exact provenance)
    from compliance_reporting.posture_run import PostureRunStore
    pr = PostureRunStore(store.root).by_report("acme", d["evidence_lineage"]["report_id"])
    assert pr is not None
    assert d["evidence_lineage"]["posture_run"]["run_id"] == pr["run_id"]


def test_stale_evidence_marks_control_stale():
    """A control whose backing assertion evidence is older than its cadence is
    reported stale even if the report itself is recent."""
    store = _seeded_store()
    # Control 5's AWS evidence is observed at collection time; a tiny cadence far
    # in the future makes the actual backing evidence stale (not just the report).
    from compliance_reporting.control_profile import ControlProfileStore
    ControlProfileStore(store.root).update("acme", "Control 5", {"test_cadence_days": 1},
                                           updated_by="admin", updated_at=_NOW)
    d = service.get_control_workspace(store, "acme", "Control 5", registry=_REG,
                                      now="2026-12-01T00:00:00+00:00")
    assert d["evidence_freshness"] == "stale"
    assert d["oldest_evidence_at"] is not None  # derived from the evidence, not report time


def test_unknown_control_raises():
    store = _seeded_store()
    try:
        service.get_control_workspace(store, "acme", "Control 999", registry=_REG, now=_NOW)
        raise AssertionError("expected FileNotFoundError")
    except FileNotFoundError:
        pass


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
    print(f"\n{len(tests) - failed}/{len(tests)} compliance-workspace tests passed")
    sys.exit(1 if failed else 0)
