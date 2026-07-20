"""
test_posture_run.py
===================
The unified posture-run pipeline (Wave-H): one run chains connector collection →
raw snapshot → immutable evidence → reconciliation → assertions → verified report
→ findings, recorded as a single PostureRun with linked IDs.

    python3 -m api.test_posture_run
"""

from __future__ import annotations

import tempfile

from compliance_reporting.evidence import EvidenceStore
from compliance_reporting.history import ReportStore
from compliance_reporting.posture_run import PostureRunStore
from compliance_reporting.registry import FrameworkRegistry

from . import service

_REG = FrameworkRegistry.from_snapshot()
_NOW = "2026-07-19T12:00:00+00:00"


def _store():
    return ReportStore(tempfile.mkdtemp(prefix="furix_posture_"))


def _collect():
    # deterministic demo connector collection (snapshot + signed manifest)
    return service.collect_snapshot("acme", "demo-aws", {}, "sign-secret")


def test_posture_run_links_every_stage():
    store = _store()
    out = _collect()
    run = service.run_posture(store, tenant="acme", snapshot=out["snapshot"],
                              manifest=out["manifest"], connector_id="demo-aws",
                              registry=_REG, occurred_at=_NOW)

    # every stage is linked
    assert run["run_id"].startswith("run-")
    assert run["connector_id"] == "demo-aws"
    assert run["collection"]["signed"] is True
    assert run["collection"]["reconciled"] is True
    assert run["collection"]["reconciliation_basis"] == "independent-ou-tree"
    assert run["snapshot"]["resource_count"] >= 1
    assert len(run["evidence"]["snapshot_sha256"]) == 64
    assert run["evidence"]["raw_uri"].startswith("furix-evidence://")
    assert run["evaluation"]["assertion_total"] >= 1
    assert run["report_id"] and run["verified"] is True


def test_snapshot_evidence_is_immutably_retained():
    store = _store()
    out = _collect()
    run = service.run_posture(store, tenant="acme", snapshot=out["snapshot"],
                              manifest=out["manifest"], registry=_REG, occurred_at=_NOW)
    # the linked snapshot evidence sha resolves to a verifiable object
    ev = EvidenceStore(store.root)
    assert ev.verify_object(run["evidence"]["snapshot_sha256"])


def test_report_and_findings_are_linked_and_loadable():
    store = _store()
    out = _collect()
    run = service.run_posture(store, tenant="acme", snapshot=out["snapshot"],
                              manifest=out["manifest"], registry=_REG, occurred_at=_NOW)
    # the linked report id loads and matches
    report = store.load(run["report_id"])
    assert report["report_id"] == run["report_id"]
    # every affected control has a finding, and each finding is retrievable
    from compliance_reporting.exceptions import FindingStore
    fs = FindingStore(store.root)
    assert len(run["findings"]) == len(run["affected_controls"])
    for fid in run["findings"]:
        assert fs.get(fid) is not None


def test_posture_run_is_persisted_and_listable():
    store = _store()
    out = _collect()
    run = service.run_posture(store, tenant="acme", snapshot=out["snapshot"],
                              manifest=out["manifest"], registry=_REG, occurred_at=_NOW)
    prs = PostureRunStore(store.root)
    assert prs.get("acme", run["run_id"]) is not None
    assert prs.latest("acme")["run_id"] == run["run_id"]
    # tenant isolation
    assert prs.list("globex") == []
    assert service.list_posture_runs(store, "acme")[0]["run_id"] == run["run_id"]


def test_posture_run_is_deterministic_for_same_inputs():
    store = _store()
    out = _collect()
    # pin collected_at so the two runs derive the same report + run id
    out["snapshot"]["collected_at"] = _NOW
    r1 = service.run_posture(store, tenant="acme", snapshot=out["snapshot"],
                             manifest=out["manifest"], registry=_REG, occurred_at=_NOW)
    r2 = service.run_posture(store, tenant="acme", snapshot=out["snapshot"],
                             manifest=out["manifest"], registry=_REG, occurred_at=_NOW)
    assert r1["run_id"] == r2["run_id"] and r1["report_id"] == r2["report_id"]


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
    print(f"\n{len(tests) - failed}/{len(tests)} posture-run tests passed")
    sys.exit(1 if failed else 0)
