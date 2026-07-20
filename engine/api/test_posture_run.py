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
    assert run["data_mode"] in ("demo", "live")


def test_posture_run_preserves_approved_manual_attestations():
    """Wave-J P0: a connector/posture run must NOT regress verified people/process
    controls (from approved manual attestations) back to manual_pending."""
    from compliance_reporting.fixtures import demo_attestation_keyring, demo_attestations
    store = _store()
    out = _collect()
    atts = demo_attestations(tenant="acme")     # signed, "approved" set for the tenant
    ring = demo_attestation_keyring()

    # WITH the approved attestations threaded through → manual controls compliant
    run = service.run_posture(store, tenant="acme", snapshot=out["snapshot"],
                              manifest=out["manifest"], registry=_REG, occurred_at=_NOW,
                              attestations=atts, attestation_keyring=ring)
    by_id = {c["control_id"]: c for c in store.load(run["report_id"])["controls"]}
    for cid in ("Control 9", "Control 14", "Control 17", "Control 18"):
        assert by_id[cid]["status"] == "compliant", (cid, by_id[cid]["status"])

    # WITHOUT them (the old bug) → the same controls regress to manual_pending
    store2 = _store()
    run2 = service.run_posture(store2, tenant="acme", snapshot=out["snapshot"],
                               manifest=out["manifest"], registry=_REG, occurred_at=_NOW)
    by_id2 = {c["control_id"]: c for c in store2.load(run2["report_id"])["controls"]}
    assert by_id2["Control 9"]["status"] != "compliant"


def test_demo_data_mode_isolates_synthetic_runs():
    store = _store()
    out = _collect()
    run = service.run_posture(store, tenant="acme", snapshot=out["snapshot"],
                              manifest=out["manifest"], registry=_REG, occurred_at=_NOW,
                              data_mode="demo")
    assert run["data_mode"] == "demo"
    assert service.is_demo_kind("demo-aws") and not service.is_demo_kind("aws-org-iam")


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
