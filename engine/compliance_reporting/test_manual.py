"""
test_manual.py
==============
Manual / operational evidence assertions for the people/process controls
(Wave-E, P2): Controls 9, 14, 15, 17, 18.

    python3 -m compliance_reporting.test_manual
"""

from __future__ import annotations

from .fixtures import demo_attestations, demo_batch, demo_config_snapshot
from .manual_evidence import (
    MANUAL_ASSERTION_CATALOG,
    MANUAL_CONTROLS,
    evaluate_manual,
)
from .registry import FrameworkRegistry
from .report_builder import build_report
from .verifier import verify_report

_REG = FrameworkRegistry.from_snapshot()
_GEN = "2026-07-19T12:00:00+00:00"


def test_catalog_covers_the_five_missing_controls():
    assert MANUAL_CONTROLS == {"Control 9", "Control 14", "Control 15", "Control 17", "Control 18"}
    assert len(MANUAL_ASSERTION_CATALOG) == 5


def test_no_attestation_is_manual_pending_not_pass():
    results = {r["spec_id"]: r for r in evaluate_manual([], as_of=_GEN)}
    for r in results.values():
        assert r["status"] == "manual_pending" and r["status_reason"] == "no_attestation"


def test_current_attestation_passes():
    results = {r["spec_id"]: r for r in evaluate_manual(demo_attestations(), as_of=_GEN)}
    assert all(r["status"] == "pass" for r in results.values())
    ev = results["MAN-PENTEST"]["evidence"][0]
    assert ev["attester"] == "ciso@acme" and ev["raw_uri"].startswith("furix-attestation://")


def test_stale_attestation_is_not_pass():
    # attested 2 years before as_of, cadence 365d → stale
    old = [{"spec_id": "MAN-PENTEST", "attester": "x", "statement": "s",
            "evidence_ref": "e", "attested_at": "2024-01-01T00:00:00+00:00"}]
    r = {x["spec_id"]: x for x in evaluate_manual(old, as_of=_GEN)}["MAN-PENTEST"]
    assert r["status"] == "stale"


def test_manual_pass_makes_control_compliant_in_report():
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN,
                     config_snapshot=demo_config_snapshot(), attestations=demo_attestations())
    by_id = {c["control_id"]: c for c in r["controls"]}
    # people/process controls with a current attestation go compliant …
    for cid in ("Control 9", "Control 14", "Control 17", "Control 18"):
        assert by_id[cid]["status"] == "compliant", (cid, by_id[cid]["status"])
    # … EXCEPT Control 15, which has a real detection finding (POL-015): a clean
    # attestation can never override an observed violation.
    assert by_id["Control 15"]["status"] == "at_risk"
    assert verify_report(r, demo_batch()).ok


def test_missing_attestations_keep_controls_pending_never_compliant():
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN,
                     config_snapshot=demo_config_snapshot(), attestations=[])
    by_id = {c["control_id"]: c for c in r["controls"]}
    for cid in ("Control 9", "Control 14", "Control 15", "Control 17", "Control 18"):
        assert by_id[cid]["status"] != "compliant"
    assert verify_report(r, demo_batch()).ok


def test_verifier_rejects_forged_manual_pass():
    import copy
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN, attestations=[])
    bad = copy.deepcopy(r)
    for res in bad["config_assertions"]:
        if res["spec_id"].startswith("MAN-"):
            res["status"] = "pass"   # forge a pass with no attestation
            break
    out = verify_report(bad, demo_batch())
    assert not out.ok
    assert any(c in ("MAN-PASS-GATE", "RECOMP-CTRL-S", "HASH-CONTENT") for c, _ in out.failures)


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
    print(f"\n{len(tests) - failed}/{len(tests)} manual-evidence tests passed")
    sys.exit(1 if failed else 0)
