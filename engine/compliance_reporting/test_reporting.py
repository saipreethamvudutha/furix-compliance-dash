"""
test_reporting.py
=================
Pytest-compatible, but also self-running on machines without pytest:

    python3 -m compliance_reporting.test_reporting

Covers: aggregation correctness, framework rollup math, determinism,
verifier pass on honest output, verifier failure on five kinds of tampering,
mixed input shapes, empty/no-data batches, and catalog sync with
policy_engine (skipped when its heavy deps are absent).
"""

from __future__ import annotations

import copy
import json

from .fixtures import demo_batch
from .registry import CONTROL_CATALOG, TEST_CATALOG, FrameworkRegistry
from .report_builder import build_report, canonical_json
from .verifier import verify_report

_REGISTRY = FrameworkRegistry.from_snapshot()
_GEN_AT = "2026-07-14T12:00:00+00:00"


def _report(batch=None):
    return build_report(batch or demo_batch(), registry=_REGISTRY, generated_at=_GEN_AT)


# ── aggregation ───────────────────────────────────────────────────────────────
def test_batch_counters():
    r = _report()
    assert r["batch"]["total_logs"] == 5
    assert r["batch"]["successful_logs"] == 4
    assert r["batch"]["failed_logs"] == 1
    assert r["summary"]["total_violations"] == 6


def test_test_statuses():
    r = _report()
    by_id = {t["test_id"]: t for t in r["tests"]}
    assert by_id["POL-001"]["status"] == "fail" and by_id["POL-001"]["occurrences"] == 1
    assert by_id["POL-006"]["status"] == "fail"
    assert by_id["POL-004"]["status"] == "fail"
    assert by_id["POL-003"]["status"] == "pass"       # evaluated, never fired
    assert by_id["POL-014"]["status"] == "pass"
    assert len(by_id) == len(TEST_CATALOG)


def test_control_statuses():
    r = _report()
    by_id = {c["control_id"]: c for c in r["controls"]}
    # at risk via fired rules
    for ctrl in ("Control 5", "Control 6", "Control 8", "Control 10", "Control 12", "Control 15"):
        assert by_id[ctrl]["status"] == "at_risk", ctrl
    # monitored and clean
    for ctrl in ("Control 3", "Control 4", "Control 7", "Control 13", "Control 17"):
        assert by_id[ctrl]["status"] == "compliant", ctrl
    # no policy rule covers these — reported honestly
    for ctrl in ("Control 1", "Control 2", "Control 9", "Control 11",
                 "Control 14", "Control 16", "Control 18"):
        assert by_id[ctrl]["status"] == "not_monitored", ctrl
    # observation counts come from detection mappings, not rules
    assert by_id["Control 13"]["observation_count"] == 1   # benign log observed it
    assert by_id["Control 2"]["observation_count"] == 1    # windows log mapped it


def test_framework_rollup_math():
    r = _report()
    for fw in r["frameworks"]:
        monitored = fw["requirements_compliant"] + fw["requirements_at_risk"]
        assert (
            fw["requirements_total"]
            == monitored + fw["requirements_not_monitored"]
            == len(fw["requirements"])
        )
        if monitored:
            assert fw["compliance_pct"] == round(100.0 * fw["requirements_compliant"] / monitored, 1)
        else:
            assert fw["compliance_pct"] is None
    cis = next(fw for fw in r["frameworks"] if fw["framework_id"] == "cis_v8")
    assert cis["requirements_total"] == len(CONTROL_CATALOG)
    assert cis["requirements_at_risk"] == 6
    # PCI DSS is the fourth framework, rolled up through the same edges.
    # 11 of 12 requirements are reachable: Req 9 (Physical Access) has no
    # log-evidencable CIS control behind it — a truth the report must not hide.
    pci = next(fw for fw in r["frameworks"] if fw["framework_id"] == "pci_dss_4_0")
    assert pci["requirements_total"] == 11
    req_ids = {req["requirement_id"] for req in pci["requirements"]}
    assert "Req 9" not in req_ids
    assert pci["requirements_at_risk"] > 0  # Req 8 etc. inherit at-risk Control 5/6


def test_mixed_input_shapes_are_equivalent():
    wrapped = demo_batch()
    bare = [e["result"] for e in wrapped]
    a = build_report(wrapped, registry=_REGISTRY, generated_at=_GEN_AT)
    b = build_report(bare, registry=_REGISTRY, generated_at=_GEN_AT)
    # identical content except log_type labels lost on failed bare entries
    assert a["summary"] == b["summary"]
    assert a["integrity"]["content_sha256"] != "" and b["integrity"]["content_sha256"] != ""


def test_empty_and_all_failed_batches():
    empty = build_report([], registry=_REGISTRY, generated_at=_GEN_AT)
    assert empty["batch"]["total_logs"] == 0
    assert all(t["status"] == "no_data" for t in empty["tests"])
    assert verify_report(empty, []).ok

    failed_only = [e for e in demo_batch() if e["result"]["_failure_stage"]]
    r = build_report(failed_only, registry=_REGISTRY, generated_at=_GEN_AT)
    assert r["batch"]["successful_logs"] == 0
    assert all(t["status"] == "no_data" for t in r["tests"])
    assert verify_report(r, failed_only).ok


# ── determinism ───────────────────────────────────────────────────────────────
def test_determinism_same_batch_same_report():
    a, b = _report(), _report()
    assert a["report_id"] == b["report_id"]
    assert canonical_json(a) == canonical_json(b)


def test_report_is_json_serialisable():
    json.loads(json.dumps(_report()))


# ── verification ──────────────────────────────────────────────────────────────
def test_verifier_passes_on_honest_report():
    batch = demo_batch()
    result = verify_report(build_report(batch, registry=_REGISTRY, generated_at=_GEN_AT), batch)
    assert result.ok, result.summary()
    assert result.checks_run > 100  # it actually checked things


def _tampered(mutate):
    batch = demo_batch()
    report = build_report(batch, registry=_REGISTRY, generated_at=_GEN_AT)
    tampered = copy.deepcopy(report)
    mutate(tampered)
    return verify_report(tampered, batch)


def test_verifier_catches_inflated_compliance_pct():
    res = _tampered(lambda r: r["frameworks"][0].__setitem__("compliance_pct", 100.0))
    assert not res.ok and any(code.startswith(("RECOMP-FW", "HASH")) for code, _ in res.failures)


def test_verifier_catches_dropped_evidence():
    def mutate(r):
        t = next(t for t in r["tests"] if t["status"] == "fail")
        t["evidence"].pop()
    res = _tampered(mutate)
    assert not res.ok


def test_verifier_catches_flipped_control_status():
    def mutate(r):
        c = next(c for c in r["controls"] if c["status"] == "at_risk")
        c["status"] = "compliant"
    res = _tampered(mutate)
    assert not res.ok and any(code == "RECOMP-CTRL-S" for code, _ in res.failures)


def test_verifier_catches_edited_evidence_value():
    def mutate(r):
        t = next(t for t in r["tests"] if t["evidence"])
        t["evidence"][0]["triggered_value"] = "nothing to see here"
    res = _tampered(mutate)
    assert not res.ok and any(code == "HASH-EVIDENCE" for code, _ in res.failures)


def test_verifier_catches_forged_finding_uuid():
    def mutate(r):
        t = next(t for t in r["tests"] if t["evidence"])
        ev = t["evidence"][0]
        ev["finding_uuid"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        # attacker recomputes the row hash — REF check still catches it
        from .report_builder import _sha256_of
        ev["evidence_sha256"] = _sha256_of({k: ev[k] for k in ev if k != "evidence_sha256"})
    res = _tampered(mutate)
    assert not res.ok and any(code == "REF-EV-UUID" for code, _ in res.failures)


# ── persistence (ReportStore) ─────────────────────────────────────────────────
def _tmp_store():
    import tempfile
    from .history import ReportStore
    return ReportStore(tempfile.mkdtemp(prefix="furix_store_"))


def test_store_roundtrip_and_idempotency():
    from .history import ReportStore  # noqa: F401
    store = _tmp_store()
    batch = demo_batch()
    report = build_report(batch, registry=_REGISTRY, generated_at=_GEN_AT)
    p1 = store.save(report, batch=batch)
    p2 = store.save(report, batch=batch)          # identical save → no-op
    assert p1 == p2
    loaded = store.load(report["report_id"])
    assert canonical_json(loaded) == canonical_json(report)
    assert store.load_batch(report["report_id"]) is not None
    assert len(store.entries()) == 1              # not double-indexed


def test_store_refuses_tampered_report_on_save_and_load():
    from .history import IntegrityError
    store = _tmp_store()
    report = build_report(demo_batch(), registry=_REGISTRY, generated_at=_GEN_AT)
    bad = copy.deepcopy(report)
    bad["summary"]["total_violations"] = 0
    try:
        store.save(bad)
        raise AssertionError("save accepted a tampered report")
    except IntegrityError:
        pass
    # now tamper ON DISK and confirm load refuses it
    path = store.save(report)
    doc = json.loads(path.read_text())
    doc["summary"]["total_violations"] = 0
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True))
    try:
        store.load(report["report_id"])
        raise AssertionError("load returned a report tampered on disk")
    except IntegrityError:
        pass


def test_store_rebuild_index():
    store = _tmp_store()
    r1 = build_report(demo_batch(), registry=_REGISTRY, generated_at=_GEN_AT)
    from .fixtures import demo_batch_remediated
    r2 = build_report(demo_batch_remediated(), registry=_REGISTRY,
                      generated_at="2026-07-21T12:00:00+00:00")
    store.save(r1)
    store.save(r2)
    store.index_path.unlink()                     # lose the index
    assert store.rebuild_index() == 2             # fully recovered from reports
    ids = [e.report_id for e in store.entries()]
    assert set(ids) == {r1["report_id"], r2["report_id"]}


# ── diff + alerts ──────────────────────────────────────────────────────────────
def _two_reports():
    from .fixtures import demo_batch_remediated
    old = build_report(demo_batch(), registry=_REGISTRY, generated_at=_GEN_AT)
    new = build_report(demo_batch_remediated(), registry=_REGISTRY,
                       generated_at="2026-07-21T12:00:00+00:00")
    return old, new


def test_diff_detects_improvements_and_persistence():
    from .diff import diff_reports
    old, new = _two_reports()
    d = diff_reports(old, new)
    improved_ids = {r["control_id"] for r in d["controls"]["improved"]}
    # cloud takeover + malware remediated
    for ctrl in ("Control 5", "Control 8", "Control 10", "Control 12", "Control 15"):
        assert ctrl in improved_ids, ctrl
    # brute-force persists → Control 6 still at risk
    assert {r["control_id"] for r in d["controls"]["still_at_risk"]} == {"Control 6"}
    assert d["violations"]["delta"] == 1 - 6
    assert {t["test_id"] for t in d["tests"]["newly_passing"]} >= {"POL-001", "POL-006"}
    hipaa = next(f for f in d["frameworks"] if f["framework_id"] == "hipaa_security_rule")
    assert hipaa["direction"] == "improved"       # 0% → 50%


def test_diff_reverse_direction_yields_regression_alerts():
    from .diff import alerts_from_diff, diff_reports
    old, new = _two_reports()
    d = diff_reports(new, old)                    # time reversed = regression
    regressed_ids = {r["control_id"] for r in d["controls"]["regressed"]}
    assert "Control 5" in regressed_ids and "Control 10" in regressed_ids
    alerts = alerts_from_diff(d)
    types = {a["type"] for a in alerts}
    assert {"control_regressed", "violations_increased"} <= types
    # the forward (improving) diff must produce zero regression alerts
    forward_alerts = alerts_from_diff(diff_reports(old, new))
    assert not any(a["type"] == "control_regressed" for a in forward_alerts)


def test_diff_is_deterministic():
    from .diff import diff_reports
    old, new = _two_reports()
    assert canonical_json(diff_reports(old, new)) == canonical_json(diff_reports(old, new))


def test_trend_series_is_time_ordered():
    store = _tmp_store()
    old, new = _two_reports()
    store.save(new)                               # save out of order on purpose
    store.save(old)
    series = store.trend()
    assert [row["report_id"] for row in series] == [old["report_id"], new["report_id"]]
    assert series[0]["total_violations"] == 6 and series[1]["total_violations"] == 1


def test_trend_orders_by_data_window_when_generated_same_instant():
    # Two reports generated at the SAME wall-clock instant (back-to-back CLI
    # runs) must still order by their batch data window, not by report_id.
    from .fixtures import demo_batch_remediated
    store = _tmp_store()
    old = build_report(demo_batch(), registry=_REGISTRY, generated_at=_GEN_AT)
    new = build_report(demo_batch_remediated(), registry=_REGISTRY, generated_at=_GEN_AT)
    store.save(new)
    store.save(old)
    series = store.trend()
    assert [row["total_violations"] for row in series] == [6, 1]  # attack week first


# ── registry from real SCF JSON (skipped when the JSON/module is absent) ─────
def test_registry_from_scf_json_when_available():
    import os
    from pathlib import Path
    scf = os.environ.get(
        "FURIX_SCF_JSON",
        "/Users/preetham/compliance research/SCF-2026-2/JSON/scf-full-2026.2.json",
    )
    if not Path(scf).exists():
        print("  (skipped: SCF JSON not present)")
        return
    try:
        reg = FrameworkRegistry.from_scf_json(scf)
    except ImportError:
        print("  (skipped: scf_crosswalk module not importable here)")
        return
    # all three real crosswalks populated, all 18 CIS controls covered for NIST/PCI
    assert len(reg.cis_to_nist) == 18 and len(reg.cis_to_pci) == 18
    assert reg.cis_to_hipaa  # non-empty
    assert "SCF 2026.2" in reg.provenance
    # a full report builds + verifies against the real crosswalk
    r = build_report(demo_batch(), registry=reg, generated_at=_GEN_AT)
    assert verify_report(r, demo_batch()).ok
    # PCI now has real requirements, not the snapshot stub
    pci = next(f for f in r["frameworks"] if f["framework_id"] == "pci_dss_4_0")
    assert pci["requirements_total"] >= 8


# ── catalog sync with policy_engine (skipped without its heavy deps) ─────────
def test_catalog_mirrors_policy_engine():
    try:
        import policy_engine  # noqa: PLC0415
    except Exception:
        print("  (skipped: policy_engine deps unavailable in this environment)")
        return
    assert len(policy_engine._RULES) == len(TEST_CATALOG), (
        f"policy_engine has {len(policy_engine._RULES)} rules, "
        f"TEST_CATALOG has {len(TEST_CATALOG)} — update registry.py"
    )


# ── self-runner ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import traceback

    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)
