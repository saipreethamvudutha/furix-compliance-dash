"""
test_service.py
===============
Exercises the API service layer end-to-end WITHOUT the heavy pipeline, by
injecting a stub analyzer (the pipeline is only lazy-imported in the default
path). Covers: ingest → build → verify → store, framework adapter output, the
read paths, and second-ingest diff + alerts.

    python3 -m api.test_service
"""

from __future__ import annotations

import tempfile

from compliance_reporting.fixtures import _policy_finding, _result
from compliance_reporting.history import ReportStore
from compliance_reporting.registry import FrameworkRegistry

from . import service

_REG = FrameworkRegistry.from_snapshot()


def _stub_analyzer(raw: str, log_type: str):
    """Deterministic fake pipeline: keyword in the line → a canned result dict."""
    if "CreateUser" in raw:
        return _result("cloudtrail", "high", ["Control 5"],
                       [_policy_finding("POL-001", "Unauthorised Account Creation", "Control 5",
                                        "high", "account_creation_detected", raw[:80], "1")],
                       "2026-07-16T09:00:01+00:00")
    if "mimikatz" in raw:
        return _result("windows_evtx", "critical", ["Control 10"],
                       [_policy_finding("POL-006", "Malware or C2 Activity Confirmed", "Control 10",
                                        "critical", "primary_finding", raw[:80], "2",
                                        nist_csf_ids=["DE.CM-09"])],
                       "2026-07-16T09:00:02+00:00")
    if "BROKEN" in raw:
        return _result("generic", "", [], [], "2026-07-16T09:00:03+00:00",
                       failure_stage="det_analysis")
    return _result("syslog", "informational", ["Control 13"], [],
                   "2026-07-16T09:00:04+00:00")


def _store():
    return ReportStore(tempfile.mkdtemp(prefix="furix_api_"))


_ATTACK = "line CreateUser backdoor_admin\nline mimikatz.exe\nBROKEN garbage\nroutine ok"
_CLEAN = "routine ok\nanother routine"


def test_ingest_builds_verified_report():
    store = _store()
    out = service.ingest_batch(store, _ATTACK, analyzer=_stub_analyzer,
                               registry=_REG, deliver=False)
    assert out["lines_ingested"] == 4
    assert out["verification"]["ok"] and out["verification"]["checks_run"] > 100
    assert len(out["frameworks"]) == 4
    assert out["summary"]["total_violations"] == 2   # POL-001 + POL-006
    assert out["summary"]["failed_logs"] == 1        # the BROKEN line
    assert len(store.entries()) == 1


def test_frameworks_reflect_findings():
    store = _store()
    out = service.ingest_batch(store, _ATTACK, analyzer=_stub_analyzer, registry=_REG, deliver=False)
    cis = next(f for f in out["frameworks"] if f["id"] == "cis")
    by_ref = {c["reference"]: c for c in cis["controls"]}
    assert by_ref["Control 5"]["status"] == "gap"    # account creation
    assert by_ref["Control 10"]["status"] == "gap"   # malware
    # a gap row carries traceable evidence
    assert by_ref["Control 5"]["systems"] and "POL-001" in by_ref["Control 5"]["systems"][0]["detail"]


def test_read_paths():
    store = _store()
    out = service.ingest_batch(store, _ATTACK, analyzer=_stub_analyzer, registry=_REG, deliver=False)
    rid = out["report_id"]
    assert service.get_report(store, "latest")["report_id"] == rid
    assert service.get_report(store, rid[:8])["report_id"] == rid   # prefix resolves
    assert len(service.get_frameworks(store, "latest")) == 4
    assert service.get_summary(store, "latest")["report_id"] == rid
    assert len(service.list_reports(store)) == 1
    assert len(service.get_trend(store)) == 1


def test_second_ingest_diffs_and_alerts_on_regression():
    store = _store()
    # first: clean week → high compliance
    first = service.ingest_batch(store, _CLEAN, analyzer=_stub_analyzer, registry=_REG, deliver=False)
    # second: attack week → regression → alerts
    second = service.ingest_batch(store, _ATTACK, analyzer=_stub_analyzer, registry=_REG, deliver=False)
    assert first["report_id"] != second["report_id"]
    assert len(store.entries()) == 2
    assert second["alerts"], "expected regression alerts on the attack ingest"
    assert any(a["type"] in ("control_regressed", "violations_increased") for a in second["alerts"])
    # forward-to-clean (improvement) should NOT raise control_regressed alerts
    third = service.ingest_batch(store, _CLEAN, analyzer=_stub_analyzer, registry=_REG, deliver=False)
    assert not any(a["type"] == "control_regressed" for a in third["alerts"])


def test_get_diff_between_two_reports():
    store = _store()
    a = service.ingest_batch(store, _CLEAN, analyzer=_stub_analyzer, registry=_REG, deliver=False)
    b = service.ingest_batch(store, _ATTACK, analyzer=_stub_analyzer, registry=_REG, deliver=False)
    d = service.get_diff(store, a["report_id"], b["report_id"])
    assert "diff" in d and "alerts" in d
    assert d["diff"]["violations"]["new_total"] == 2


def test_generate_and_ingest():
    store = _store()
    out = service.generate_and_ingest(store, count=30, attack_ratio=0.4, seed=11,
                                      analyzer=_stub_analyzer, registry=_REG)
    assert out["lines_ingested"] == 30
    assert out["verification"]["ok"]
    assert len(out["frameworks"]) == 4
    assert len(store.entries()) == 1


def test_empty_ingest_is_valid_no_data_report():
    store = _store()
    out = service.ingest_batch(store, "   \n  \n", analyzer=_stub_analyzer, registry=_REG, deliver=False)
    assert out["lines_ingested"] == 0
    assert out["verification"]["ok"]
    assert out["summary"]["total_violations"] == 0


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
    print(f"\n{len(tests) - failed}/{len(tests)} service tests passed")
    sys.exit(1 if failed else 0)
