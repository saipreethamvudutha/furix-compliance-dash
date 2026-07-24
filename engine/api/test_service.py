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


def test_verification_reports_named_level():
    """FUR-CMP-003: the API states the achieved verification level; with a
    stored batch that is ROLLUP_VERIFIED — never an overclaim about raw logs."""
    store = _store()
    out = service.ingest_batch(store, _ATTACK, analyzer=_stub_analyzer,
                               registry=_REG, deliver=False)
    assert out["verification"]["level"] == "ROLLUP_VERIFIED"


def test_auto_ingest_routes_known_formats_deterministically():
    """FUR-CMP-005 acceptance gate: with log_type='auto', recognised formats
    are classified BEFORE analysis so the analyzer receives the concrete type
    (never 'auto'), and only unrecognised lines fall back to 'generic'."""
    seen: list[str] = []

    def recording_analyzer(raw: str, log_type: str):
        seen.append(log_type)
        return _stub_analyzer(raw, log_type)

    cloudtrail = ('{"eventVersion": "1.08", "eventSource": "iam.amazonaws.com", '
                  '"eventName": "CreateUser", "awsRegion": "us-east-1"}')
    syslog = "Jul  6 08:12:01 web01 sshd[4242]: Failed password for root from 10.0.0.5 port 22 ssh2"
    mystery = "completely unrecognisable line ~~ 12345"
    store = _store()
    service.ingest_batch(store, "\n".join([cloudtrail, syslog, mystery]),
                         analyzer=recording_analyzer, registry=_REG, deliver=False)
    assert "auto" not in seen, "analyzer must never receive the 'auto' pseudo-type"
    assert seen[0] == "cloudtrail" and seen[1] == "syslog"
    assert seen[2] == "generic"  # unknown stays generic (deterministic unless FURIX_LLM_ENRICH=1)


def test_findings_lifecycle_end_to_end():
    """Wave 5: at-risk controls → derived findings → risk acceptance → the
    live frameworks annotate the at-risk row with the exception."""
    store = _store()
    service.ingest_batch(store, _ATTACK, analyzer=_stub_analyzer, registry=_REG, deliver=False)
    d = service.derive_findings(store, "latest", tenant="acme", actor="analyst",
                                occurred_at="2026-07-19T09:00:00+00:00")
    assert d["opened"] >= 2 and d["open_findings"] >= 2   # Control 5 + 10 at risk
    findings = service.list_findings(store, open_only=True)
    fid = next(f["finding_id"] for f in findings if f["control_id"] == "Control 5")

    # accept the risk with a full exception
    service.transition_finding(store, fid, "accept_risk", actor="ciso",
                               occurred_at="2026-07-19T10:00:00+00:00",
                               payload={"exception": {"approver": "ciso", "rationale": "legacy",
                                                      "compensating_control": "isolation",
                                                      "expiry": "2026-12-01T00:00:00+00:00"}})
    # the live frameworks now annotate Control 5's at-risk row with the exception
    fws = service.get_frameworks(store, "latest", as_of="2026-07-20T00:00:00+00:00")
    cis = next(f for f in fws if f["id"] == "cis")
    c5 = next(c for c in cis["controls"] if c["reference"] == "Control 5")
    assert c5["status"] == "gap" and c5["finding"]["state"] == "risk_accepted"
    assert c5["finding"]["exception"]["approver"] == "ciso"


def test_evidence_persistence_failure_aborts_ingest():
    """Wave-N transactional evidence: if raw evidence can't be persisted, the
    ingest aborts — no report is produced with unbacked evidence."""
    class FailingEvidenceStore:
        objects_dir = None
        def put(self, *a, **k):
            raise OSError("disk full")
        def verify_object(self, sha):
            return False
    store = _store()
    try:
        service.ingest_batch(store, _ATTACK, analyzer=_stub_analyzer, registry=_REG,
                             deliver=False, evidence_store=FailingEvidenceStore())
        raise AssertionError("ingest did not abort on evidence persistence failure")
    except service.IngestError:
        pass
    assert len(store.entries()) == 0   # no report saved


def test_evidence_verification_failure_aborts_ingest():
    """Even if put() 'succeeds' but the object doesn't verify, abort."""
    class SilentlyDroppingStore:
        def put(self, raw, **k):
            class _O:  # returns an object but never actually stored it
                sha256 = "0" * 64
            return _O()
        def verify_object(self, sha):
            return False
    store = _store()
    try:
        service.ingest_batch(store, "CreateUser evil", analyzer=_stub_analyzer, registry=_REG,
                             deliver=False, evidence_store=SilentlyDroppingStore())
        raise AssertionError("ingest did not abort on verification failure")
    except service.IngestError:
        pass


def test_get_evidence_returns_verified_object():
    """FUR-CMP-007: a retained evidence object resolves to its raw bytes +
    provenance envelope, with a live integrity re-verification."""
    from compliance_reporting.evidence import EvidenceStore
    store = _store()
    ev = EvidenceStore(store.root)
    obj = ev.put("Jul  6 08:12:01 web01 sshd[4242]: Failed password for root",
                 source="syslog", tenant="default")
    got = service.get_evidence(store, obj.sha256)
    assert got["sha256"] == obj.sha256
    assert got["integrity_verified"] is True
    assert got["raw_uri"] == f"furix-evidence://{obj.sha256}"
    assert "Failed password" in got["raw"]
    assert got["envelope"]["source"] == "syslog"
    assert got["size_bytes"] > 0
    # uppercase / whitespace in the id is tolerated (normalised to lowercase)
    assert service.get_evidence(store, f"  {obj.sha256.upper()} ")["sha256"] == obj.sha256


def test_get_evidence_rejects_bad_id_and_missing_object():
    store = _store()
    for bad in ("", "not-a-sha", "abc", "g" * 64):
        try:
            service.get_evidence(store, bad)
            raise AssertionError(f"expected ValueError for {bad!r}")
        except ValueError:
            pass
    try:
        service.get_evidence(store, "0" * 64)   # well-formed but not retained
        raise AssertionError("expected FileNotFoundError for a missing object")
    except FileNotFoundError:
        pass


def test_evidence_includes_retention_posture():
    """FUR-CMP-008: get_evidence reports retention (class/retain_until/expired)."""
    from compliance_reporting.evidence import EvidenceStore
    store = _store()
    obj = EvidenceStore(store.root).put("evt", source="syslog", tenant="default")
    r = service.get_evidence(store, obj.sha256)["retention"]
    assert r["class"] == "hipaa" and r["retention_days"] == 2190
    assert r["retain_until"] is not None
    assert r["expired"] is False
    assert r["on_legal_hold"] is False and r["legal_hold"] is None


def test_retention_expiry_and_legal_hold_override():
    """An object past its retention window is expired — unless a legal hold is
    active, which freezes it (overrides expiry). Release re-enables expiry."""
    from datetime import datetime, timezone
    from compliance_reporting.evidence import EvidenceStore
    from compliance_reporting.retention import retention_for

    now = datetime(2026, 7, 22, tzinfo=timezone.utc)
    assert retention_for("2010-01-01T00:00:00+00:00", now=now)["expired"] is True
    assert retention_for(now.isoformat(), now=now)["expired"] is False

    store = _store()
    obj = EvidenceStore(store.root).put("old evt", source="syslog", tenant="default",
                                        collected_at="2010-01-01T00:00:00+00:00")
    assert service.get_evidence(store, obj.sha256, now=now)["retention"]["expired"] is True
    service.place_legal_hold(store, obj.sha256, reason="litigation X", actor="auditor",
                             at="2026-07-22T00:00:00+00:00")
    held = service.get_evidence(store, obj.sha256, now=now)["retention"]
    assert held["on_legal_hold"] is True and held["expired"] is False
    service.release_legal_hold(store, obj.sha256, actor="admin",
                               at="2026-07-22T01:00:00+00:00", reason="closed")
    assert service.get_evidence(store, obj.sha256, now=now)["retention"]["expired"] is True


def test_legal_hold_validation():
    from compliance_reporting.evidence import EvidenceStore
    from compliance_reporting.legal_hold import LegalHoldError
    store = _store()
    obj = EvidenceStore(store.root).put("evt", source="syslog", tenant="default")
    for bad_reason in ("", "   "):
        try:
            service.place_legal_hold(store, obj.sha256, reason=bad_reason, actor="a", at="t")
            raise AssertionError("expected LegalHoldError for empty reason")
        except LegalHoldError:
            pass
    try:
        service.place_legal_hold(store, "0" * 64, reason="x", actor="a", at="t")
        raise AssertionError("expected FileNotFoundError for a missing object")
    except FileNotFoundError:
        pass
    try:
        service.release_legal_hold(store, obj.sha256, actor="a", at="t")
        raise AssertionError("expected LegalHoldError releasing a non-held object")
    except LegalHoldError:
        pass


def test_evidence_storage_posture():
    """FUR-CMP-008: get_evidence reports the store immutability posture; the
    default (no S3 configured) is honest — filesystem, write-once, not WORM."""
    from compliance_reporting.evidence import EvidenceStore
    store = _store()
    obj = EvidenceStore(store.root).put("evt", source="syslog", tenant="default")
    sp = service.get_evidence(store, obj.sha256)["storage"]
    assert sp["backend"] == "filesystem"
    assert sp["worm"] is False and sp["object_lock"] is False
    assert sp["immutability"] == "content-addressed write-once"
    assert "encrypted_at_rest" in sp
    assert service.evidence_storage_posture()["backend"] == "filesystem"


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
