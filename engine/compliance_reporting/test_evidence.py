"""
test_evidence.py
================
The Evidence Kernel: immutable content-addressed store, envelope determinism,
population manifest, assertion runs, and report wiring (FUR-CMP-007/008).

    python3 -m compliance_reporting.test_evidence
"""

from __future__ import annotations

import tempfile

from .assertions import ASSERTION_CATALOG, assertion_run
from .evidence import (
    EvidenceStore,
    build_population_manifest,
    evidence_uri,
    sha256_bytes,
)
from .fixtures import demo_batch
from .registry import FrameworkRegistry
from .report_builder import build_report
from .verifier import verify_report

_REG = FrameworkRegistry.from_snapshot()
_GEN_AT = "2026-07-19T12:00:00+00:00"


def _store():
    return EvidenceStore(tempfile.mkdtemp(prefix="furix_evid_"))


# ── content-addressed store ───────────────────────────────────────────────────
def test_put_is_content_addressed_and_idempotent():
    s = _store()
    raw = 'Jul 6 08:12:01 web01 sshd[1]: Failed password for root from 1.2.3.4'
    a = s.put(raw, source="syslog", tenant="acme")
    b = s.put(raw, source="syslog", tenant="acme")
    assert a.sha256 == b.sha256 == sha256_bytes(raw.encode())
    assert a.evidence_id == b.evidence_id            # identity is content-derived
    assert a.raw_uri == evidence_uri(a.sha256)
    assert s.exists(a.sha256)
    assert s.get_raw(a.sha256).decode() == raw


def test_identity_excludes_volatile_collected_at():
    s = _store()
    a = s.put("same bytes", source="x", collected_at="2026-01-01T00:00:00+00:00")
    b = s.put("same bytes", source="x", collected_at="2026-09-09T09:09:09+00:00")
    # different ingestion times, identical identity
    assert a.identity() == b.identity()
    assert "collected_at" not in a.identity()


def test_store_is_write_once_and_tamper_evident():
    s = _store()
    obj = s.put("original evidence", source="cloudtrail")
    # overwrite attempt with different bytes at the SAME address is impossible
    # (different bytes hash differently); the stored object re-verifies clean.
    assert s.verify_object(obj.sha256)
    # simulate on-disk tampering
    (s.objects_dir / f"{obj.sha256}.raw").write_text("tampered!")
    assert not s.verify_object(obj.sha256)


def test_envelope_carries_full_provenance():
    s = _store()
    obj = s.put("evt", source="okta", tenant="globex", boundary="prod-eu",
                observed_at="2026-07-01T00:00:00+00:00")
    d = obj.to_dict()
    for k in ("evidence_id", "source", "tenant", "boundary", "sha256", "raw_uri",
              "size_bytes", "observed_at", "collected_at", "collector_version",
              "parser_version", "schema_version"):
        assert k in d, k
    assert d["source"] == "okta" and d["tenant"] == "globex" and d["boundary"] == "prod-eu"


# ── population manifest ───────────────────────────────────────────────────────
def test_population_manifest_reconciles():
    m = build_population_manifest(expected=10, observed=8, errored=2)
    assert m["reconciled"] and m["coverage_pct"] == 80.0
    bad = build_population_manifest(expected=10, observed=5, errored=2)
    assert not bad["reconciled"]                     # 5+2 != 10
    excl = build_population_manifest(expected=10, observed=7, errored=1, excluded=2)
    assert excl["reconciled"] and excl["coverage_pct"] == 87.5  # 7 of (10-2)


# ── assertion runs ────────────────────────────────────────────────────────────
def test_assertion_spec_hash_is_stable_and_detection_only():
    spec = ASSERTION_CATALOG["POL-001"]
    assert spec.mode == "detection_only" and spec.predicate_kind == "negative"
    assert spec.evaluator_hash() == ASSERTION_CATALOG["POL-001"].evaluator_hash()
    assert spec.evaluator_hash() != ASSERTION_CATALOG["POL-006"].evaluator_hash()


def test_assertion_run_shape():
    run = assertion_run("POL-001", status="fail", status_reason="violations_observed",
                        occurrences=2, population={"evaluated": 5, "matched": 2},
                        evidence_refs=["furix-evidence://abc"])
    for k in ("spec_id", "policy_version", "mode", "evaluator_hash", "status",
              "occurrences", "population", "evidence_refs"):
        assert k in run
    assert run["evaluator_hash"] == ASSERTION_CATALOG["POL-001"].evaluator_hash()


# ── report wiring ─────────────────────────────────────────────────────────────
def test_report_carries_population_and_assertions():
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT)
    pop = r["population"]
    assert pop["expected"] == 5 and pop["observed"] == 4 and pop["errored"] == 1
    assert pop["reconciled"]
    for t in r["tests"]:
        a = t["assertion"]
        assert a["evaluator_hash"] == ASSERTION_CATALOG[t["test_id"]].evaluator_hash()
        assert a["status"] == t["status"]
        # evidence_refs reflect the test's evidence rows
        refs = sorted({e["raw_uri"] for e in t["evidence"] if e.get("raw_uri")})
        assert a["evidence_refs"] == refs


def test_verifier_accepts_evidence_and_population():
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT)
    res = verify_report(r, demo_batch())
    assert res.ok, res.summary()


def test_verifier_catches_broken_population():
    import copy
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT)
    bad = copy.deepcopy(r)
    bad["population"]["observed"] = 99
    res = verify_report(bad, demo_batch())
    assert not res.ok
    assert any(c.startswith(("POP-", "HASH")) for c, _ in res.failures)


def test_verifier_catches_forged_assertion_hash():
    import copy
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT)
    bad = copy.deepcopy(r)
    bad["tests"][0]["assertion"]["evaluator_hash"] = "0" * 64
    res = verify_report(bad, demo_batch())
    assert not res.ok
    assert any(c in ("ASSERT-HASH", "HASH-CONTENT") for c, _ in res.failures)


def test_evaluation_reproduced_level_from_raw_evidence():
    """FUR-CMP-003 top level: replaying the raw evidence through the SAME
    analyzer reproduces the byte-identical report → EVALUATION_REPRODUCED."""
    # a deterministic stub analyzer keyed on the raw line
    from .fixtures import _policy_finding, _result

    def analyzer(raw: str, log_type: str):
        if "CreateUser" in raw:
            res = _result("cloudtrail", "high", ["Control 5"],
                          [_policy_finding("POL-001", "Unauthorised Account Creation",
                                           "Control 5", "high", "account_creation_detected",
                                           raw[:60], "1")],
                          "2026-07-19T09:00:01+00:00")
        else:
            res = _result("syslog", "informational", ["Control 13"], [],
                          "2026-07-19T09:00:02+00:00")
        return res

    raw_logs = [("cloudtrail", "CreateUser backdoor_admin"), ("syslog", "routine heartbeat")]
    batch = [{"log_type": lt, "result": dict(analyzer(raw, lt))} for lt, raw in raw_logs]
    report = build_report(batch, registry=_REG, generated_at=_GEN_AT)

    res = verify_report(report, batch, raw_logs=raw_logs, reanalyzer=analyzer, registry=_REG)
    assert res.ok, res.summary()
    assert res.level == "EVALUATION_REPRODUCED", res.level


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
    print(f"\n{len(tests) - failed}/{len(tests)} evidence tests passed")
    sys.exit(1 if failed else 0)
