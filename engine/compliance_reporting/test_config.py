"""
test_config.py
==============
Positive config-posture assertions (Wave 2, FUR-CMP-008/009): connectors,
the assertion catalog + evaluator, and the report merge that lets a control
legitimately reach `compliant` with an earned compliance %.

    python3 -m compliance_reporting.test_config
"""

from __future__ import annotations

import copy

from .config_assertions import CONFIG_ASSERTION_CATALOG, evaluate
from .connectors import parse_snapshot
from .fixtures import demo_batch, demo_config_snapshot, demo_config_snapshot_with_gap
from .registry import FrameworkRegistry
from .report_builder import build_report
from .verifier import verify_report

_REG = FrameworkRegistry.from_snapshot()
_GEN_AT = "2026-07-19T12:00:00+00:00"


def _snap():
    return parse_snapshot(demo_config_snapshot())


# ── connectors ────────────────────────────────────────────────────────────────
def test_snapshot_parses_and_reconciles_population():
    s = _snap()
    assert s.observed_count("okta_app") == 2 == s.expected_count("okta_app")
    assert s.observed_count("github_repo") == 2
    # the expanded snapshot spans many resource types across 13 controls
    types = {r.resource_type for r in s.resources}
    for t in ("okta_app", "aws_s3_bucket", "github_repo", "asset", "software",
              "config_item", "vuln_scan", "log_source", "endpoint", "backup_job"):
        assert t in types, t


# ── evaluator ─────────────────────────────────────────────────────────────────
def test_all_assertions_pass_on_clean_snapshot():
    results = {r["spec_id"]: r for r in evaluate(_snap())}
    assert len(results) == len(CONFIG_ASSERTION_CATALOG)
    for r in results.values():
        assert r["status"] == "pass", (r["spec_id"], r["status_reason"])
        assert r["population"]["reconciled"] and r["population"]["failing"] == 0


def test_incomplete_population_is_unknown_not_pass():
    raw = demo_config_snapshot()
    raw["expected_counts"]["okta_app"] = 5   # expected 5, only 2 observed
    r = {x["spec_id"]: x for x in evaluate(parse_snapshot(raw))}["CFG-IDP-MFA-EXTERNAL"]
    assert r["status"] == "unknown" and r["status_reason"] == "incomplete_population"


def test_undeclared_population_is_unknown_never_pass():
    """P1 fix: a collector that did NOT declare expected_counts can never make
    an assertion PASS — incomplete collection can't masquerade as complete."""
    raw = demo_config_snapshot()
    del raw["expected_counts"]["okta_app"]   # undeclared → unverified population
    r = {x["spec_id"]: x for x in evaluate(parse_snapshot(raw))}["CFG-IDP-MFA-EXTERNAL"]
    assert r["status"] == "unknown" and r["status_reason"] == "population_unverified"
    assert r["population"]["population_verified"] is False


def test_evaluator_hash_covers_the_actual_predicate_logic():
    """P0 fix: opposing predicates must NOT collide on the evaluator hash."""
    from .config_assertions import ConfigAssertionSpec
    base = dict(spec_id="X", title="t", resource_type="rt", control_edges=("Control 1",),
                severity="high", applies_clause={"op": "always"}, rationale="r")
    a = ConfigAssertionSpec(predicate_clause={"op": "truthy", "attr": "enabled"}, **base)
    b = ConfigAssertionSpec(predicate_clause={"op": "falsy", "attr": "enabled"}, **base)
    c = ConfigAssertionSpec(predicate_clause={"op": "gte", "attr": "n", "value": 90}, **base)
    d = ConfigAssertionSpec(predicate_clause={"op": "gte", "attr": "n", "value": 30}, **base)
    hashes = {a.evaluator_hash(), b.evaluator_hash(), c.evaluator_hash(), d.evaluator_hash()}
    assert len(hashes) == 4, "opposing/parameterised predicates must hash differently"


def test_violation_makes_assertion_fail():
    r = {x["spec_id"]: x for x in evaluate(parse_snapshot(demo_config_snapshot_with_gap()))}
    assert r["CFG-GH-BRANCH-PROTECTION"]["status"] == "fail"
    assert r["CFG-GH-BRANCH-PROTECTION"]["population"]["failing"] == 1
    # the other GitHub assertions still pass
    assert r["CFG-GH-SECRET-SCANNING"]["status"] == "pass"


def test_evaluator_hash_is_stable():
    a = {r["spec_id"]: r["evaluator_hash"] for r in evaluate(_snap())}
    b = {r["spec_id"]: r["evaluator_hash"] for r in evaluate(_snap())}
    assert a == b
    assert a["CFG-IDP-MFA-EXTERNAL"] != a["CFG-AWS-ROOT-MFA"]


def test_catalog_spans_thirty_assertions_and_thirteen_controls():
    assert len(CONFIG_ASSERTION_CATALOG) >= 30
    controls = {c for s in CONFIG_ASSERTION_CATALOG.values() for c in s.control_edges}
    # config now covers many controls detection never touched (1,2,4,7,8,10,11,12,13)
    for c in ("Control 1", "Control 2", "Control 4", "Control 7", "Control 8",
              "Control 10", "Control 11", "Control 12", "Control 13", "Control 16"):
        assert c in controls, c
    assert len(controls) >= 13


def test_resource_evidence_has_lineage_hash():
    r = {x["spec_id"]: x for x in evaluate(_snap())}["CFG-BACKUP-ENCRYPTED"]
    ev = r["evidence"][0]
    assert ev["resource_sha256"] and ev["raw_uri"] == f"furix-evidence://{ev['resource_sha256']}"


# ── freshness / STALE (FUR-CMP-010) ───────────────────────────────────────────
def test_fresh_evidence_within_slo_passes():
    # as_of equal to collected_at → age 0 → fresh
    results = evaluate(_snap(), as_of="2026-07-19T08:00:00+00:00")
    assert all(r["status"] == "pass" for r in results)
    assert all(not r["freshness"]["stale"] for r in results)


def test_stale_evidence_downgrades_pass_to_stale():
    # config collected 2026-07-19, evaluated 6 months later → beyond every SLO
    results = evaluate(_snap(), as_of="2027-01-19T08:00:00+00:00")
    assert all(r["status"] == "stale" for r in results)
    assert all(r["freshness"]["stale"] for r in results)


def test_stale_config_cannot_make_control_compliant():
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT,
                     config_snapshot=demo_config_snapshot(),
                     config_as_of="2027-01-19T08:00:00+00:00")
    # every config assertion is stale → NO control should be compliant on it
    compliant = [c["control_id"] for c in r["controls"] if c["status"] == "compliant"]
    assert compliant == [], compliant
    assert verify_report(r, demo_batch()).ok


def test_verifier_rejects_pass_on_stale_evidence():
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT,
                     config_snapshot=demo_config_snapshot())
    bad = copy.deepcopy(r)
    # force one assertion stale but leave it claiming pass
    a = bad["config_assertions"][0]
    a["freshness"]["stale"] = True
    out = verify_report(bad, demo_batch())
    assert not out.ok
    assert any(c in ("CFG-FRESH-GATE", "HASH-CONTENT") for c, _ in out.failures)


# ── report merge: controls can now be compliant ──────────────────────────────
def test_positive_pass_makes_control_compliant():
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT,
                     config_snapshot=demo_config_snapshot())
    by_id = {c["control_id"]: c for c in r["controls"]}
    # Control 3 (public buckets blocked) and Control 16 (GitHub) → compliant
    assert by_id["Control 3"]["status"] == "compliant"
    assert by_id["Control 16"]["status"] == "compliant"
    assert by_id["Control 3"]["config_passing"]
    # detection failures still outrank a clean config
    assert by_id["Control 5"]["status"] == "at_risk"
    assert by_id["Control 6"]["status"] == "at_risk"


def test_compliance_pct_is_now_earned_not_null():
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT,
                     config_snapshot=demo_config_snapshot())
    cis = next(f for f in r["frameworks"] if f["framework_id"] == "cis_v8")
    assert cis["requirements_compliant"] >= 2       # Controls 3 + 16
    assert cis["compliance_pct"] is not None and cis["compliance_pct"] > 0
    assert r["summary"]["config_assertions_passed"] == len(CONFIG_ASSERTION_CATALOG)


def test_config_failure_flips_control_to_at_risk():
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT,
                     config_snapshot=demo_config_snapshot_with_gap())
    by_id = {c["control_id"]: c for c in r["controls"]}
    assert by_id["Control 16"]["status"] == "at_risk"   # branch protection off
    assert "CFG-GH-BRANCH-PROTECTION" in by_id["Control 16"]["config_failing"]


def test_no_config_snapshot_preserves_detection_only_behaviour():
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT)
    assert r["config_assertions"] == []
    for c in r["controls"]:
        assert c["status"] != "compliant"              # no positive assertions → none met


# ── verification holds with config assertions ─────────────────────────────────
def test_verifier_accepts_report_with_config():
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT,
                     config_snapshot=demo_config_snapshot())
    res = verify_report(r, demo_batch())
    assert res.ok, res.summary()


def test_verifier_rejects_forged_config_pass():
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT,
                     config_snapshot=demo_config_snapshot_with_gap())
    bad = copy.deepcopy(r)
    # forge the failing branch-protection assertion into a pass
    for res in bad["config_assertions"]:
        if res["spec_id"] == "CFG-GH-BRANCH-PROTECTION":
            res["status"] = "pass"
    out = verify_report(bad, demo_batch())
    assert not out.ok
    assert any(c in ("CFG-PASS-GATE", "RECOMP-CTRL-S", "HASH-CONTENT")
               for c, _ in out.failures)


def test_determinism_with_config():
    from .report_builder import canonical_json
    a = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT,
                     config_snapshot=demo_config_snapshot())
    b = build_report(demo_batch(), registry=_REG, generated_at=_GEN_AT,
                     config_snapshot=demo_config_snapshot())
    assert a["report_id"] == b["report_id"]
    assert canonical_json(a) == canonical_json(b)


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
    print(f"\n{len(tests) - failed}/{len(tests)} config tests passed")
    sys.exit(1 if failed else 0)
