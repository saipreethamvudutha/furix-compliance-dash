"""
test_detection.py
=================
Tests for the ATT&CK pivot, including CI-grade rule quality gates:

  * every rule file loads and validates (schema, level, unique ids)
  * every rule has fixtures, and matches every 'match' / rejects every 'nomatch'
  * every rule's ATT&CK tags resolve to at least one control edge
  * the YAML subset loader round-trips the structures rules use
  * the end-to-end pivot maps the CloudTrail attack story to the right controls
  * matching is deterministic and anchored (no substring false positives)

Run standalone:  python3 -m compliance_reporting.detection.test_detection
"""

from __future__ import annotations

import json
from pathlib import Path

from . import sigmayaml
from .resolver import AttackPivotResolver
from .sigma import Ruleset, build_env, evaluate, load_rule
from .technique_map import TechniqueMap

_HERE = Path(__file__).parent
_RULES = _HERE / "rules"
_FIXTURES = json.loads((_HERE / "fixtures" / "rule_fixtures.json").read_text())


# ── YAML subset ────────────────────────────────────────────────────────────────
def test_yaml_roundtrips_rule_structures():
    doc = sigmayaml.load(
        "title: T\nlogsource:\n  product: aws\n  service: cloudtrail\n"
        "detection:\n  sel:\n    a|contains|all:\n      - x\n      - y\n  condition: sel\n"
        "level: high\ntags:\n  - attack.t1098\nflow: [p, q]\n"
    )
    assert doc["logsource"] == {"product": "aws", "service": "cloudtrail"}
    assert doc["detection"]["sel"] == {"a|contains|all": ["x", "y"]}
    assert doc["tags"] == ["attack.t1098"] and doc["flow"] == ["p", "q"]


# ── rule quality gates ─────────────────────────────────────────────────────────
def test_all_rules_load_and_are_unique():
    rs = Ruleset.from_dir(_RULES)              # raises on dup id / bad schema
    assert len(rs.rules) >= 10
    ids = [r.rule_id for r in rs.rules]
    assert len(ids) == len(set(ids))


def test_every_rule_has_technique_and_control_edges():
    tmap = TechniqueMap.load()
    for rule in Ruleset.from_dir(_RULES).rules:
        assert rule.technique_ids, f"{rule.source_path} has no ATT&CK technique tag"
        mapped = [t for t in rule.technique_ids if tmap.controls_for(t)]
        assert mapped, f"{rule.source_path}: no technique resolves to a control edge"


def test_every_rule_has_fixtures():
    rule_ids = {r.rule_id for r in Ruleset.from_dir(_RULES).rules}
    fixture_ids = {k for k in _FIXTURES if not k.startswith("_")}
    assert rule_ids == fixture_ids, (
        f"fixture/rule mismatch: missing={rule_ids - fixture_ids}, "
        f"extra={fixture_ids - rule_ids}"
    )


def test_rules_match_and_reject_their_fixtures():
    rules = {r.rule_id: r for r in Ruleset.from_dir(_RULES).rules}
    for rule_id, cases in _FIXTURES.items():
        if rule_id.startswith("_"):
            continue
        rule = rules[rule_id]
        for ex in cases.get("match", []):
            env = build_env(ex["raw_log"], ex["log_type"])
            assert evaluate(rule, env), f"{rule_id} FAILED to match: {ex['raw_log'][:60]}"
        for ex in cases.get("nomatch", []):
            env = build_env(ex["raw_log"], ex["log_type"])
            assert not evaluate(rule, env), f"{rule_id} WRONGLY matched: {ex['raw_log'][:60]}"


# ── anchored matching (the bug the keyword table had) ─────────────────────────
def test_matching_is_anchored_no_substring_false_positive():
    rule = load_rule(_RULES / "windows_mimikatz.yml")
    # 'mimikatz' must not fire on an unrelated word that contains no such token
    env = build_env("EventID 4624 process notmimi.exe running", "windows_evtx")
    # 'mimikatz' genuinely absent → must not match
    assert not evaluate(rule, env)


# ── end-to-end pivot ───────────────────────────────────────────────────────────
def test_cloudtrail_attack_story_maps_to_expected_controls():
    resolver = AttackPivotResolver.load()
    cloudtrail = (
        '{"eventName":"ConsoleLogin","responseElements":{"ConsoleLogin":"Success"},'
        '"additionalEventData":{"MFAUsed":"No"}}\n'
        '{"eventName":"CreateUser","requestParameters":{"userName":"backdoor_admin"}}\n'
        '{"eventName":"AttachUserPolicy","requestParameters":'
        '{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}}\n'
        '{"eventName":"GetSecretValue","requestParameters":{"secretId":"prod/db/password"}}'
    )
    result = resolver.resolve(cloudtrail, "cloudtrail")
    controls = set(result.control_ids)
    # CreateUser→C5, AttachAdmin→C6, GetSecret→C3, NoMFA→C6
    assert {"Control 3", "Control 5", "Control 6"} <= controls
    # provenance chains every control back to a technique and a rule
    prov = result.provenance()
    assert all({"control_id", "technique_id", "rule_id"} <= set(row) for row in prov)
    assert any(r["technique_id"].startswith("T1136") for r in prov)  # account creation


def test_windows_mimikatz_maps_to_malware_defenses():
    resolver = AttackPivotResolver.load()
    result = resolver.resolve("proc mimikatz.exe sekurlsa::logonpasswords", "windows_evtx")
    assert "Control 10" in result.control_ids
    assert result.worst_level == "critical"


def test_resolution_is_deterministic():
    resolver = AttackPivotResolver.load()
    log = '{"eventName":"CreateUser","requestParameters":{"userName":"x"}}'
    a = resolver.resolve(log, "cloudtrail")
    b = resolver.resolve(log, "cloudtrail")
    assert a.control_ids == b.control_ids
    assert a.provenance() == b.provenance()


def test_benign_log_maps_to_nothing():
    resolver = AttackPivotResolver.load()
    result = resolver.resolve("GET /api/health 200 OK kube-probe", "benign_network")
    assert result.control_ids == []


# ── self-runner ───────────────────────────────────────────────────────────────
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
    print(f"\n{len(tests) - failed}/{len(tests)} detection tests passed")
    sys.exit(1 if failed else 0)
