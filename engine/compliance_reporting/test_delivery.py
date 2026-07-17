"""
test_delivery.py
================
Tests for alert delivery sinks and the ATT&CK pivot's agreement with the
report's control model. Self-running:

    python3 -m compliance_reporting.test_delivery
"""

from __future__ import annotations

import io
import json
import tempfile
from pathlib import Path

from .delivery import ConsoleSink, JsonlSink, MultiSink, WebhookSink, deliver_alerts
from .detection import AttackPivotResolver
from .registry import CONTROL_CATALOG

_ALERTS = [
    {"type": "control_regressed", "severity": "critical", "control_id": "Control 6",
     "message": "Control 6 went compliant → at_risk"},
    {"type": "violations_increased", "severity": "medium", "message": "violations rose 1 → 6"},
]
_CTX = {"new_report_id": "abcd1234-0000", "old_report_id": "ef567890-0000"}


def test_console_sink_writes_sorted_by_severity():
    buf = io.StringIO()
    result = ConsoleSink(stream=buf).send(_ALERTS, context=_CTX)
    assert result.ok and result.delivered == 2
    out = buf.getvalue()
    assert out.index("CRITICAL") < out.index("MEDIUM")  # severity-ordered


def test_console_sink_reports_no_regressions():
    buf = io.StringIO()
    ConsoleSink(stream=buf).send([], context=_CTX)
    assert "none" in buf.getvalue()


def test_jsonl_sink_appends_durable_records():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "alerts.jsonl"
        JsonlSink(path).send(_ALERTS, context=_CTX)
        JsonlSink(path).send(_ALERTS, context=_CTX)  # append, not overwrite
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 4
        rec = json.loads(lines[0])
        assert rec["type"] and rec["context"]["new_report_id"] == "abcd1234-0000"


def test_webhook_sink_refuses_insecure_url_by_default():
    result = WebhookSink("http://example.com/hook").send(_ALERTS, context=_CTX)
    assert not result.ok and "non-https" in result.error


def test_webhook_sink_no_alerts_is_ok_noop():
    result = WebhookSink("https://example.com/hook").send([], context=_CTX)
    assert result.ok and result.delivered == 0


def test_multisink_isolation_one_failure_does_not_block_others():
    buf = io.StringIO()
    results = MultiSink([
        WebhookSink("http://insecure/hook"),   # will fail (non-https)
        ConsoleSink(stream=buf),               # must still deliver
    ]).send(_ALERTS, context=_CTX)
    assert results[0].ok is False and results[1].ok is True
    assert "CRITICAL" in buf.getvalue()


def test_deliver_alerts_convenience():
    buf = io.StringIO()
    results = deliver_alerts(_ALERTS, [ConsoleSink(stream=buf)], context=_CTX)
    assert len(results) == 1 and results[0].ok


# ── pivot ↔ report model agreement ────────────────────────────────────────────
def test_pivot_controls_are_all_real_catalog_controls():
    resolver = AttackPivotResolver.load()
    log = ('{"eventName":"CreateUser"}\n{"eventName":"AttachUserPolicy",'
           '"requestParameters":{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}}')
    result = resolver.resolve(log, "cloudtrail")
    assert result.control_ids  # non-empty
    for cid in result.control_ids:
        assert cid in CONTROL_CATALOG, f"pivot produced unknown control {cid}"


def test_pivot_agrees_with_keyword_engine_on_cloudtrail_takeover():
    # The keyword engine mapped the CloudTrail backdoor story to Controls
    # 3, 5, 6 (and 15). The pivot must cover the same access/account/data core.
    resolver = AttackPivotResolver.load()
    log = (
        '{"eventName":"ConsoleLogin","additionalEventData":{"MFAUsed":"No"}}\n'
        '{"eventName":"CreateUser","requestParameters":{"userName":"backdoor_admin"}}\n'
        '{"eventName":"AttachUserPolicy","requestParameters":'
        '{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}}\n'
        '{"eventName":"GetSecretValue","requestParameters":{"secretId":"prod/db/password"}}'
    )
    controls = set(resolver.resolve(log, "cloudtrail").control_ids)
    assert {"Control 3", "Control 5", "Control 6"} <= controls


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
    print(f"\n{len(tests) - failed}/{len(tests)} delivery tests passed")
    sys.exit(1 if failed else 0)
