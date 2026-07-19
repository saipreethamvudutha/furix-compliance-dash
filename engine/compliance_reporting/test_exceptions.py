"""
test_exceptions.py
==================
Finding → remediation → exception lifecycle (Wave 5, FUR-CMP-013).

    python3 -m compliance_reporting.test_exceptions
"""

from __future__ import annotations

import tempfile

from .exceptions import (
    CLOSED,
    EXPIRED,
    IN_PROGRESS,
    OPEN,
    REMEDIATED,
    RETEST_PENDING,
    RISK_ACCEPTED,
    FindingStore,
    LifecycleError,
    new_finding_id,
)


def _store():
    return FindingStore(tempfile.mkdtemp(prefix="furix_find_"))


def _open(store, fid="f1"):
    return store.open_finding(
        fid, control_id="Control 6", framework_id="cis_v8", severity="high",
        actor="analyst@acme", occurred_at="2026-07-19T09:00:00+00:00",
        owner="secops", due_date="2026-08-19", discovered_report="r1",
    )


# ── happy-path remediation ────────────────────────────────────────────────────
def test_full_remediation_path_to_closed():
    s = _store()
    _open(s)
    assert s.get("f1")["state"] == OPEN
    s.transition("f1", "start", actor="secops", occurred_at="2026-07-20T00:00:00+00:00")
    assert s.get("f1")["state"] == IN_PROGRESS
    s.transition("f1", "remediate", actor="secops", occurred_at="2026-07-21T00:00:00+00:00",
                 reason="patched")
    assert s.get("f1")["state"] == REMEDIATED
    s.transition("f1", "request_retest", actor="secops", occurred_at="2026-07-22T00:00:00+00:00")
    assert s.get("f1")["state"] == RETEST_PENDING
    s.transition("f1", "retest_pass", actor="auditor@acme", occurred_at="2026-07-23T00:00:00+00:00",
                 payload={"retest": {"report_id": "r2", "result": "pass"}})
    f = s.get("f1")
    assert f["state"] == CLOSED and f["retest"]["report_id"] == "r2"


def test_illegal_transition_rejected():
    s = _store()
    _open(s)
    # can't close straight from open
    try:
        s.transition("f1", "retest_pass", actor="x", occurred_at="t",
                     payload={"retest": {"report_id": "r"}})
        raise AssertionError("closed from open")
    except LifecycleError:
        pass


def test_retest_pass_requires_report():
    s = _store()
    _open(s)
    s.transition("f1", "remediate", actor="x", occurred_at="t")
    s.transition("f1", "request_retest", actor="x", occurred_at="t2")
    try:
        s.transition("f1", "retest_pass", actor="x", occurred_at="t3")   # no retest.report_id
        raise AssertionError("closed without a retest report")
    except LifecycleError:
        pass


# ── risk acceptance + expiry ──────────────────────────────────────────────────
def _accept(s, expiry):
    return s.transition(
        "f1", "accept_risk", actor="ciso@acme", occurred_at="2026-07-20T00:00:00+00:00",
        reason="compensating control in place",
        payload={"exception": {"approver": "ciso@acme", "rationale": "legacy app",
                               "compensating_control": "network isolation", "expiry": expiry}},
    )


def test_accept_risk_requires_full_exception():
    s = _store()
    _open(s)
    try:
        s.transition("f1", "accept_risk", actor="ciso", occurred_at="t",
                     payload={"exception": {"approver": "ciso"}})  # missing fields
        raise AssertionError("accepted a partial exception")
    except LifecycleError:
        pass


def test_risk_acceptance_and_deterministic_expiry():
    s = _store()
    _open(s)
    _accept(s, expiry="2026-09-01T00:00:00+00:00")
    # before expiry → still accepted
    assert s.get("f1", as_of="2026-08-15T00:00:00+00:00")["state"] == RISK_ACCEPTED
    # after expiry → EXPIRED (an accepted risk can't silently become permanent)
    f = s.get("f1", as_of="2026-09-02T00:00:00+00:00")
    assert f["state"] == EXPIRED and f.get("expired") is True


# ── event sourcing / audit trail ──────────────────────────────────────────────
def test_event_history_is_append_only_and_identified():
    s = _store()
    _open(s)
    s.transition("f1", "start", actor="a", occurred_at="t1", reason="triage")
    s.transition("f1", "remediate", actor="b", occurred_at="t2", reason="fixed")
    hist = s.history("f1")
    assert [e["seq"] for e in hist] == [1, 2, 3]
    assert [e["to_state"] for e in hist] == [OPEN, IN_PROGRESS, REMEDIATED]
    # every event carries actor, from/to, reason, ts, and a content-derived id
    for e in hist:
        for k in ("actor", "from_state", "to_state", "reason", "occurred_at", "event_id"):
            assert e[k] is not None
    assert len({e["event_id"] for e in hist}) == 3   # unique, deterministic ids


def test_finding_id_is_stable_per_control():
    a = new_finding_id("acme", "Control 6", "cis_v8", "r1")
    b = new_finding_id("acme", "Control 6", "cis_v8", "r1")
    c = new_finding_id("acme", "Control 5", "cis_v8", "r1")
    assert a == b and a != c


def test_list_and_open_only_filter():
    s = _store()
    _open(s, "f1")
    _open(s, "f2")
    # close f2
    s.transition("f2", "remediate", actor="x", occurred_at="t")
    s.transition("f2", "request_retest", actor="x", occurred_at="t2")
    s.transition("f2", "retest_pass", actor="x", occurred_at="t3",
                 payload={"retest": {"report_id": "r9"}})
    assert {f["finding_id"] for f in s.list()} == {"f1", "f2"}
    open_ids = {f["finding_id"] for f in s.list(open_only=True)}
    assert "f1" in open_ids and "f2" not in open_ids   # closed f2 excluded


def test_reopen_after_close():
    s = _store()
    _open(s)
    s.transition("f1", "remediate", actor="x", occurred_at="t")
    s.transition("f1", "request_retest", actor="x", occurred_at="t2")
    s.transition("f1", "retest_pass", actor="x", occurred_at="t3",
                 payload={"retest": {"report_id": "r"}})
    assert s.get("f1")["state"] == CLOSED
    s.transition("f1", "reopen", actor="x", occurred_at="t4", reason="regressed")
    assert s.get("f1")["state"] == OPEN


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
    print(f"\n{len(tests) - failed}/{len(tests)} exception tests passed")
    sys.exit(1 if failed else 0)
