"""
test_connector_registry.py
==========================
Scheduled connector jobs + connector health (Wave-G): durable registry,
deterministic scheduling (injected time), and health derivation.

    python3 -m compliance_reporting.test_connector_registry
"""

from __future__ import annotations

import tempfile

from .connector_registry import ConnectorRegistry, ConnectorScheduler

_SIGNED_OK = {"resource_sha256": "abc", "signature": "sig", "reconciled": True}
_UNSIGNED = {"resource_sha256": "abc", "signature": "", "reconciled": True}
_UNRECONCILED = {"resource_sha256": "abc", "signature": "sig", "reconciled": False}


def _reg():
    return ConnectorRegistry(tempfile.mkdtemp(prefix="furix_conn_"))


def _register(reg, now=1000, schedule=3600):
    return reg.register(tenant="acme", connector_id="aws-prod", kind="aws-org-iam",
                        schedule_seconds=schedule, now=now)


def test_register_schedules_first_run_now_and_is_unknown():
    reg = _reg()
    job = _register(reg, now=1000)
    assert job["next_run_at"] == 1000 and job["last_run_at"] is None
    listed = reg.list("acme", now=1000)[0]
    assert listed["health"] == "unknown"


def test_due_and_run_marks_healthy_then_reschedules():
    reg = _reg()
    _register(reg, now=1000, schedule=3600)
    sched = ConnectorScheduler(reg)
    assert [j["connector_id"] for j in reg.due("acme", 1000)] == ["aws-prod"]
    sched.tick("acme", lambda job: _SIGNED_OK, now=1000)
    row = reg.list("acme", now=1000)[0]
    assert row["health"] == "healthy" and row["last_status"] == "ok"
    assert row["last_signed"] and row["last_reconciled"]
    # rescheduled: not due again until now + cadence
    assert reg.due("acme", 1000) == []
    assert [j["connector_id"] for j in reg.due("acme", 1000 + 3600)] == ["aws-prod"]


def test_runner_error_is_failed_health():
    reg = _reg()
    _register(reg, now=1000)
    sched = ConnectorScheduler(reg)

    def boom(job):
        raise RuntimeError("permission denied")

    sched.run_one("acme", "aws-prod", boom, now=1000)
    row = reg.list("acme", now=1000)[0]
    assert row["health"] == "failed" and "permission denied" in row["last_error"]


def test_unsigned_or_unreconciled_is_degraded():
    reg = _reg()
    _register(reg, now=1000)
    sched = ConnectorScheduler(reg)
    sched.run_one("acme", "aws-prod", lambda j: _UNSIGNED, now=1000)
    assert reg.list("acme", now=1000)[0]["health"] == "degraded"
    sched.run_one("acme", "aws-prod", lambda j: _UNRECONCILED, now=2000)
    assert reg.list("acme", now=2000)[0]["health"] == "degraded"


def test_stale_data_is_degraded():
    reg = _reg()
    _register(reg, now=1000, schedule=3600)
    ConnectorScheduler(reg).run_one("acme", "aws-prod", lambda j: _SIGNED_OK, now=1000)
    # fresh right after
    assert reg.list("acme", now=1000)[0]["health"] == "healthy"
    # more than 2x cadence later with no new run → stale → degraded
    assert reg.list("acme", now=1000 + 3 * 3600)[0]["health"] == "degraded"


def test_tenant_isolation():
    reg = _reg()
    _register(reg, now=1000)
    assert reg.list("globex", now=1000) == []
    assert reg.due("globex", 1000) == []


def test_register_is_idempotent_upsert():
    reg = _reg()
    _register(reg, now=1000, schedule=3600)
    _register(reg, now=1000, schedule=7200)  # update cadence
    rows = reg.list("acme", now=1000)
    assert len(rows) == 1 and rows[0]["schedule_seconds"] == 7200


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
    print(f"\n{len(tests) - failed}/{len(tests)} connector-registry tests passed")
    sys.exit(1 if failed else 0)
