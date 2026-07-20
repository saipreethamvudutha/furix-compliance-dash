"""
test_worker.py
=============
The posture worker (Wave-J P0): scheduled connector runs flow through the durable
queue and execute the FULL posture pipeline (evaluate controls), preserving
approved manual attestations — no more manifest-only scheduled runs.

    python3 -m api.test_worker
"""

from __future__ import annotations

import tempfile

from compliance_reporting.connector_registry import ConnectorRegistry
from compliance_reporting.history import ReportStore
from compliance_reporting.posture_run import PostureRunStore
from compliance_reporting.registry import FrameworkRegistry
from compliance_reporting.work_queue import WorkQueue

from .worker import PostureWorker

_REG = FrameworkRegistry.from_snapshot()


def _setup():
    """A stores root with one demo-aws connector registered for tenant 'acme'."""
    root = tempfile.mkdtemp(prefix="furix_worker_")
    store = ReportStore(f"{root}/tenants/acme")
    reg = ConnectorRegistry(store.root)
    reg.register(tenant="acme", connector_id="demo-aws", kind="demo-aws",
                 schedule_seconds=3600, now=1000)
    return root, store


def test_worker_enqueues_due_connectors_and_runs_full_posture():
    root, store = _setup()
    w = PostureWorker(root, signing_secret="s", registry=_REG)

    # tick 1: connector is due → enqueue + claim + run a full posture pipeline
    stats = w.tick(now=1000)
    assert stats["enqueued"] == 1 and stats["processed"] == 1 and stats["failed"] == 0

    # a REAL posture run was produced (controls evaluated), not just a manifest
    runs = PostureRunStore(store.root).list("acme")
    assert len(runs) == 1 and runs[0]["report_id"]
    assert runs[0]["evaluation"]["assertion_total"] >= 1  # controls actually evaluated
    # the report is loadable + verified
    assert store.load(runs[0]["report_id"])["report_id"] == runs[0]["report_id"]
    assert runs[0]["verified"] is True

    # connector health updated to healthy (signed + reconciled)
    row = ConnectorRegistry(store.root).list("acme", now=1000)[0]
    assert row["health"] == "healthy" and row["last_signed"] and row["last_reconciled"]


def test_worker_reschedules_and_does_not_double_enqueue():
    root, store = _setup()
    w = PostureWorker(root, signing_secret="s", registry=_REG)
    w.tick(now=1000)
    # right after a run the connector is rescheduled (now + cadence) → not due
    stats = w.tick(now=1000)
    assert stats["enqueued"] == 0 and stats["processed"] == 0
    # only one job total was ever enqueued (idempotent per due-window)
    q = WorkQueue(store.root)
    assert sum(q.stats("acme").values()) == 1


def test_worker_records_failure_on_bad_connector():
    root, store = _setup()
    reg = ConnectorRegistry(store.root)
    reg.register(tenant="acme", connector_id="broken", kind="nonexistent-kind",
                 schedule_seconds=3600, now=1000)
    w = PostureWorker(root, signing_secret="s", registry=_REG)
    # run enough ticks to process both due connectors
    seen = {"processed": 0, "failed": 0}
    for _ in range(4):
        s = w.tick(now=1000)
        seen["processed"] += s["processed"]
        seen["failed"] += s["failed"]
    assert seen["processed"] >= 1 and seen["failed"] >= 1  # demo ok, broken failed
    row = {c["connector_id"]: c for c in reg.list("acme", now=1000)}["broken"]
    assert row["health"] == "failed"


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
    print(f"\n{len(tests) - failed}/{len(tests)} worker tests passed")
    sys.exit(1 if failed else 0)
