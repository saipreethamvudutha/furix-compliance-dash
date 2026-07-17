"""
test_jobs.py
============
Tests the background JobManager end to end (real worker thread) and its
integration with service.ingest_batch via a stub analyzer.

    python3 -m api.test_jobs
"""

from __future__ import annotations

import tempfile
import time

from compliance_reporting.history import ReportStore
from compliance_reporting.registry import FrameworkRegistry

from . import service
from .jobs import JobManager
from .test_service import _ATTACK, _stub_analyzer

_REG = FrameworkRegistry.from_snapshot()


def _wait(jm: JobManager, jid: str, timeout: float = 8.0):
    end = time.time() + timeout
    while time.time() < end:
        job = jm.get(jid)
        if job and job.status in ("done", "error"):
            return job
        time.sleep(0.02)
    raise TimeoutError(f"job {jid} did not finish in {timeout}s")


def test_job_completes_with_progress():
    jm = JobManager()
    seen: list[tuple[int, int]] = []

    def work(progress):
        for i in range(5):
            progress(i + 1, 5, "analyzing")
            seen.append((i + 1, 5))
        return {"lines_ingested": 5, "ok": True}

    job = _wait(jm, jm.submit(work))
    assert job.status == "done"
    assert job.result["ok"] and job.processed == 5 and job.total == 5
    assert job.to_dict()["percent"] == 100.0


def test_job_error_surfaces():
    jm = JobManager()

    def work(progress):
        raise RuntimeError("boom in worker")

    job = _wait(jm, jm.submit(work))
    assert job.status == "error"
    assert "boom in worker" in (job.error or "")
    assert job.to_dict()["result"] is None


def test_job_runs_service_ingest():
    jm = JobManager()
    store = ReportStore(tempfile.mkdtemp(prefix="furix_jobs_"))
    jid = jm.submit(
        lambda p: service.ingest_batch(
            store, _ATTACK, analyzer=_stub_analyzer, registry=_REG, deliver=False, on_progress=p
        )
    )
    job = _wait(jm, jid)
    assert job.status == "done", job.error
    d = job.to_dict()
    assert d["status"] == "done" and d["percent"] == 100.0
    assert len(d["result"]["frameworks"]) == 4
    assert d["result"]["verification"]["ok"]
    assert len(store.entries()) == 1


def test_jobs_serialize_fifo():
    # two jobs submitted; both complete (single worker drains the queue in order)
    jm = JobManager()
    order: list[str] = []

    def make(tag):
        def work(progress):
            order.append(tag)
            return {"lines_ingested": 1}
        return work

    j1 = jm.submit(make("a"))
    j2 = jm.submit(make("b"))
    _wait(jm, j1)
    _wait(jm, j2)
    assert order == ["a", "b"]


def test_unknown_job_is_none():
    jm = JobManager()
    assert jm.get("does-not-exist") is None


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
    print(f"\n{len(tests) - failed}/{len(tests)} job tests passed")
    sys.exit(1 if failed else 0)
