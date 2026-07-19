"""
jobs.py
=======
Tiny, dependency-free background-job manager for long ingests. A single daemon
worker drains a FIFO queue, so jobs run one at a time (the pipeline is CPU-bound;
serializing avoids thread-safety concerns and keeps the box responsive). Each
job reports progress as it processes; the API exposes it via GET /api/jobs/{id}.

State lives in memory — fine for the single-uvicorn-worker deployment. If you
scale to multiple workers, back this with the ReportStore dir or Redis.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from queue import Queue
from typing import Any, Callable

# work(on_progress) -> result dict.  on_progress(processed, total, phase="analyzing")
ProgressFn = Callable[[int, int, str], None]
WorkFn = Callable[[ProgressFn], dict]

_MAX_JOBS = 100  # keep the most recent N jobs in memory


@dataclass
class Job:
    id: str
    status: str = "queued"          # queued | running | done | error
    phase: str = "queued"           # analyzing | finalizing | done | error
    processed: int = 0
    total: int = 0
    result: dict | None = None
    error: str | None = None
    owner: str | None = None        # key_id of the principal that submitted it
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        pct = round(100.0 * self.processed / self.total, 1) if self.total else 0.0
        return {
            "job_id": self.id,
            "status": self.status,
            "phase": self.phase,
            "processed": self.processed,
            "total": self.total,
            "percent": pct,
            "error": self.error,
            "result": self.result if self.status == "done" else None,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class JobManager:
    def __init__(self, durable_path: str | None = None) -> None:
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._queue: "Queue[tuple[str, WorkFn]]" = Queue()
        # Optional durable backing (FUR-OPS-001): job records survive a restart.
        # Set FURIX_JOB_DB (or pass durable_path) to enable; on startup, jobs a
        # crash left mid-flight are recovered as errored.
        import os  # noqa: PLC0415
        path = durable_path or os.environ.get("FURIX_JOB_DB")
        self._durable = None
        if path:
            from .sqlite_store import DurableJobStore  # noqa: PLC0415
            self._durable = DurableJobStore(path)
            self._durable.recover_stuck(time.time())
        self._worker = threading.Thread(target=self._loop, daemon=True)
        self._worker.start()

    # ── public ────────────────────────────────────────────────────────────────
    def submit(self, work: WorkFn, owner: str | None = None) -> str:
        job_id = uuid.uuid4().hex[:16]
        with self._lock:
            job = Job(id=job_id, owner=owner)
            self._jobs[job_id] = job
            self._order.append(job_id)
            self._evict_locked()
        if self._durable:
            self._durable.create(job_id, owner, job.created_at)
        self._queue.put((job_id, work))
        return job_id

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def stats(self) -> dict[str, int]:
        with self._lock:
            active = sum(1 for j in self._jobs.values() if j.status in ("queued", "running"))
            return {"total": len(self._jobs), "active": active, "queued": self._queue.qsize()}

    # ── internals ───────────────────────────────────────────────────────────────
    def _evict_locked(self) -> None:
        while len(self._order) > _MAX_JOBS:
            old = self._order.pop(0)
            job = self._jobs.get(old)
            # never evict a still-running job
            if job and job.status in ("queued", "running"):
                self._order.append(old)  # requeue at end; try later
                break
            self._jobs.pop(old, None)

    def _update(self, job_id: str, **fields: Any) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            for k, v in fields.items():
                setattr(job, k, v)
            job.updated_at = time.time()
        if self._durable:
            # mirror the durable columns (result serialised by the store)
            cols = {k: v for k, v in fields.items()
                    if k in ("status", "phase", "processed", "total", "result", "error")}
            if cols:
                self._durable.update(job_id, time.time(), **cols)

    def _loop(self) -> None:
        while True:
            job_id, work = self._queue.get()
            self._update(job_id, status="running", phase="analyzing")

            _last = [0.0]

            def on_progress(processed: int, total: int, phase: str = "analyzing") -> None:
                # throttle lock churn: update at most ~5x/sec (plus first/last)
                now = time.time()
                if processed in (1, total) or now - _last[0] >= 0.2:
                    _last[0] = now
                    self._update(job_id, processed=processed, total=total, phase=phase)

            try:
                result = work(on_progress)
                self._update(job_id, status="done", phase="done", result=result,
                             processed=result.get("lines_ingested", 0),
                             total=result.get("lines_ingested", 0))
            except Exception as exc:  # noqa: BLE001 — surface any failure to the client
                self._update(job_id, status="error", phase="error", error=str(exc))
            finally:
                self._queue.task_done()
