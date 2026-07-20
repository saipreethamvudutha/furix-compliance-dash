"""
worker.py
=========
The posture worker service (Wave-J P0). Closes the "continuous compliance is
manual" gap: a real, restart-safe worker that drives EVERY scheduled connector
run through the unified posture pipeline via the durable work queue.

Each tick, per tenant:
  1. return crashed-worker jobs to the queue (expired leases),
  2. enqueue a posture job for every DUE connector (idempotent per due-window),
  3. claim ONE posture job and execute the FULL posture pipeline (collect →
     evidence → assertions → verified report → findings), preserving approved
     manual attestations, and record connector health.

Run as its own process (production):  python -m api.worker
Time is injected into `tick()` so scheduling is deterministic in tests; `main()`
loops with a real clock.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from compliance_reporting.attestation_store import AttestationStore
from compliance_reporting.connector_registry import ConnectorRegistry
from compliance_reporting.history import ReportStore
from compliance_reporting.registry import FrameworkRegistry
from compliance_reporting.work_queue import WorkQueue

from . import service
from .attest_keys import attestation_keyring_for
from .secrets_env import read_secret

POSTURE_KIND = "posture"


class PostureWorker:
    def __init__(self, stores_root: Path | str, *, signing_secret: str,
                 registry: FrameworkRegistry | None = None, worker_name: str = "posture-worker-1"):
        self.tenants_root = Path(stores_root) / "tenants"
        self.signing_secret = signing_secret
        self.worker_name = worker_name
        self._registry = registry

    def _registry_lazy(self) -> FrameworkRegistry:
        if self._registry is None:
            self._registry = FrameworkRegistry.from_live()
        return self._registry

    def _tenants(self) -> list[str]:
        if not self.tenants_root.exists():
            return []
        return sorted(p.name for p in self.tenants_root.iterdir() if p.is_dir())

    def _store(self, tenant: str) -> ReportStore:
        return ReportStore(self.tenants_root / tenant)

    def _approved(self, store: ReportStore, tenant: str):
        return AttestationStore(store.root).approved_attestations(tenant), attestation_keyring_for(tenant)

    def process(self, tenant: str, connector_id: str) -> dict[str, Any]:
        """Execute the full posture pipeline for one connector."""
        store = self._store(tenant)
        reg = ConnectorRegistry(store.root)
        job = reg.get(tenant, connector_id)
        if job is None:
            raise ValueError(f"unknown connector {connector_id}")
        atts, ring = self._approved(store, tenant)
        return service.run_connector_posture(
            store, tenant, connector_id, kind=job["kind"], config=job.get("config", {}) or {},
            signing_secret=self.signing_secret, registry=self._registry_lazy(),
            attestations=atts, attestation_keyring=ring, actor=self.worker_name)

    def tick(self, *, now: int, lease_seconds: int = 300) -> dict[str, int]:
        enqueued = processed = failed = 0
        for tenant in self._tenants():
            store = self._store(tenant)
            reg = ConnectorRegistry(store.root)
            q = WorkQueue(store.root)
            q.requeue_expired(now=now)

            # enqueue a posture job for every due connector (idempotent per window)
            for job in reg.due(tenant, now):
                cid = job["connector_id"]
                q.enqueue(tenant=tenant, kind=POSTURE_KIND, payload={"connector_id": cid}, now=now,
                          job_id=f"posture-{tenant}-{cid}-{job['next_run_at']}")
                enqueued += 1

            # claim + run ONE posture job
            claimed = q.claim(worker=self.worker_name, now=now, lease_seconds=lease_seconds)
            if not claimed or claimed["kind"] != POSTURE_KIND:
                continue
            cid = claimed["payload"]["connector_id"]
            try:
                out = self.process(tenant, cid)
                reg.record_run(tenant, cid, now=now, manifest=out["manifest"], error=None)
                q.complete(claimed["job_id"])
                processed += 1
            except Exception as e:  # noqa: BLE001
                reg.record_run(tenant, cid, now=now, manifest=None, error=str(e))
                q.fail(claimed["job_id"], error=str(e), now=now)
                failed += 1
        return {"enqueued": enqueued, "processed": processed, "failed": failed}


def _signing_secret() -> str:
    s = read_secret("FURIX_CONNECTOR_SIGNING_SECRET", "")
    if not s and os.environ.get("FURIX_ENV", "development").lower() != "production":
        return "furix-dev-connector-secret"
    return s


def main() -> int:  # pragma: no cover - the long-running process entrypoint
    root = os.environ.get("FURIX_REPORT_STORE", "_report_store")
    interval = int(os.environ.get("FURIX_WORKER_INTERVAL", "30"))
    secret = _signing_secret()
    if not secret:
        print("[worker] FATAL: FURIX_CONNECTOR_SIGNING_SECRET not set (manifests are mandatory-signed)")
        return 1
    worker = PostureWorker(root, signing_secret=secret)
    print(f"[worker] posture worker started; store={root} interval={interval}s")
    while True:
        try:
            stats = worker.tick(now=int(time.time()))
            if any(stats.values()):
                print(f"[worker] {stats}")
        except Exception as e:  # noqa: BLE001
            print(f"[worker] tick error: {e}")
        time.sleep(interval)


if __name__ == "__main__":  # pragma: no cover
    import sys
    sys.exit(main())
