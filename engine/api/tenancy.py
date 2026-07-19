"""
tenancy.py
==========
Tenant-scoped ReportStore resolution (FUR-CMP-004). Each tenant gets its own
store subtree under the configured root, so a report written for tenant A is
physically unreachable from a request scoped to tenant B — object-level
isolation, not a filter that can be forgotten.

    <FURIX_REPORT_STORE>/
      tenants/
        acme/         reports/ batches/ index.jsonl
        globex/       reports/ batches/ index.jsonl

The tenant id is taken from the authenticated Principal, never from client
input (except the explicit cross-tenant path, which requires an admin/MSSP
scope checked in auth.authorize).
"""

from __future__ import annotations

import re
from pathlib import Path
from threading import Lock

from compliance_reporting.history import ReportStore

# tenant ids are slugs: lowercase alnum, dash, underscore — no path traversal.
_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


def valid_tenant(tenant_id: str) -> bool:
    return bool(_TENANT_RE.match(tenant_id))


class TenantStores:
    """Process-wide registry of per-tenant ReportStores (thread-safe, cached)."""

    def __init__(self, root: Path | str):
        self.root = Path(root) / "tenants"
        self._cache: dict[str, ReportStore] = {}
        self._lock = Lock()

    def for_tenant(self, tenant_id: str) -> ReportStore:
        if not valid_tenant(tenant_id):
            raise ValueError(f"invalid tenant id: {tenant_id!r}")
        with self._lock:
            store = self._cache.get(tenant_id)
            if store is None:
                store = ReportStore(self.root / tenant_id)
                self._cache[tenant_id] = store
            return store
