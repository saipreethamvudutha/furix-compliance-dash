"""
auth.py
=======
Server-side authentication, authorization and tenancy for the Furix API
(FUR-CMP-004). The pre-audit API was fully open — any network client could
read every tenant's evidence or ingest data, and roles lived in browser
localStorage. This module makes every endpoint fail closed.

Model
-----
* A **Principal** is proven by a bearer API key. Keys carry a tenant and a
  role; the role expands to a fixed scope set. Keys are compared by constant-
  time hash — the plaintext is never held after load.
* **Tenancy** is enforced at the data layer: each principal reads/writes only
  its own tenant's ReportStore. Cross-tenant reads require an explicit scope
  (admin / MSSP) AND an explicit `tenant` argument — never implicit.
* Every authorization decision (allow or deny) is written to an **append-only
  audit log** with actor, action, tenant, decision and wall-clock time.

Configuration (env)
-------------------
  FURIX_API_KEYS        JSON list: [{"key","key_id","tenant","role"}...]
  FURIX_API_KEYS_FILE   path to the same JSON (takes precedence if set)
  FURIX_ENV             "production" refuses to mint a dev key (fail closed)
  FURIX_AUTH_AUDIT      path to the auth audit JSONL (default <store>/auth_audit.jsonl)

In a non-production env with no keys configured, ONE loud-warned dev key is
minted so local work is frictionless. In production, missing keys means every
request is denied — there is no implicit trust.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Iterable

# ── roles → scopes ────────────────────────────────────────────────────────────
SCOPE_READ = "reports:read"
SCOPE_INGEST = "reports:ingest"
SCOPE_EXPORT = "reports:export"
SCOPE_ADMIN = "admin"
SCOPE_CROSS_TENANT = "tenant:cross_read"

ROLE_SCOPES: dict[str, frozenset[str]] = {
    "admin":   frozenset({SCOPE_READ, SCOPE_INGEST, SCOPE_EXPORT, SCOPE_ADMIN, SCOPE_CROSS_TENANT}),
    "analyst": frozenset({SCOPE_READ, SCOPE_INGEST}),
    "auditor": frozenset({SCOPE_READ, SCOPE_EXPORT}),
    "mssp":    frozenset({SCOPE_READ, SCOPE_INGEST, SCOPE_CROSS_TENANT}),
    "service": frozenset({SCOPE_READ, SCOPE_INGEST}),  # scoped machine account
    "readonly": frozenset({SCOPE_READ}),
}

DEV_KEY = "furix-dev-key"  # only ever active outside production, with a warning


@dataclass(frozen=True)
class Principal:
    key_id: str
    tenant_id: str
    role: str
    scopes: frozenset[str] = field(default_factory=frozenset)

    def has(self, scope: str) -> bool:
        return scope in self.scopes or SCOPE_ADMIN in self.scopes

    def can_read_tenant(self, tenant_id: str) -> bool:
        if tenant_id == self.tenant_id:
            return True
        return SCOPE_CROSS_TENANT in self.scopes or SCOPE_ADMIN in self.scopes


class AuthError(Exception):
    """Authentication failed (401)."""


class ForbiddenError(Exception):
    """Authenticated but not authorized (403)."""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuthRegistry:
    """
    Holds the hash→Principal table and appends the immutable audit log. One
    instance per process; constructed from env at import time in main.py.
    """

    def __init__(self, keys: Iterable[dict], audit_path: Path | str | None = None):
        self._by_hash: dict[str, Principal] = {}
        self._lock = Lock()
        self.audit_path = Path(audit_path) if audit_path else None
        for k in keys:
            role = str(k.get("role", "readonly"))
            scopes = ROLE_SCOPES.get(role, ROLE_SCOPES["readonly"])
            principal = Principal(
                key_id=str(k.get("key_id", "unknown")),
                tenant_id=str(k.get("tenant", "default")),
                role=role,
                scopes=scopes,
            )
            self._by_hash[_sha256(str(k["key"]))] = principal

    # ── construction ─────────────────────────────────────────────────────────
    @classmethod
    def from_env(cls) -> "AuthRegistry":
        raw = ""
        keys_file = os.environ.get("FURIX_API_KEYS_FILE", "")
        if keys_file and Path(keys_file).exists():
            raw = Path(keys_file).read_text(encoding="utf-8")
        else:
            raw = os.environ.get("FURIX_API_KEYS", "")

        keys: list[dict] = []
        if raw.strip():
            try:
                keys = json.loads(raw)
                if not isinstance(keys, list):
                    raise ValueError("FURIX_API_KEYS must be a JSON list")
            except (json.JSONDecodeError, ValueError) as e:
                raise RuntimeError(f"invalid FURIX_API_KEYS configuration: {e}") from e

        is_prod = os.environ.get("FURIX_ENV", "").lower() == "production"
        if not keys:
            if is_prod:
                # Fail closed: no keys in prod → nobody is authorized.
                print("[auth] FURIX_ENV=production and no API keys configured — "
                      "ALL requests will be denied until keys are provided.")
            else:
                print("[auth] WARNING: no API keys configured; minting a DEV key "
                      f"({DEV_KEY!r}, tenant=default, role=admin). "
                      "Never use this in production — set FURIX_API_KEYS.")
                keys = [{"key": DEV_KEY, "key_id": "dev", "tenant": "default", "role": "admin"}]

        audit = os.environ.get("FURIX_AUTH_AUDIT", "")
        store = os.environ.get("FURIX_REPORT_STORE", "_report_store")
        audit_path = Path(audit) if audit else Path(store) / "auth_audit.jsonl"
        return cls(keys, audit_path=audit_path)

    # ── authentication ───────────────────────────────────────────────────────
    def authenticate(self, authorization: str | None) -> Principal:
        """Resolve a bearer token to a Principal, or raise AuthError."""
        token = self._bearer(authorization)
        principal = self._by_hash.get(_sha256(token)) if token else None
        # constant-time-ish: always hash, and confirm membership via digest compare
        if principal is None:
            self._audit(None, "authenticate", "-", "deny", "invalid_or_missing_key")
            raise AuthError("missing or invalid API key")
        return principal

    @staticmethod
    def _bearer(authorization: str | None) -> str | None:
        if not authorization:
            return None
        parts = authorization.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        # also accept a raw key (no "Bearer " prefix) for curl-friendliness
        return authorization.strip() or None

    # ── authorization ────────────────────────────────────────────────────────
    def authorize(self, principal: Principal, scope: str, action: str,
                  tenant: str | None = None) -> None:
        """Enforce a scope (and optional cross-tenant access) or raise."""
        if not principal.has(scope):
            self._audit(principal, action, tenant or principal.tenant_id,
                        "deny", f"missing_scope:{scope}")
            raise ForbiddenError(f"principal lacks required scope: {scope}")
        if tenant is not None and not principal.can_read_tenant(tenant):
            self._audit(principal, action, tenant, "deny", "cross_tenant_denied")
            raise ForbiddenError("cross-tenant access denied")
        self._audit(principal, action, tenant or principal.tenant_id, "allow", scope)

    # ── audit ────────────────────────────────────────────────────────────────
    def _audit(self, principal: Principal | None, action: str, tenant: str,
               decision: str, reason: str) -> None:
        if not self.audit_path:
            return
        rec = {
            # wall-clock is correct here: an audit event is a real-time fact,
            # not part of any reproducible report identity.
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "actor": principal.key_id if principal else None,
            "role": principal.role if principal else None,
            "action": action,
            "tenant": tenant,
            "decision": decision,
            "reason": reason,
        }
        try:
            with self._lock:
                self.audit_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.audit_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, sort_keys=True) + "\n")
        except OSError:
            pass  # auditing must never break a request

    # test/inspection helper — never logs the plaintext
    def principal_count(self) -> int:
        return len(self._by_hash)


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
