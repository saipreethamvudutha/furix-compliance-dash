"""
scim.py
=======
SCIM 2.0 user provisioning (Wave-I / Epic 6). Lets an enterprise IdP (Okta,
Entra, …) provision and DEPROVISION Furix users automatically, so access is
governed centrally: when someone leaves, the IdP `DELETE`s (deactivates) them and
they lose access immediately.

A minimal but conformant SCIM `Users` store: create, get, list (with the common
`userName eq "x"` filter), replace (PUT), patch (`active` toggle), and delete
(deactivate). Tenant-scoped; backed by SQLite. Resources are shaped as SCIM 2.0
`User` objects. Role/tenant are carried as a custom attribute for the app's RBAC.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from threading import Lock
from typing import Any

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
_CUSTOM = "urn:furix:params:scim:schemas:extension:2.0:User"


class ScimError(Exception):
    def __init__(self, message: str, status: int = 400):
        self.status = status
        super().__init__(message)


class ScimUserStore:
    def __init__(self, root: Path | str, tenant: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.tenant = tenant
        self.path = self.root / "scim_users.db"
        self._lock = Lock()
        self._conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS scim_users (
                   id TEXT NOT NULL,
                   tenant TEXT NOT NULL,
                   user_name TEXT NOT NULL,
                   external_id TEXT,
                   active INTEGER NOT NULL DEFAULT 1,
                   resource TEXT NOT NULL,
                   created TEXT NOT NULL,
                   modified TEXT NOT NULL,
                   PRIMARY KEY (tenant, id)
               )"""
        )
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS scim_username ON scim_users(tenant, user_name)")
        self._conn.commit()

    # ── shaping ──────────────────────────────────────────────────────────────────
    def _to_scim(self, r: sqlite3.Row) -> dict[str, Any]:
        res = json.loads(r["resource"])
        res.update({
            "schemas": [USER_SCHEMA],
            "id": r["id"], "userName": r["user_name"], "externalId": r["external_id"],
            "active": bool(r["active"]),
            "meta": {"resourceType": "User", "created": r["created"], "lastModified": r["modified"]},
        })
        return res

    def _get_locked(self, user_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM scim_users WHERE tenant=? AND id=?", (self.tenant, user_id)).fetchone()

    # ── operations ───────────────────────────────────────────────────────────────
    def create(self, resource: dict[str, Any], *, now: str) -> dict[str, Any]:
        user_name = resource.get("userName")
        if not user_name:
            raise ScimError("userName is required", 400)
        user_id = uuid.uuid5(uuid.NAMESPACE_URL, f"{self.tenant}|{user_name}").hex
        body = {
            "userName": user_name, "externalId": resource.get("externalId"),
            "name": resource.get("name", {}), "emails": resource.get("emails", []),
            "displayName": resource.get("displayName"),
            _CUSTOM: {"role": (resource.get(_CUSTOM, {}) or {}).get("role", "auditor"),
                      "tenant": self.tenant},
        }
        with self._lock, self._conn:
            if self._get_locked(user_id):
                raise ScimError("user already exists", 409)
            self._conn.execute(
                "INSERT INTO scim_users (id, tenant, user_name, external_id, active, resource, "
                "created, modified) VALUES (?,?,?,?,?,?,?,?)",
                (user_id, self.tenant, user_name, resource.get("externalId"),
                 1 if resource.get("active", True) else 0, json.dumps(body), now, now),
            )
        return self.get(user_id)

    def get(self, user_id: str) -> dict[str, Any]:
        with self._lock:
            r = self._get_locked(user_id)
        if not r:
            raise ScimError("user not found", 404)
        return self._to_scim(r)

    def list(self, *, user_name: str | None = None, start: int = 1,
             count: int = 100) -> dict[str, Any]:
        with self._lock:
            if user_name:
                rows = self._conn.execute(
                    "SELECT * FROM scim_users WHERE tenant=? AND user_name=?",
                    (self.tenant, user_name)).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM scim_users WHERE tenant=? ORDER BY user_name", (self.tenant,)).fetchall()
        resources = [self._to_scim(r) for r in rows][start - 1: start - 1 + count]
        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(rows), "startIndex": start, "itemsPerPage": len(resources),
            "Resources": resources,
        }

    def replace(self, user_id: str, resource: dict[str, Any], *, now: str) -> dict[str, Any]:
        with self._lock, self._conn:
            r = self._get_locked(user_id)
            if not r:
                raise ScimError("user not found", 404)
            body = json.loads(r["resource"])
            for k in ("name", "emails", "displayName", "externalId"):
                if k in resource:
                    body[k] = resource[k]
            if _CUSTOM in resource:
                body[_CUSTOM] = {**body.get(_CUSTOM, {}), **resource[_CUSTOM]}
            active = 1 if resource.get("active", bool(r["active"])) else 0
            self._conn.execute(
                "UPDATE scim_users SET resource=?, external_id=?, active=?, modified=? "
                "WHERE tenant=? AND id=?",
                (json.dumps(body), resource.get("externalId", r["external_id"]), active, now,
                 self.tenant, user_id))
        return self.get(user_id)

    def set_active(self, user_id: str, active: bool, *, now: str) -> dict[str, Any]:
        """The core deprovisioning path (SCIM PATCH active=false / DELETE)."""
        with self._lock, self._conn:
            if not self._get_locked(user_id):
                raise ScimError("user not found", 404)
            self._conn.execute(
                "UPDATE scim_users SET active=?, modified=? WHERE tenant=? AND id=?",
                (1 if active else 0, now, self.tenant, user_id))
        return self.get(user_id)

    def is_active(self, user_name: str) -> bool:
        """Used by the app to honour IdP deprovisioning at login/authz time."""
        with self._lock:
            r = self._conn.execute(
                "SELECT active FROM scim_users WHERE tenant=? AND user_name=?",
                (self.tenant, user_name)).fetchone()
        return bool(r["active"]) if r else False
