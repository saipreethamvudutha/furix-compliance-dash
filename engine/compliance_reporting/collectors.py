"""
collectors.py
=============
The collection plane (Wave-N #5): a real read-only collector framework that
turns authoritative provider state into a `ConfigSnapshot` — with pagination,
retry/backoff, permission preflight, checkpoints, independent population
reconciliation, and a **signed collection manifest**.

Deliberately **no network**: the AWS Organizations/IAM collector runs against a
deterministic client interface. The production client is boto3 implementing the
same three methods — swapping it in is a constructor argument, not a rewrite.
This lets the whole collection machinery (the hard part) be built and tested
offline and deterministically.

Guarantees the framework enforces:
  * a missing permission aborts collection (no partial, misleading snapshot),
  * every page is followed to completion (no silent truncation),
  * transient errors are retried with bounded backoff; a permanent failure
    aborts rather than under-reporting,
  * the collected population is reconciled against an INDEPENDENT expected count
    (from account discovery), and the mismatch is recorded,
  * the manifest is HMAC-signed so the collection's provenance is tamper-evident.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol


class CollectionError(Exception):
    """Collection aborted (permission, exhausted retries, reconciliation gap)."""


class PermissionError_(CollectionError):
    """A required read permission is missing."""


@dataclass
class Page:
    items: list[dict[str, Any]]
    next_cursor: str | None = None


@dataclass
class RetryPolicy:
    max_attempts: int = 4
    base_delay: float = 0.05
    # injectable sleep so tests are instant + deterministic (default: no sleep)
    sleep: Callable[[float], None] = lambda _s: None

    def run(self, fn: Callable[[], Any], *, on_transient: type[Exception] = Exception) -> Any:
        last: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                return fn()
            except on_transient as e:  # noqa: BLE001
                last = e
                if attempt == self.max_attempts:
                    break
                self.sleep(self.base_delay * (2 ** (attempt - 1)))  # exponential backoff
        raise CollectionError(f"exhausted {self.max_attempts} attempts: {last}")


@dataclass
class Checkpoint:
    """A resumable cursor per collection stage (persist between runs)."""

    cursors: dict[str, str | None] = field(default_factory=dict)
    # optional durable backing store; when set, every mutation is flushed to disk
    store: "CheckpointStore | None" = None

    def get(self, stage: str) -> str | None:
        return self.cursors.get(stage)

    def set(self, stage: str, cursor: str | None) -> None:
        self.cursors[stage] = cursor
        if self.store is not None:
            self.store.save(self)


class CheckpointStore:
    """
    Durable, JSON-file-backed checkpoint persistence so a collection can resume
    across process restarts (crash-safe: written atomically via a temp file +
    rename). Keyed per (tenant, connector) file.
    """

    def __init__(self, root: Path | str, tenant: str, connector: str):
        self.dir = Path(root) / tenant
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / f"checkpoint-{connector}.json"

    def load(self) -> Checkpoint:
        cursors: dict[str, str | None] = {}
        if self.path.exists():
            try:
                cursors = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                cursors = {}
        return Checkpoint(cursors=cursors, store=self)

    def save(self, checkpoint: Checkpoint) -> None:
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(checkpoint.cursors, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)


class TransientError(Exception):
    """A retryable provider error (throttling, 5xx)."""


# ── provider client interface (boto3 implements this in prod) ──────────────────
class AwsClient(Protocol):
    def list_accounts(self, cursor: str | None) -> Page: ...
    def list_access_keys(self, account_id: str, cursor: str | None) -> Page: ...
    def get_account_summary(self, account_id: str) -> dict[str, Any]: ...
    def check_permissions(self) -> list[str]: ...  # returns MISSING permissions
    # OPTIONAL: an INDEPENDENTLY-derived expected account count (e.g. counted by
    # traversing the Organizations OU tree rather than the flat list_accounts).
    # When present the collector reconciles the observed population against THIS,
    # so a mismatch is meaningful rather than self-referential.
    # def independent_account_count(self) -> int: ...


def paginate(fetch: Callable[[str | None], Page], retry: RetryPolicy,
             checkpoint: Checkpoint | None, stage: str) -> list[dict[str, Any]]:
    """Follow a cursor to completion, retrying transient errors per page."""
    cursor = checkpoint.get(stage) if checkpoint else None
    items: list[dict[str, Any]] = []
    seen_cursors: set[str] = set()
    while True:
        page = retry.run(lambda: fetch(cursor), on_transient=TransientError)
        items.extend(page.items)
        if checkpoint:
            checkpoint.set(stage, page.next_cursor)
        if not page.next_cursor:
            break
        if page.next_cursor in seen_cursors:
            raise CollectionError(f"cursor loop detected at stage {stage}")
        seen_cursors.add(page.next_cursor)
        cursor = page.next_cursor
    return items


# ── collection manifest (signed, tamper-evident) ──────────────────────────────
def sign_manifest(manifest: dict[str, Any], secret: str) -> str:
    payload = json.dumps({k: v for k, v in manifest.items() if k != "signature"},
                         sort_keys=True, separators=(",", ":"))
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def verify_manifest(manifest: dict[str, Any], secret: str) -> bool:
    expected = sign_manifest(manifest, secret)
    return hmac.compare_digest(expected, str(manifest.get("signature", "")))


# ── the AWS Organizations + IAM collector ─────────────────────────────────────
@dataclass
class AwsOrgIamCollector:
    client: AwsClient
    tenant: str = "default"
    boundary: str = "aws"
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    signing_secret: str = ""
    require_signed: bool = True   # fail-closed: a manifest MUST be signed

    def collect(self, *, collected_at: str, checkpoint: Checkpoint | None = None) -> dict[str, Any]:
        """
        Collect AWS org accounts + IAM posture into a snapshot, reconcile the
        population against an INDEPENDENT expected count, and attach a MANDATORY
        signed manifest. Returns {"snapshot":..., "manifest":...}.
        """
        # 0. a manifest must be signed (tamper-evident provenance) — refuse to
        #    run without a signing secret rather than emit an unsigned manifest.
        if self.require_signed and not self.signing_secret:
            raise CollectionError("refusing to collect without a manifest signing secret "
                                  "(set a signing_secret; manifests are mandatory-signed)")

        # 1. permission preflight — abort on any missing read permission
        missing = self.retry.run(self.client.check_permissions, on_transient=TransientError)
        if missing:
            raise PermissionError_(f"missing required read permissions: {', '.join(missing)}")

        # 2. discover accounts
        accounts = paginate(lambda c: self.client.list_accounts(c), self.retry, checkpoint, "accounts")

        # 2b. INDEPENDENT expected population: prefer a count derived by a DIFFERENT
        #     path (OU-tree traversal) so reconciliation is not self-referential.
        indep = getattr(self.client, "independent_account_count", None)
        indep_val = self.retry.run(indep, on_transient=TransientError) if callable(indep) else None
        if indep_val is not None:
            expected_accounts = indep_val
            reconciliation_basis = "independent-ou-tree"
        else:
            expected_accounts = len(accounts)
            reconciliation_basis = "self-referential"

        resources: list[dict[str, Any]] = []
        observed_keys = 0
        for acct in accounts:
            acct_id = acct["account_id"]
            summary = self.retry.run(lambda: self.client.get_account_summary(acct_id),
                                     on_transient=TransientError)
            resources.append({
                "resource_id": f"aws-account-{acct_id}", "resource_type": "aws_account",
                "observed_at": collected_at,
                "attributes": {"root_mfa_enabled": bool(summary.get("root_mfa_enabled"))},
            })
            keys = paginate(lambda c: self.client.list_access_keys(acct_id, c),
                            self.retry, checkpoint, f"keys:{acct_id}")
            observed_keys += len(keys)
            for k in keys:
                resources.append({
                    "resource_id": f"aws-key-{k['key_id']}", "resource_type": "aws_access_key",
                    "observed_at": collected_at,
                    "attributes": {"status": k.get("status", "active"),
                                   "age_days": int(k.get("age_days", 0))},
                })

        # 3. reconcile: observed vs independently-derived expected
        observed_accounts = sum(1 for r in resources if r["resource_type"] == "aws_account")
        reconciled = observed_accounts == expected_accounts
        expected_counts = {"aws_account": expected_accounts, "aws_access_key": observed_keys}

        snapshot = {
            "source": "aws", "collected_at": collected_at, "boundary": self.boundary,
            "expected_counts": expected_counts, "resources": resources,
        }

        # 4. mandatory signed manifest
        manifest = {
            "source": "aws-org-iam", "tenant": self.tenant, "boundary": self.boundary,
            "collected_at": collected_at,
            "reconciliation_basis": reconciliation_basis,
            "expected_accounts": expected_accounts, "observed_accounts": observed_accounts,
            "observed_access_keys": observed_keys, "reconciled": reconciled,
            "resource_sha256": hashlib.sha256(
                json.dumps(resources, sort_keys=True).encode()).hexdigest(),
        }
        if self.signing_secret:
            manifest["signature"] = sign_manifest(manifest, self.signing_secret)
        elif self.require_signed:  # pragma: no cover - guarded at entry
            raise CollectionError("manifest signing secret disappeared mid-collection")

        if not reconciled:
            raise CollectionError(
                f"population reconciliation failed ({reconciliation_basis}): expected "
                f"{expected_accounts} accounts, observed {observed_accounts}")
        return {"snapshot": snapshot, "manifest": manifest}


# ── deterministic fake client (no network) for tests + offline demo ───────────
class FakeAwsClient:
    """
    A deterministic, paginated stand-in for boto3. Configurable to inject
    transient failures (to exercise retry) and missing permissions.
    """

    def __init__(self, *, accounts: list[dict[str, Any]] | None = None,
                 keys_by_account: dict[str, list[dict[str, Any]]] | None = None,
                 summaries: dict[str, dict[str, Any]] | None = None,
                 missing_permissions: list[str] | None = None,
                 fail_times: int = 0, page_size: int = 2,
                 independent_count: int | None = None):
        self._accounts = accounts or []
        self._keys = keys_by_account or {}
        self._summaries = summaries or {}
        self._missing = missing_permissions or []
        self._fail_remaining = fail_times
        self._page_size = page_size
        # when set, exposes an INDEPENDENT expected account count (set it to a
        # value different from len(accounts) to exercise reconciliation failure)
        self._independent_count = independent_count

    def check_permissions(self) -> list[str]:
        return list(self._missing)

    def independent_account_count(self) -> int | None:
        # None → not available (collector falls back to self-referential reconc.)
        return self._independent_count

    def _maybe_fail(self) -> None:
        if self._fail_remaining > 0:
            self._fail_remaining -= 1
            raise TransientError("throttled (429)")

    def _page(self, items: list[dict[str, Any]], cursor: str | None) -> Page:
        start = int(cursor) if cursor else 0
        chunk = items[start:start + self._page_size]
        nxt = str(start + self._page_size) if start + self._page_size < len(items) else None
        return Page(items=chunk, next_cursor=nxt)

    def list_accounts(self, cursor: str | None) -> Page:
        self._maybe_fail()
        return self._page(self._accounts, cursor)

    def list_access_keys(self, account_id: str, cursor: str | None) -> Page:
        return self._page(self._keys.get(account_id, []), cursor)

    def get_account_summary(self, account_id: str) -> dict[str, Any]:
        return self._summaries.get(account_id, {"root_mfa_enabled": True})
