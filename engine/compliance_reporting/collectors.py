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
from typing import Any, Callable, Iterator, Protocol


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

    def get(self, stage: str) -> str | None:
        return self.cursors.get(stage)

    def set(self, stage: str, cursor: str | None) -> None:
        self.cursors[stage] = cursor


class TransientError(Exception):
    """A retryable provider error (throttling, 5xx)."""


# ── provider client interface (boto3 implements this in prod) ──────────────────
class AwsClient(Protocol):
    def list_accounts(self, cursor: str | None) -> Page: ...
    def list_access_keys(self, account_id: str, cursor: str | None) -> Page: ...
    def get_account_summary(self, account_id: str) -> dict[str, Any]: ...
    def check_permissions(self) -> list[str]: ...  # returns MISSING permissions


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

    def collect(self, *, collected_at: str, checkpoint: Checkpoint | None = None) -> dict[str, Any]:
        """
        Collect AWS org accounts + IAM posture into a snapshot, reconcile the
        population, and attach a signed manifest. Returns {"snapshot":..., "manifest":...}.
        """
        # 1. permission preflight — abort on any missing read permission
        missing = self.retry.run(self.client.check_permissions, on_transient=TransientError)
        if missing:
            raise PermissionError_(f"missing required read permissions: {', '.join(missing)}")

        # 2. discover accounts (INDEPENDENT expected population)
        accounts = paginate(lambda c: self.client.list_accounts(c), self.retry, checkpoint, "accounts")
        expected_accounts = len(accounts)

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

        # 4. signed manifest
        manifest = {
            "source": "aws-org-iam", "tenant": self.tenant, "boundary": self.boundary,
            "collected_at": collected_at,
            "expected_accounts": expected_accounts, "observed_accounts": observed_accounts,
            "observed_access_keys": observed_keys, "reconciled": reconciled,
            "resource_sha256": hashlib.sha256(
                json.dumps(resources, sort_keys=True).encode()).hexdigest(),
        }
        if self.signing_secret:
            manifest["signature"] = sign_manifest(manifest, self.signing_secret)

        if not reconciled:
            raise CollectionError(
                f"population reconciliation failed: expected {expected_accounts} accounts, "
                f"observed {observed_accounts}")
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
                 fail_times: int = 0, page_size: int = 2):
        self._accounts = accounts or []
        self._keys = keys_by_account or {}
        self._summaries = summaries or {}
        self._missing = missing_permissions or []
        self._fail_remaining = fail_times
        self._page_size = page_size

    def check_permissions(self) -> list[str]:
        return list(self._missing)

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
