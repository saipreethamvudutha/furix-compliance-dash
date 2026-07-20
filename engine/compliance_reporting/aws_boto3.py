"""
aws_boto3.py
============
The REAL boto3-backed AWS collector client (Wave-G). It implements the exact
`AwsClient` interface the collection framework (`collectors.py`) drives, so it is
a **drop-in** for the deterministic `FakeAwsClient` — the hard machinery
(pagination, retry, reconciliation, signed manifest) is unchanged; this module
only supplies real provider reads.

Design
------
* **STS role assumption.** The Organizations API is read from the management
  account (optionally via an assumed management role), and each member account's
  IAM posture is read by assuming a per-account role (default
  `OrganizationAccountAccessRole`) with an optional ExternalId — the standard
  cross-account read pattern. No long-lived member credentials are held.
* **Independent population.** `independent_account_count()` counts ACTIVE
  accounts by traversing the Organizations **OU tree** (`list_roots` →
  `list_accounts_for_parent` / `list_organizational_units_for_parent`), a
  DIFFERENT path than the flat `list_accounts` used to build the snapshot — so
  the framework's reconciliation is meaningful, not self-referential.
* **Dependency-injected + duck-typed errors.** boto3 is imported lazily (only to
  build a default session). Every provider call is classified by the AWS error
  *response shape* (`e.response["Error"]["Code"]`), not by importing botocore's
  exception class — so a `boto3.Session`-shaped stub drives the whole adapter in
  tests with no network and no botocore dependency. Throttling → `TransientError`
  (retried); access-denied is surfaced by `check_permissions()`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .collectors import Page, TransientError

_THROTTLE_CODES = {"Throttling", "ThrottlingException", "TooManyRequestsException",
                   "RequestLimitExceeded", "ThrottledException"}
_DENY_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
               "AuthorizationError"}

DEFAULT_MEMBER_ROLE = "OrganizationAccountAccessRole"


def _boto3_session(region: str):
    """Build a default boto3 Session (lazy import; clear error if boto3 absent)."""
    try:
        import boto3  # noqa: PLC0415
    except ImportError as e:  # pragma: no cover - depends on optional dep
        raise RuntimeError(
            "boto3 is required for the live AWS collector (pip install boto3), or inject a "
            "session=... for testing") from e
    return boto3.Session(region_name=region)


def _error_code(exc: Exception) -> str | None:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code")
    return None


def _age_days(create_date: Any) -> int:
    """Age in days from an AWS CreateDate (datetime or ISO-8601 string)."""
    if create_date is None:
        return 0
    if isinstance(create_date, str):
        try:
            create_date = datetime.fromisoformat(create_date.replace("Z", "+00:00"))
        except ValueError:
            return 0
    if create_date.tzinfo is None:
        create_date = create_date.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - create_date).days)


@dataclass
class Boto3AwsClient:
    """Live AWS Organizations + IAM reader implementing the AwsClient interface."""

    member_role_name: str = DEFAULT_MEMBER_ROLE
    org_role_arn: str | None = None       # optional management-account role to assume
    external_id: str | None = None
    region: str = "us-east-1"
    session: Any = None                   # inject a boto3.Session (or stub) for tests
    role_session_name: str = "furix-collector"
    _session: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self._session = self.session or _boto3_session(self.region)

    # ── error-classified call ─────────────────────────────────────────────────
    def _call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001
            if _error_code(e) in _THROTTLE_CODES:
                raise TransientError(str(e)) from e   # let the RetryPolicy back off
            raise

    # ── credential plumbing ───────────────────────────────────────────────────
    def _assume(self, role_arn: str) -> dict[str, str]:
        sts = self._session.client("sts")
        params: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": self.role_session_name}
        if self.external_id:
            params["ExternalId"] = self.external_id
        creds = self._call(sts.assume_role, **params)["Credentials"]
        return {"aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"]}

    def _org(self):
        kw = self._assume(self.org_role_arn) if self.org_role_arn else {}
        return self._session.client("organizations", **kw)

    def _iam(self, account_id: str):
        arn = f"arn:aws:iam::{account_id}:role/{self.member_role_name}"
        return self._session.client("iam", **self._assume(arn))

    # ── AwsClient interface ───────────────────────────────────────────────────
    def check_permissions(self) -> list[str]:
        """Probe the org-level reads we depend on; return any that are denied."""
        missing: list[str] = []
        org = self._org()
        for api, fn, kwargs in (
            ("organizations:ListAccounts", org.list_accounts, {"MaxResults": 1}),
            ("organizations:ListRoots", org.list_roots, {}),
        ):
            try:
                self._call(fn, **kwargs)
            except Exception as e:  # noqa: BLE001
                if _error_code(e) in _DENY_CODES:
                    missing.append(api)
                else:
                    raise
        return missing

    def list_accounts(self, cursor: str | None) -> Page:
        org = self._org()
        kwargs = {"NextToken": cursor} if cursor else {}
        resp = self._call(org.list_accounts, **kwargs)
        items = [{"account_id": a["Id"], "name": a.get("Name", "")}
                 for a in resp.get("Accounts", []) if a.get("Status", "ACTIVE") == "ACTIVE"]
        return Page(items=items, next_cursor=resp.get("NextToken"))

    def independent_account_count(self) -> int:
        """Count ACTIVE accounts by traversing the OU tree (independent path)."""
        org = self._org()
        count = 0
        stack = [r["Id"] for r in self._call(org.list_roots).get("Roots", [])]
        while stack:
            parent = stack.pop()
            marker: str | None = None
            while True:
                kw = {"ParentId": parent}
                if marker:
                    kw["NextToken"] = marker
                resp = self._call(org.list_accounts_for_parent, **kw)
                count += sum(1 for a in resp.get("Accounts", [])
                             if a.get("Status", "ACTIVE") == "ACTIVE")
                marker = resp.get("NextToken")
                if not marker:
                    break
            marker = None
            while True:
                kw = {"ParentId": parent}
                if marker:
                    kw["NextToken"] = marker
                resp = self._call(org.list_organizational_units_for_parent, **kw)
                stack.extend(ou["Id"] for ou in resp.get("OrganizationalUnits", []))
                marker = resp.get("NextToken")
                if not marker:
                    break
        return count

    def get_account_summary(self, account_id: str) -> dict[str, Any]:
        iam = self._iam(account_id)
        summary = self._call(iam.get_account_summary).get("SummaryMap", {})
        return {"root_mfa_enabled": bool(summary.get("AccountMFAEnabled", 0))}

    def list_access_keys(self, account_id: str, cursor: str | None) -> Page:
        """Aggregate every IAM user's access keys in the account (single page)."""
        iam = self._iam(account_id)
        keys: list[dict[str, Any]] = []
        user_marker: str | None = None
        while True:
            kw = {"Marker": user_marker} if user_marker else {}
            resp = self._call(iam.list_users, **kw)
            for user in resp.get("Users", []):
                meta = self._call(iam.list_access_keys, UserName=user["UserName"])
                for k in meta.get("AccessKeyMetadata", []):
                    keys.append({
                        "key_id": k["AccessKeyId"],
                        "status": str(k.get("Status", "Active")).lower(),
                        "age_days": _age_days(k.get("CreateDate")),
                    })
            user_marker = resp.get("Marker")
            if not user_marker:
                break
        return Page(items=keys, next_cursor=None)
