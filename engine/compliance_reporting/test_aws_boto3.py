"""
test_aws_boto3.py
=================
The live boto3 AWS collector client (Wave-G), driven against a boto3.Session-
shaped STUB — no network, no botocore. Proves STS role assumption, pagination,
independent OU-tree population counting, throttling→TransientError, permission
denial reporting, and that the real adapter drives the whole collection
framework (snapshot + mandatory signed manifest + independent reconciliation).

    python3 -m compliance_reporting.test_aws_boto3
"""

from __future__ import annotations

from .aws_boto3 import Boto3AwsClient
from .collectors import AwsOrgIamCollector, RetryPolicy, TransientError, verify_manifest
from .connectors import parse_snapshot

_NOW = "2026-07-19T12:00:00+00:00"


# ── boto3-shaped stubs ────────────────────────────────────────────────────────
class _AwsError(Exception):
    def __init__(self, code: str):
        self.response = {"Error": {"Code": code}}
        super().__init__(code)


class _StubOrg:
    def __init__(self, accounts, ou_tree, *, throttle_first=0, deny=()):
        self._accounts = accounts        # [{"Id","Name","Status"}]
        self._ou = ou_tree               # {"roots":[], "accounts_for":{}, "ous_for":{}}
        self._throttle = throttle_first
        self._deny = set(deny)
        self._page = 2

    def _guard(self, api):
        if api in self._deny:
            raise _AwsError("AccessDenied")

    def list_accounts(self, NextToken=None, MaxResults=None):
        self._guard("organizations:ListAccounts")
        if self._throttle > 0:
            self._throttle -= 1
            raise _AwsError("Throttling")
        start = int(NextToken) if NextToken else 0
        chunk = self._accounts[start:start + self._page]
        nxt = str(start + self._page) if start + self._page < len(self._accounts) else None
        return {"Accounts": chunk, "NextToken": nxt}

    def list_roots(self):
        self._guard("organizations:ListRoots")
        return {"Roots": [{"Id": r} for r in self._ou["roots"]]}

    def list_accounts_for_parent(self, ParentId, NextToken=None):
        return {"Accounts": self._ou["accounts_for"].get(ParentId, [])}

    def list_organizational_units_for_parent(self, ParentId, NextToken=None):
        return {"OrganizationalUnits": self._ou["ous_for"].get(ParentId, [])}


class _StubIam:
    def __init__(self, *, mfa=1, users_keys=None):
        self._mfa = mfa
        self._uk = users_keys or {}      # {username: [ {AccessKeyId, Status, CreateDate} ]}

    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": self._mfa}}

    def list_users(self, Marker=None):
        return {"Users": [{"UserName": u} for u in self._uk]}

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": self._uk.get(UserName, [])}


class _StubSts:
    def __init__(self):
        self.calls = []

    def assume_role(self, RoleArn, RoleSessionName, ExternalId=None):
        self.calls.append({"RoleArn": RoleArn, "ExternalId": ExternalId})
        return {"Credentials": {"AccessKeyId": "AK", "SecretAccessKey": "SK", "SessionToken": "TK"}}


class StubSession:
    def __init__(self, org, iam, sts):
        self._org, self._iam, self._sts = org, iam, sts
        self.iam_kwargs = []

    def client(self, name, **kw):
        if name == "organizations":
            return self._org
        if name == "sts":
            return self._sts
        if name == "iam":
            self.iam_kwargs.append(kw)
            return self._iam
        raise AssertionError(f"unexpected client {name}")


_ACCOUNTS = [{"Id": f"{i:012d}", "Name": f"acct{i}", "Status": "ACTIVE"} for i in range(1, 6)]
_OU_TREE = {
    "roots": ["r-root"],
    "ous_for": {"r-root": [{"Id": "ou-a"}, {"Id": "ou-b"}]},
    "accounts_for": {
        "r-root": [{"Id": "000000000001", "Status": "ACTIVE"}],
        "ou-a": [{"Id": "000000000002", "Status": "ACTIVE"}, {"Id": "000000000003", "Status": "ACTIVE"}],
        "ou-b": [{"Id": "000000000004", "Status": "ACTIVE"}, {"Id": "000000000005", "Status": "ACTIVE"}],
    },
}


def _client(**org_over):
    org = _StubOrg(_ACCOUNTS, _OU_TREE, **org_over)
    iam = _StubIam(mfa=1, users_keys={
        "svc": [{"AccessKeyId": "AKIA1", "Status": "Active", "CreateDate": "2026-06-01T00:00:00+00:00"}]})
    return Boto3AwsClient(session=StubSession(org, iam, _StubSts()), external_id="ext-123")


# ── unit behaviour ────────────────────────────────────────────────────────────
def test_list_accounts_paginates_and_filters_active():
    c = _client()
    p1 = c.list_accounts(None)
    assert len(p1.items) == 2 and p1.next_cursor == "2"
    assert p1.items[0]["account_id"] == "000000000001"


def test_assume_role_carries_external_id():
    c = _client()
    c.get_account_summary("000000000002")
    sts = c._session._sts
    assert any(call["ExternalId"] == "ext-123" for call in sts.calls)
    assert any("role/OrganizationAccountAccessRole" in call["RoleArn"] for call in sts.calls)


def test_account_summary_maps_root_mfa():
    assert _client().get_account_summary("000000000001") == {"root_mfa_enabled": True}
    org = _StubOrg(_ACCOUNTS, _OU_TREE)
    c = Boto3AwsClient(session=StubSession(org, _StubIam(mfa=0), _StubSts()))
    assert c.get_account_summary("x") == {"root_mfa_enabled": False}


def test_access_keys_aggregated_with_age():
    keys = _client().list_access_keys("000000000001", None)
    assert keys.items[0]["key_id"] == "AKIA1" and keys.items[0]["status"] == "active"
    assert keys.items[0]["age_days"] >= 0


def test_independent_account_count_walks_the_ou_tree():
    # 1 (root) + 2 (ou-a) + 2 (ou-b) = 5, counted independently of list_accounts
    assert _client().independent_account_count() == 5


def test_throttling_becomes_transient_error():
    c = _client(throttle_first=1)
    try:
        c.list_accounts(None)
        raise AssertionError("throttling not surfaced")
    except TransientError:
        pass


def test_check_permissions_reports_denied():
    c = _client(deny=["organizations:ListAccounts"])
    missing = c.check_permissions()
    assert "organizations:ListAccounts" in missing


# ── the real adapter drives the whole collection framework ────────────────────
def test_boto3_client_drives_the_collector_end_to_end():
    collector = AwsOrgIamCollector(
        client=_client(), tenant="acme", signing_secret="collect-secret",
        retry=RetryPolicy(max_attempts=4, base_delay=0.0))
    out = collector.collect(collected_at=_NOW)
    snap = parse_snapshot(out["snapshot"])
    assert snap.observed_count("aws_account") == 5
    m = out["manifest"]
    # independent reconciliation basis + mandatory signature verify
    assert m["reconciliation_basis"] == "independent-ou-tree"
    assert m["reconciled"] is True and m["expected_accounts"] == 5
    assert m["signature"] and verify_manifest(m, "collect-secret")


def test_retry_policy_recovers_from_throttling_via_collector():
    collector = AwsOrgIamCollector(
        client=_client(throttle_first=2), tenant="acme", signing_secret="s",
        retry=RetryPolicy(max_attempts=5, base_delay=0.0))
    out = collector.collect(collected_at=_NOW)
    assert parse_snapshot(out["snapshot"]).observed_count("aws_account") == 5


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
    print(f"\n{len(tests) - failed}/{len(tests)} aws-boto3 tests passed")
    sys.exit(1 if failed else 0)
