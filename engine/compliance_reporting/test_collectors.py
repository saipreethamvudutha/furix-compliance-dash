"""
test_collectors.py
==================
The collection plane (Wave-N #5): pagination, retry/backoff, permission
preflight, checkpoints, population reconciliation, signed manifest — all
against a deterministic fake client (no network).

    python3 -m compliance_reporting.test_collectors
"""

from __future__ import annotations

from .collectors import (
    AwsOrgIamCollector,
    Checkpoint,
    CheckpointStore,
    CollectionError,
    FakeAwsClient,
    Page,
    PermissionError_,
    RetryPolicy,
    paginate,
    sign_manifest,
    verify_manifest,
)
from .config_assertions import evaluate
from .connectors import parse_snapshot

_ACCOUNTS = [{"account_id": f"{i:012d}"} for i in range(1, 6)]  # 5 accounts, page_size 2 → 3 pages
_KEYS = {"000000000001": [{"key_id": "AKIA1", "status": "active", "age_days": 30},
                          {"key_id": "AKIA2", "status": "active", "age_days": 200}]}
_SUMMARIES = {a["account_id"]: {"root_mfa_enabled": True} for a in _ACCOUNTS}
_NOW = "2026-07-19T12:00:00+00:00"


def _collector(**client_over):
    client = FakeAwsClient(accounts=_ACCOUNTS, keys_by_account=_KEYS, summaries=_SUMMARIES,
                           page_size=2, **client_over)
    return AwsOrgIamCollector(client=client, tenant="acme", signing_secret="collect-secret",
                              retry=RetryPolicy(max_attempts=4, base_delay=0.0))


# ── pagination ────────────────────────────────────────────────────────────────
def test_pagination_assembles_all_pages():
    out = _collector().collect(collected_at=_NOW)
    snap = parse_snapshot(out["snapshot"])
    assert snap.observed_count("aws_account") == 5   # all 3 pages followed
    assert snap.expected_count("aws_account") == 5


# ── retry / backoff ───────────────────────────────────────────────────────────
def test_transient_errors_are_retried():
    # fail the first 2 calls (throttling), then succeed — must still complete
    out = _collector(fail_times=2).collect(collected_at=_NOW)
    assert parse_snapshot(out["snapshot"]).observed_count("aws_account") == 5


def test_permanent_failure_aborts():
    c = FakeAwsClient(accounts=_ACCOUNTS, page_size=2, fail_times=99)
    col = AwsOrgIamCollector(client=c, signing_secret="s",
                            retry=RetryPolicy(max_attempts=3, base_delay=0.0))
    try:
        col.collect(collected_at=_NOW)
        raise AssertionError("did not abort on exhausted retries")
    except CollectionError:
        pass


# ── mandatory signed manifest (fail-closed) ───────────────────────────────────
def test_collection_refuses_without_a_signing_secret():
    c = FakeAwsClient(accounts=_ACCOUNTS, page_size=2)
    col = AwsOrgIamCollector(client=c, retry=RetryPolicy(base_delay=0.0))  # no secret
    try:
        col.collect(collected_at=_NOW)
        raise AssertionError("collected without a signing secret")
    except CollectionError as e:
        assert "signing secret" in str(e)


# ── independent population reconciliation ─────────────────────────────────────
def test_independent_count_is_used_for_reconciliation():
    out = _collector(independent_count=5).collect(collected_at=_NOW)
    m = out["manifest"]
    assert m["reconciliation_basis"] == "independent-ou-tree"
    assert m["reconciled"] is True and m["expected_accounts"] == 5


def test_independent_mismatch_aborts_collection():
    # the OU-tree says 7 accounts but we only listed 5 → reconciliation gap
    col = _collector(independent_count=7)
    try:
        col.collect(collected_at=_NOW)
        raise AssertionError("did not abort on independent reconciliation mismatch")
    except CollectionError as e:
        assert "reconciliation" in str(e) and "independent-ou-tree" in str(e)


# ── durable checkpoints ───────────────────────────────────────────────────────
def test_crash_resume_pagination_from_durable_checkpoint():
    """A collection that crashes mid-pagination resumes from the durably-persisted
    cursor — remaining pages only, no page fetched twice, no items lost/duplicated."""
    import tempfile

    root = tempfile.mkdtemp(prefix="furix_crashcp_")
    pages = [Page(items=[{"account_id": str(i)}], next_cursor=(str(i + 1) if i < 4 else None))
             for i in range(5)]  # cursors "0".."4", one item each

    fetched: list[str | None] = []
    processed: list[dict] = []          # simulates durable per-page persistence

    def make_fetch(crash_at: int | None):
        def fetch(cursor):
            idx = int(cursor) if cursor else 0
            fetched.append(cursor)
            if crash_at is not None and idx == crash_at:
                raise RuntimeError("simulated worker crash")
            processed.extend(pages[idx].items)   # persist BEFORE advancing the cursor
            return pages[idx]
        return fetch

    # run 1: crash while fetching page index 3
    cp = CheckpointStore(root, tenant="acme", connector="aws").load()
    try:
        paginate(make_fetch(crash_at=3), RetryPolicy(base_delay=0.0), cp, "accounts")
        raise AssertionError("expected the simulated crash")
    except RuntimeError:
        pass
    # the checkpoint durably advanced to the resume point (cursor "3")
    reloaded = CheckpointStore(root, tenant="acme", connector="aws").load()
    assert reloaded.get("accounts") == "3"
    pre_crash_fetched = list(fetched)
    assert pre_crash_fetched == [None, "1", "2", "3"]  # pages 0,1,2 ok; crash fetching "3"

    # run 2: resume from the persisted checkpoint → remaining pages only
    fetched.clear()
    paginate(make_fetch(crash_at=None), RetryPolicy(base_delay=0.0), reloaded, "accounts")
    assert fetched == ["3", "4"]                       # NO re-fetch of completed pages 0..2
    # every account collected exactly once across the crash boundary
    ids = [a["account_id"] for a in processed]
    assert sorted(ids) == ["0", "1", "2", "3", "4"] and len(ids) == len(set(ids))


def test_durable_checkpoint_persists_and_resumes(tmp_root=None):
    import tempfile

    from .collectors import CheckpointStore
    root = tmp_root or tempfile.mkdtemp(prefix="furix_cp_")
    store = CheckpointStore(root, tenant="acme", connector="aws-org-iam")
    cp = store.load()
    _collector().collect(collected_at=_NOW, checkpoint=cp)
    # a fresh store over the same path sees the persisted cursors
    reloaded = CheckpointStore(root, tenant="acme", connector="aws-org-iam").load()
    assert "accounts" in reloaded.cursors
    assert reloaded.get("accounts") is None  # accounts stage ran to completion


# ── permission preflight ──────────────────────────────────────────────────────
def test_missing_permission_aborts_before_collecting():
    col = _collector(missing_permissions=["organizations:ListAccounts"])
    try:
        col.collect(collected_at=_NOW)
        raise AssertionError("collected despite missing permission")
    except PermissionError_ as e:
        assert "ListAccounts" in str(e)


# ── checkpoints ───────────────────────────────────────────────────────────────
def test_checkpoint_records_cursor_progress():
    cp = Checkpoint()
    _collector().collect(collected_at=_NOW, checkpoint=cp)
    # accounts stage completed → cursor exhausted (None)
    assert "accounts" in cp.cursors and cp.get("accounts") is None


# ── reconciliation ────────────────────────────────────────────────────────────
def test_reconciliation_passes_when_complete():
    out = _collector().collect(collected_at=_NOW)
    assert out["manifest"]["reconciled"] is True
    assert out["manifest"]["expected_accounts"] == out["manifest"]["observed_accounts"] == 5


# ── signed manifest ───────────────────────────────────────────────────────────
def test_manifest_is_signed_and_verifies():
    out = _collector().collect(collected_at=_NOW)
    m = out["manifest"]
    assert m["signature"] and verify_manifest(m, "collect-secret")
    # tamper → verification fails
    m["observed_accounts"] = 999
    assert not verify_manifest(m, "collect-secret")


# ── end-to-end into the assertion engine ──────────────────────────────────────
def test_collected_snapshot_drives_config_assertions():
    out = _collector().collect(collected_at=_NOW)
    snap = parse_snapshot(out["snapshot"])
    results = {r["spec_id"]: r for r in evaluate(snap, as_of=_NOW)}
    # root MFA on all accounts → PASS; one 200-day key → CFG-AWS-KEY-ROTATION FAIL
    assert results["CFG-AWS-ROOT-MFA"]["status"] == "pass"
    assert results["CFG-AWS-KEY-ROTATION"]["status"] == "fail"


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
    print(f"\n{len(tests) - failed}/{len(tests)} collector tests passed")
    sys.exit(1 if failed else 0)
