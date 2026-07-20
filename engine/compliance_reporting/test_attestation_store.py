"""
test_attestation_store.py
=========================
Tenant-scoped attestation submission/approval store (Wave-F). Fail-closed:
unverifiable submissions are rejected, cross-tenant submissions are rejected,
and only APPROVED attestations feed a report.

    python3 -m compliance_reporting.test_attestation_store
"""

from __future__ import annotations

import tempfile

from .attestation import AttestationKeyRing, make_attestation
from .attestation_store import AttestationError, AttestationStore

_RING = AttestationKeyRing({"k1": "secret-one"})
_GEN = "2026-07-19T12:00:00+00:00"


def _att(tenant="acme", spec_id="MAN-PENTEST", attested_at="2026-03-01T00:00:00+00:00"):
    return make_attestation(spec_id=spec_id, attester="ciso@acme", statement="pentest done",
                            evidence_ref="PT-2026", attested_at=attested_at, tenant=tenant,
                            scope="prod", key_id="k1", keyring=_RING)


def _store():
    return AttestationStore(tempfile.mkdtemp(prefix="furix_att_"))


def test_submit_then_approve_makes_it_available():
    s = _store()
    rec = s.submit(_att(), tenant="acme", keyring=_RING, submitted_by="ciso@acme",
                   submitted_at=_GEN, as_of=_GEN)
    assert rec["status"] == "submitted"
    assert rec["verification"]["status"] == "verified"
    # not yet available to a report
    assert s.approved_attestations("acme") == []
    s.approve(rec["att_id"], tenant="acme", approved_by="admin@acme", decided_at=_GEN)
    approved = s.approved_attestations("acme")
    assert len(approved) == 1 and approved[0]["spec_id"] == "MAN-PENTEST"


def test_submitted_but_unapproved_never_feeds_report():
    s = _store()
    s.submit(_att(), tenant="acme", keyring=_RING, submitted_by="ciso@acme",
             submitted_at=_GEN, as_of=_GEN)
    assert s.approved_attestations("acme") == []  # fail-closed: pending ≠ usable


def test_unverifiable_submission_is_rejected():
    s = _store()
    att = _att()
    att["signature"] = "deadbeef"  # tamper
    try:
        s.submit(att, tenant="acme", keyring=_RING, submitted_by="x", submitted_at=_GEN, as_of=_GEN)
        assert False, "expected AttestationError"
    except AttestationError as e:
        assert "verification" in str(e)


def test_cross_tenant_submission_is_rejected():
    s = _store()
    att = _att(tenant="globex")  # attestation says globex
    try:
        s.submit(att, tenant="acme", keyring=_RING, submitted_by="x", submitted_at=_GEN, as_of=_GEN)
        assert False, "expected AttestationError"
    except AttestationError as e:
        assert "tenant" in str(e)


def test_tenant_isolation_of_listing():
    s = _store()
    a = s.submit(_att(tenant="acme"), tenant="acme", keyring=_RING,
                 submitted_by="x", submitted_at=_GEN, as_of=_GEN)
    s.approve(a["att_id"], tenant="acme", approved_by="admin", decided_at=_GEN)
    # globex sees nothing
    assert s.list("globex") == []
    assert s.approved_attestations("globex") == []


def test_reject_blocks_report_use():
    s = _store()
    rec = s.submit(_att(), tenant="acme", keyring=_RING, submitted_by="x",
                   submitted_at=_GEN, as_of=_GEN)
    s.reject(rec["att_id"], tenant="acme", rejected_by="admin", decided_at=_GEN, reason="bad evidence")
    assert s.get("acme", rec["att_id"])["status"] == "rejected"
    assert s.approved_attestations("acme") == []
    # cannot approve a rejected one
    try:
        s.approve(rec["att_id"], tenant="acme", approved_by="admin", decided_at=_GEN)
        assert False, "expected AttestationError"
    except AttestationError:
        pass


def test_resubmit_is_idempotent():
    s = _store()
    r1 = s.submit(_att(), tenant="acme", keyring=_RING, submitted_by="x", submitted_at=_GEN, as_of=_GEN)
    r2 = s.submit(_att(), tenant="acme", keyring=_RING, submitted_by="y", submitted_at=_GEN, as_of=_GEN)
    assert r1["att_id"] == r2["att_id"]
    assert len(s.list("acme")) == 1


def test_double_approve_is_illegal():
    s = _store()
    rec = s.submit(_att(), tenant="acme", keyring=_RING, submitted_by="x", submitted_at=_GEN, as_of=_GEN)
    s.approve(rec["att_id"], tenant="acme", approved_by="admin", decided_at=_GEN)
    try:
        s.approve(rec["att_id"], tenant="acme", approved_by="admin", decided_at=_GEN)
        assert False, "expected AttestationError"
    except AttestationError:
        pass


# ── two-person rule (segregation of duty) ─────────────────────────────────────
def test_submitter_cannot_self_approve():
    s = _store()
    rec = s.submit(_att(), tenant="acme", keyring=_RING, submitted_by="ciso@acme",
                   submitted_at=_GEN, as_of=_GEN)
    try:
        s.approve(rec["att_id"], tenant="acme", approved_by="ciso@acme", decided_at=_GEN)
        assert False, "expected AttestationError (self-approval)"
    except AttestationError as e:
        assert "self-approval" in str(e)
    # still pending → cannot back a report
    assert s.approved_attestations("acme") == []


def test_quorum_requires_two_distinct_approvers():
    s = AttestationStore(tempfile.mkdtemp(prefix="furix_att2_"), required_approvals=2)
    rec = s.submit(_att(), tenant="acme", keyring=_RING, submitted_by="ciso@acme",
                   submitted_at=_GEN, as_of=_GEN)
    # first approval: still pending (needs 2 distinct)
    r1 = s.approve(rec["att_id"], tenant="acme", approved_by="grc@acme", decided_at=_GEN)
    assert r1["status"] == "submitted" and r1["approvals_count"] == 1
    assert s.approved_attestations("acme") == []
    # same approver again → rejected
    try:
        s.approve(rec["att_id"], tenant="acme", approved_by="grc@acme", decided_at=_GEN)
        assert False, "expected AttestationError (duplicate approver)"
    except AttestationError:
        pass
    # a second DISTINCT approver reaches quorum → APPROVED
    r2 = s.approve(rec["att_id"], tenant="acme", approved_by="ciso2@acme", decided_at=_GEN)
    assert r2["status"] == "approved" and r2["approvals_count"] == 2
    assert len(s.approved_attestations("acme")) == 1


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
    print(f"\n{len(tests) - failed}/{len(tests)} attestation-store tests passed")
    sys.exit(1 if failed else 0)
