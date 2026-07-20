"""
test_audit_period.py
===================
Audit-period workflow (Wave-I / Epic 5): periods + evidence requests +
reviewer sign-off + immutable snapshot + freeze/reopen + downloadable ZIP.

    python3 -m api.test_audit_period
"""

from __future__ import annotations

import io
import tempfile
import zipfile

from compliance_reporting.audit_period import AuditPeriodError, AuditPeriodStore
from compliance_reporting.evidence import EvidenceStore
from compliance_reporting.history import ReportStore
from compliance_reporting.registry import FrameworkRegistry

from . import service

_REG = FrameworkRegistry.from_snapshot()
_NOW = "2026-07-19T12:00:00+00:00"


def _seeded_store():
    """A store with a real posture-run report so sign-off can build a package."""
    store = ReportStore(tempfile.mkdtemp(prefix="furix_audit_"))
    out = service.collect_snapshot("acme", "demo-aws", {}, "s")
    service.run_posture(store, tenant="acme", snapshot=out["snapshot"], manifest=out["manifest"],
                        connector_id="demo-aws", registry=_REG, occurred_at=_NOW, data_mode="demo")
    return store


def _period(store):
    return service.create_audit_period(store, "acme", name="Q3 2026 CIS",
                                       boundary="prod AWS · CIS v8", start_date="2026-07-01",
                                       end_date="2026-09-30", actor="admin", at=_NOW)


# ── lifecycle ─────────────────────────────────────────────────────────────────
def test_create_and_evidence_requests():
    store = _seeded_store()
    p = _period(store)
    assert p["status"] == "open" and p["frozen"] is False
    p = service.add_evidence_request(store, "acme", p["period_id"], control_id="Control 6",
                                     note="Show MFA policy", actor="auditor", at=_NOW)
    assert len(p["evidence_requests"]) == 1
    req_id = p["evidence_requests"][0]["req_id"]
    p = service.fulfill_evidence_request(store, "acme", p["period_id"], req_id,
                                         evidence_ref="furix-evidence://abc", actor="grc", at=_NOW)
    assert p["evidence_requests"][0]["status"] == "provided"


def test_signoff_freezes_with_immutable_snapshot():
    store = _seeded_store()
    p = _period(store)
    signed = service.sign_off_audit_period(store, "acme", p["period_id"], reviewer="ciso", at=_NOW)
    assert signed["status"] == "signed_off" and signed["frozen"] is True
    so = signed["signoffs"][0]
    assert so["reviewer"] == "ciso" and len(so["snapshot_sha256"]) == 64
    # the snapshot is retained immutably in the evidence store
    assert EvidenceStore(store.root).verify_object(so["snapshot_sha256"])


def test_frozen_period_rejects_edits_until_reopened():
    store = _seeded_store()
    p = _period(store)
    service.sign_off_audit_period(store, "acme", p["period_id"], reviewer="ciso", at=_NOW)
    # frozen → evidence requests refused
    try:
        service.add_evidence_request(store, "acme", p["period_id"], control_id="Control 1",
                                     note="x", actor="a", at=_NOW)
        raise AssertionError("edited a frozen period")
    except ValueError:
        pass
    # reopen (admin) → editable again, prior snapshot retained
    re = service.reopen_audit_period(store, "acme", p["period_id"], actor="admin", at=_NOW,
                                     reason="late evidence")
    assert re["status"] == "reopened" and re["frozen"] is False
    assert len(re["signoffs"]) == 1  # historical signed snapshot preserved
    # now editable
    service.add_evidence_request(store, "acme", p["period_id"], control_id="Control 1",
                                 note="x", actor="a", at=_NOW)


def test_reopen_requires_signed_off():
    store = _seeded_store()
    p = _period(store)
    try:
        service.reopen_audit_period(store, "acme", p["period_id"], actor="admin", at=_NOW, reason="x")
        raise AssertionError("reopened a non-frozen period")
    except ValueError:
        pass


# ── downloadable ZIP ──────────────────────────────────────────────────────────
def test_zip_package_contents():
    store = _seeded_store()
    p = _period(store)
    data = service.build_audit_zip(store, "acme", p["period_id"])
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = set(zf.namelist())
    assert {"audit-manifest.json", "oscal-assessment-results.json", "oscal-poam.json",
            "findings.json", "control-workspace.json"} <= names
    import json
    manifest = json.loads(zf.read("audit-manifest.json"))
    assert manifest["oscal_validation_ok"] is True
    assert manifest["package_source"] == "live"


def test_signed_zip_is_reconstructed_from_the_immutable_snapshot():
    store = _seeded_store()
    p = _period(store)
    service.sign_off_audit_period(store, "acme", p["period_id"], reviewer="ciso", at=_NOW)
    data = service.build_audit_zip(store, "acme", p["period_id"])
    import json
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(data)).read("audit-manifest.json"))
    assert manifest["package_source"] == "signed-snapshot"
    assert manifest["frozen"] is True and manifest["signoffs"]


# ── tenant isolation ──────────────────────────────────────────────────────────
def test_tenant_isolation():
    store = _seeded_store()
    _period(store)
    assert service.list_audit_periods(store, "globex") == []
    assert AuditPeriodStore(store.root).get("globex", "period-xyz") is None


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
    print(f"\n{len(tests) - failed}/{len(tests)} audit-period tests passed")
    sys.exit(1 if failed else 0)
