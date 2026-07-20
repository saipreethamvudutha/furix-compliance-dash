"""
test_integration.py
====================
End-to-end FastAPI integration tests (Wave-N #6) via TestClient: anonymous
access, role boundaries, tenant isolation, risk acceptance, OSCAL export, and
malformed-input handling. Skips cleanly if FastAPI/TestClient is unavailable.

    python3 -m api.test_integration
"""

from __future__ import annotations

import os
import tempfile


def _skip(msg: str) -> None:
    print(f"  (skipped: {msg})")


def _make_client():
    """Configure env, seed a tenant store, and build a TestClient over the real app."""
    store_root = tempfile.mkdtemp(prefix="furix_int_")
    os.environ["FURIX_API_KEYS"] = (
        '[{"key":"admin-k","key_id":"a","tenant":"acme","role":"admin"},'
        '{"key":"analyst-k","key_id":"b","tenant":"acme","role":"analyst"},'
        '{"key":"auditor-k","key_id":"c","tenant":"acme","role":"auditor"},'
        '{"key":"globex-k","key_id":"d","tenant":"globex","role":"admin"}]'
    )
    os.environ["FURIX_REPORT_STORE"] = store_root
    os.environ["FURIX_ENV"] = "development"

    # seed the acme tenant with a real report + findings
    from compliance_reporting.fixtures import demo_batch, demo_config_snapshot
    from compliance_reporting.registry import FrameworkRegistry
    from compliance_reporting.report_builder import build_report
    from compliance_reporting.history import ReportStore
    from compliance_reporting.exceptions import FindingStore, new_finding_id
    acme_root = os.path.join(store_root, "tenants", "acme")
    store = ReportStore(acme_root)
    report = build_report(demo_batch(), registry=FrameworkRegistry.from_snapshot(),
                          generated_at="2026-07-19T12:00:00+00:00",
                          config_snapshot=demo_config_snapshot())
    store.save(report, batch=demo_batch())
    fs = FindingStore(acme_root)
    for c in report["controls"]:
        if c["status"] == "at_risk":
            fid = new_finding_id("acme", c["control_id"], "cis_v8", report["report_id"])
            fs.open_finding(fid, control_id=c["control_id"], framework_id="cis_v8",
                            severity=c.get("worst_severity", "medium"), actor="seed",
                            occurred_at="2026-07-19T09:00:00+00:00",
                            discovered_report=report["report_id"])

    from fastapi.testclient import TestClient
    import importlib
    from api import main as main_mod
    importlib.reload(main_mod)
    return TestClient(main_mod.app), report


_H = {
    "admin": {"Authorization": "Bearer admin-k"},
    "analyst": {"Authorization": "Bearer analyst-k"},
    "auditor": {"Authorization": "Bearer auditor-k"},
    "globex": {"Authorization": "Bearer globex-k"},
}


# ── anonymous / bad credentials ───────────────────────────────────────────────
def test_anonymous_access_denied():
    c, _ = _make_client()
    for path in ("/api/summary", "/api/frameworks", "/api/findings", "/api/reports"):
        assert c.get(path).status_code == 401, path
    assert c.post("/api/ingest", json={"text": "x"}).status_code == 401
    # health + readiness are the only open endpoints
    assert c.get("/api/health").status_code == 200


def test_readiness_endpoint_is_open_and_reports_checks():
    c, _ = _make_client()
    for path in ("/readyz", "/api/readyz"):
        r = c.get(path)
        assert r.status_code == 200, (path, r.status_code)  # dev is ready
        body = r.json()
        assert body["ready"] is True
        assert body["checks"]["report_store_writable"] is True


def test_bad_key_denied():
    c, _ = _make_client()
    assert c.get("/api/summary", headers={"Authorization": "Bearer wrong"}).status_code == 401


# ── role boundaries ───────────────────────────────────────────────────────────
def test_auditor_can_read_and_export_but_not_ingest():
    c, _ = _make_client()
    assert c.get("/api/summary", headers=_H["auditor"]).status_code == 200
    assert c.get("/api/oscal?kind=poam", headers=_H["auditor"]).status_code == 200
    assert c.get("/api/audit/export", headers=_H["auditor"]).status_code == 200
    # auditor lacks ingest scope
    assert c.post("/api/ingest", json={"text": "x"}, headers=_H["auditor"]).status_code == 403


def test_analyst_can_ingest_scope_but_not_export():
    c, _ = _make_client()
    assert c.get("/api/summary", headers=_H["analyst"]).status_code == 200
    # analyst lacks export scope
    assert c.get("/api/oscal", headers=_H["analyst"]).status_code == 403
    assert c.get("/api/audit/export", headers=_H["analyst"]).status_code == 403


# ── tenant isolation ──────────────────────────────────────────────────────────
def test_tenant_isolation():
    c, _ = _make_client()
    # acme analyst cannot cross to globex
    assert c.get("/api/summary?tenant=globex", headers=_H["analyst"]).status_code == 403
    # globex admin sees its OWN (empty) tenant, not acme's data
    assert c.get("/api/summary", headers=_H["globex"]).status_code == 404  # no reports in globex


# ── risk acceptance authority ─────────────────────────────────────────────────
def test_risk_acceptance_requires_admin():
    c, report = _make_client()
    from compliance_reporting.exceptions import new_finding_id
    fid = new_finding_id("acme", "Control 5", "cis_v8", report["report_id"])
    body = {"action": "accept_risk", "occurred_at": "2026-07-19T10:00:00+00:00",
            "payload": {"exception": {"approver": "ciso", "rationale": "legacy",
                                      "compensating_control": "iso", "expiry": "2026-12-01T00:00:00+00:00"}}}
    # analyst may transition but NOT accept risk
    assert c.post(f"/api/findings/{fid}/transition", json=body, headers=_H["analyst"]).status_code == 403
    # admin may
    assert c.post(f"/api/findings/{fid}/transition", json=body, headers=_H["admin"]).status_code == 200


# ── OSCAL export is schema-valid ──────────────────────────────────────────────
def test_oscal_export_is_schema_validated():
    c, _ = _make_client()
    r = c.get("/api/oscal?kind=poam", headers=_H["admin"])
    assert r.status_code == 200
    body = r.json()
    # jsonschema present in this env → validation actually ran and passed against
    # the OFFICIAL NIST OSCAL 1.2.1 schema
    assert body["validation"]["ran"] is True and body["validation"]["ok"] is True
    assert "official" in body["validation"]["note"], body["validation"]["note"]
    assert "nist/" in body["validation"]["schema"], body["validation"]["schema"]
    pkg = c.get("/api/audit/export", headers=_H["admin"]).json()
    assert pkg["oscal"]["validation_ok"] is True


# ── attestation submission / approval (Wave-F) ────────────────────────────────
def _demo_att(tenant="acme"):
    from compliance_reporting.attestation import make_attestation
    from compliance_reporting.fixtures import demo_attestation_keyring
    return make_attestation(spec_id="MAN-PENTEST", attester="ciso@acme",
                            statement="pentest done", evidence_ref="PT-2026",
                            attested_at="2026-03-01T00:00:00+00:00", tenant=tenant,
                            scope="prod", key_id="furix-demo-key",
                            keyring=demo_attestation_keyring())


def test_attestation_submit_requires_ingest_scope():
    c, _ = _make_client()
    body = {"attestation": _demo_att(), "as_of": "2026-07-19T12:00:00+00:00"}
    # auditor lacks ingest scope
    assert c.post("/api/attestations", json=body, headers=_H["auditor"]).status_code == 403
    # analyst may submit
    r = c.post("/api/attestations", json=body, headers=_H["analyst"])
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "submitted"


def test_attestation_submit_rejects_unverifiable():
    c, _ = _make_client()
    bad = _demo_att()
    bad["signature"] = "deadbeef"
    r = c.post("/api/attestations", json={"attestation": bad, "as_of": "2026-07-19T12:00:00+00:00"},
               headers=_H["analyst"])
    assert r.status_code == 400


def test_attestation_approval_requires_admin_and_gates_availability():
    c, _ = _make_client()
    body = {"attestation": _demo_att(), "as_of": "2026-07-19T12:00:00+00:00"}
    sub = c.post("/api/attestations", json=body, headers=_H["analyst"]).json()
    att_id = sub["att_id"]
    dec = {"decided_at": "2026-07-19T13:00:00+00:00", "reason": "reviewed"}
    # analyst cannot approve (not admin)
    assert c.post(f"/api/attestations/{att_id}/approve", json=dec,
                  headers=_H["analyst"]).status_code == 403
    # before approval it is not in the approved list
    listed = c.get("/api/attestations?status=approved", headers=_H["auditor"]).json()
    assert listed == []
    # admin approves
    assert c.post(f"/api/attestations/{att_id}/approve", json=dec,
                  headers=_H["admin"]).status_code == 200
    approved = c.get("/api/attestations?status=approved", headers=_H["auditor"]).json()
    assert len(approved) == 1 and approved[0]["status"] == "approved"


def test_attestation_self_approval_is_forbidden():
    c, _ = _make_client()
    body = {"attestation": _demo_att(), "as_of": "2026-07-19T12:00:00+00:00"}
    # admin submits AND tries to approve their own → two-person rule blocks it (400)
    sub = c.post("/api/attestations", json=body, headers=_H["admin"]).json()
    dec = {"decided_at": "2026-07-19T13:00:00+00:00"}
    r = c.post(f"/api/attestations/{sub['att_id']}/approve", json=dec, headers=_H["admin"])
    assert r.status_code == 400 and "self-approval" in r.json()["detail"]
    # still not available to a report
    assert c.get("/api/attestations?status=approved", headers=_H["auditor"]).json() == []


def test_attestation_tenant_isolation():
    c, _ = _make_client()
    body = {"attestation": _demo_att("acme"), "as_of": "2026-07-19T12:00:00+00:00"}
    sub = c.post("/api/attestations", json=body, headers=_H["analyst"]).json()
    c.post(f"/api/attestations/{sub['att_id']}/approve",
           json={"decided_at": "2026-07-19T13:00:00+00:00"}, headers=_H["admin"])
    # globex admin sees NONE of acme's attestations
    assert c.get("/api/attestations", headers=_H["globex"]).json() == []


# ── connectors: scheduled collection + health (Wave-G) ────────────────────────
def test_connector_register_run_and_health():
    c, _ = _make_client()
    reg = {"connector_id": "demo1", "kind": "demo-aws", "schedule_seconds": 3600}
    # analyst may not register (admin authority)
    assert c.post("/api/connectors", json=reg, headers=_H["analyst"]).status_code == 403
    r = c.post("/api/connectors", json=reg, headers=_H["admin"])
    assert r.status_code == 201, r.text
    assert r.json()["health"] == "unknown"  # never run yet

    # any authenticated role can read connector health
    listed = c.get("/api/connectors", headers=_H["auditor"]).json()
    assert len(listed) == 1 and listed[0]["connector_id"] == "demo1"

    # admin runs it → healthy (signed manifest + reconciled)
    run = c.post("/api/connectors/demo1/run", headers=_H["admin"])
    assert run.status_code == 200, run.text
    body = run.json()
    assert body["last_status"] == "ok" and body["last_signed"] and body["last_reconciled"]
    assert c.get("/api/connectors", headers=_H["admin"]).json()[0]["health"] == "healthy"


def test_connector_run_requires_admin_and_known_id():
    c, _ = _make_client()
    c.post("/api/connectors", json={"connector_id": "demo2", "kind": "demo-aws"}, headers=_H["admin"])
    # analyst cannot run
    assert c.post("/api/connectors/demo2/run", headers=_H["analyst"]).status_code == 403
    # unknown connector
    assert c.post("/api/connectors/nope/run", headers=_H["admin"]).status_code == 404


def test_connector_tenant_isolation():
    c, _ = _make_client()
    c.post("/api/connectors", json={"connector_id": "acme-only", "kind": "demo-aws"}, headers=_H["admin"])
    # globex admin sees its own (empty) connector list
    assert c.get("/api/connectors", headers=_H["globex"]).json() == []


# ── unified posture-run pipeline (Wave-H) ─────────────────────────────────────
def test_posture_run_links_every_stage_via_api():
    c, _ = _make_client()
    c.post("/api/connectors", json={"connector_id": "pr1", "kind": "demo-aws"}, headers=_H["admin"])
    # analyst may not run a posture run
    assert c.post("/api/connectors/pr1/posture-run", headers=_H["analyst"]).status_code == 403
    r = c.post("/api/connectors/pr1/posture-run", headers=_H["admin"])
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["verified"] is True and run["report_id"]
    assert run["collection"]["signed"] and run["collection"]["reconciled"]
    assert len(run["evidence"]["snapshot_sha256"]) == 64
    assert run["evaluation"]["assertion_total"] >= 1
    assert len(run["findings"]) == len(run["affected_controls"])

    # the run is listable + retrievable, and readable by an auditor
    listed = c.get("/api/posture-runs", headers=_H["auditor"]).json()
    assert any(x["run_id"] == run["run_id"] for x in listed)
    got = c.get(f"/api/posture-runs/{run['run_id']}", headers=_H["auditor"])
    assert got.status_code == 200 and got.json()["report_id"] == run["report_id"]
    # the linked report is now the tenant's latest, and OSCAL export schema-validates
    assert c.get("/api/audit/export", headers=_H["admin"]).json()["oscal"]["validation_ok"] is True


def test_demo_connectors_blocked_in_production():
    c, _ = _make_client()
    os.environ["FURIX_ENV"] = "production"
    try:
        r = c.post("/api/connectors", json={"connector_id": "demo-prod", "kind": "demo-aws"},
                   headers=_H["admin"])
        assert r.status_code == 400 and "disabled in production" in r.json()["detail"]
    finally:
        os.environ["FURIX_ENV"] = "development"


def test_posture_run_records_data_mode():
    c, _ = _make_client()
    c.post("/api/connectors", json={"connector_id": "pr-dm", "kind": "demo-aws"}, headers=_H["admin"])
    run = c.post("/api/connectors/pr-dm/posture-run", headers=_H["admin"]).json()
    assert run["data_mode"] == "demo"


def test_posture_run_tenant_isolation():
    c, _ = _make_client()
    c.post("/api/connectors", json={"connector_id": "pr2", "kind": "demo-aws"}, headers=_H["admin"])
    c.post("/api/connectors/pr2/posture-run", headers=_H["admin"])
    # globex admin sees none of acme's posture runs
    assert c.get("/api/posture-runs", headers=_H["globex"]).json() == []


# ── malformed input handling ──────────────────────────────────────────────────
def test_malformed_requests_are_rejected_cleanly():
    c, _ = _make_client()
    # empty ingest
    assert c.post("/api/ingest", json={"text": "   "}, headers=_H["admin"]).status_code == 400
    # empty config snapshot
    assert c.post("/api/ingest-config", json={"snapshot": {}}, headers=_H["admin"]).status_code == 400
    # unknown finding transition
    r = c.post("/api/findings/nope/transition",
               json={"action": "start", "occurred_at": "t"}, headers=_H["admin"])
    assert r.status_code in (404, 422)


def _run():
    try:
        import fastapi  # noqa: F401
        from fastapi.testclient import TestClient  # noqa: F401
    except Exception:
        _skip("fastapi/testclient not available")
        return 0, 0
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    import traceback
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            passed += 1
            print(f"  PASS  {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    return passed, failed


if __name__ == "__main__":
    import sys
    p, f = _run()
    print(f"\n{p}/{p + f} integration tests passed" if (p + f) else "  (integration suite skipped)")
    sys.exit(1 if f else 0)
