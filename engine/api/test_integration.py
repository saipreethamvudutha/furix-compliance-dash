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
    # health is the only open endpoint
    assert c.get("/api/health").status_code == 200


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
    # jsonschema present in this env → validation actually ran and passed
    assert body["validation"]["ran"] is True and body["validation"]["ok"] is True
    pkg = c.get("/api/audit/export", headers=_H["admin"]).json()
    assert pkg["oscal"]["validation_ok"] is True


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
