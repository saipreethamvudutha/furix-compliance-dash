"""
test_auth.py
============
Auth, authorization and tenancy for the API (FUR-CMP-004). These tests exercise
the security core directly (no FastAPI needed), plus the endpoint wiring via
TestClient when FastAPI is importable.

    python3 -m api.test_auth
"""

from __future__ import annotations

import tempfile

from .auth import (
    AuthError,
    AuthRegistry,
    ForbiddenError,
    SCOPE_EXPORT,
    SCOPE_INGEST,
    SCOPE_READ,
)
from .tenancy import TenantStores, valid_tenant

_KEYS = [
    {"key": "admin-key", "key_id": "a", "tenant": "acme", "role": "admin"},
    {"key": "analyst-key", "key_id": "b", "tenant": "acme", "role": "analyst"},
    {"key": "auditor-key", "key_id": "c", "tenant": "acme", "role": "auditor"},
    {"key": "globex-key", "key_id": "d", "tenant": "globex", "role": "analyst"},
    {"key": "mssp-key", "key_id": "e", "tenant": "mssp0", "role": "mssp"},
]


def _reg():
    return AuthRegistry(_KEYS, audit_path=tempfile.mktemp(prefix="furix_audit_"))


# ── authentication ────────────────────────────────────────────────────────────
def test_valid_bearer_authenticates():
    reg = _reg()
    p = reg.authenticate("Bearer admin-key")
    assert p.key_id == "a" and p.tenant_id == "acme" and p.role == "admin"


def test_raw_key_without_bearer_prefix_works():
    assert _reg().authenticate("analyst-key").key_id == "b"


def test_missing_and_bad_keys_are_rejected():
    reg = _reg()
    for bad in (None, "", "Bearer ", "Bearer nope", "totally-wrong"):
        try:
            reg.authenticate(bad)
            raise AssertionError(f"accepted bad credential: {bad!r}")
        except AuthError:
            pass


# ── authorization (scopes) ────────────────────────────────────────────────────
def test_analyst_can_ingest_and_read_but_not_export():
    reg = _reg()
    analyst = reg.authenticate("analyst-key")
    reg.authorize(analyst, SCOPE_READ, "read")     # ok
    reg.authorize(analyst, SCOPE_INGEST, "ingest")  # ok
    try:
        reg.authorize(analyst, SCOPE_EXPORT, "export")
        raise AssertionError("analyst should not have export scope")
    except ForbiddenError:
        pass


def test_auditor_can_read_and_export_but_not_ingest():
    reg = _reg()
    auditor = reg.authenticate("auditor-key")
    reg.authorize(auditor, SCOPE_READ, "read")
    reg.authorize(auditor, SCOPE_EXPORT, "export")
    try:
        reg.authorize(auditor, SCOPE_INGEST, "ingest")
        raise AssertionError("auditor should not ingest")
    except ForbiddenError:
        pass


def test_admin_has_every_scope():
    reg = _reg()
    admin = reg.authenticate("admin-key")
    for scope in (SCOPE_READ, SCOPE_INGEST, SCOPE_EXPORT):
        reg.authorize(admin, scope, "x")


# ── tenancy ───────────────────────────────────────────────────────────────────
def test_cross_tenant_denied_for_normal_role():
    reg = _reg()
    analyst = reg.authenticate("analyst-key")   # tenant acme
    assert analyst.can_read_tenant("acme")
    assert not analyst.can_read_tenant("globex")
    try:
        reg.authorize(analyst, SCOPE_READ, "read", tenant="globex")
        raise AssertionError("analyst read another tenant")
    except ForbiddenError:
        pass


def test_mssp_and_admin_can_cross_tenant():
    reg = _reg()
    mssp = reg.authenticate("mssp-key")
    admin = reg.authenticate("admin-key")
    assert mssp.can_read_tenant("acme") and mssp.can_read_tenant("globex")
    assert admin.can_read_tenant("anyone")
    reg.authorize(mssp, SCOPE_READ, "read", tenant="globex")  # allowed


def test_tenant_stores_are_isolated():
    from compliance_reporting.fixtures import demo_batch
    from compliance_reporting.registry import FrameworkRegistry
    from compliance_reporting.report_builder import build_report

    stores = TenantStores(tempfile.mkdtemp(prefix="furix_tenant_"))
    reg = FrameworkRegistry.from_snapshot()
    report = build_report(demo_batch(), registry=reg, generated_at="2026-07-19T00:00:00+00:00")

    acme = stores.for_tenant("acme")
    globex = stores.for_tenant("globex")
    acme.save(report, batch=demo_batch())

    assert len(acme.entries()) == 1
    assert len(globex.entries()) == 0        # physically separate subtree
    assert acme.reports_dir != globex.reports_dir


def test_tenant_id_validation_blocks_traversal():
    stores = TenantStores(tempfile.mkdtemp(prefix="furix_tenant_"))
    assert valid_tenant("acme-1") and valid_tenant("globex_2")
    for bad in ("../etc", "a/b", "ACME", "", "x" * 100, ".hidden"):
        assert not valid_tenant(bad), bad
        try:
            stores.for_tenant(bad)
            raise AssertionError(f"accepted bad tenant id: {bad!r}")
        except ValueError:
            pass


def test_audit_log_records_allow_and_deny():
    import json
    from pathlib import Path

    audit = tempfile.mktemp(prefix="furix_audit_")
    reg = AuthRegistry(_KEYS, audit_path=audit)
    analyst = reg.authenticate("analyst-key")
    reg.authorize(analyst, SCOPE_READ, "read")            # allow
    try:
        reg.authorize(analyst, SCOPE_EXPORT, "export")     # deny
    except ForbiddenError:
        pass
    lines = [json.loads(x) for x in Path(audit).read_text().splitlines()]
    decisions = {(r["action"], r["decision"]) for r in lines}
    assert ("read", "allow") in decisions
    assert ("export", "deny") in decisions
    assert all("key" not in r for r in lines)  # never logs the secret


def test_prod_without_keys_mints_nothing(monkeypatch=None):
    import os
    old_env = os.environ.get("FURIX_ENV")
    old_keys = os.environ.get("FURIX_API_KEYS")
    try:
        os.environ["FURIX_ENV"] = "production"
        os.environ.pop("FURIX_API_KEYS", None)
        reg = AuthRegistry.from_env()
        assert reg.principal_count() == 0     # fail closed: no implicit trust
        try:
            reg.authenticate("furix-dev-key")
            raise AssertionError("dev key accepted in production")
        except AuthError:
            pass
    finally:
        if old_env is not None:
            os.environ["FURIX_ENV"] = old_env
        else:
            os.environ.pop("FURIX_ENV", None)
        if old_keys is not None:
            os.environ["FURIX_API_KEYS"] = old_keys


# ── endpoint wiring (only when FastAPI is importable) ─────────────────────────
def test_endpoints_require_auth_when_fastapi_present():
    try:
        import os
        os.environ["FURIX_API_KEYS"] = (
            '[{"key":"t-admin","key_id":"ta","tenant":"acme","role":"admin"}]'
        )
        os.environ["FURIX_REPORT_STORE"] = tempfile.mkdtemp(prefix="furix_ep_")
        from fastapi.testclient import TestClient  # noqa: PLC0415
        import importlib
        from api import main as main_mod  # noqa: PLC0415
        importlib.reload(main_mod)
        client = TestClient(main_mod.app)
    except Exception:
        print("  (skipped: fastapi/testclient not available here)")
        return

    # health is open
    assert client.get("/api/health").status_code == 200
    # every data endpoint is closed without a key
    assert client.get("/api/reports").status_code == 401
    assert client.get("/api/summary").status_code == 401
    assert client.post("/api/ingest", json={"text": "x"}).status_code == 401
    # a valid admin key opens reads
    h = {"Authorization": "Bearer t-admin"}
    assert client.get("/api/reports", headers=h).status_code == 200
    # security headers present
    r = client.get("/api/health")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"


# ── OIDC / JWT bearer auth (Wave 4) ───────────────────────────────────────────
def _oidc_reg():
    from .jwt_auth import OIDCConfig
    cfg = OIDCConfig(hs256_secret="test-secret", issuer="https://idp.example",
                     audience="furix", tenant_claim="tenant", role_claim="role")
    return AuthRegistry(_KEYS, audit_path=tempfile.mktemp(prefix="furix_audit_"), oidc=cfg)


def _token(claims, secret="test-secret", **over):
    from .jwt_auth import make_hs256_token
    base = {"iss": "https://idp.example", "aud": "furix", "sub": "alice",
            "tenant": "acme", "role": "analyst", "exp": 9999999999}
    base.update(claims)
    base.update(over)
    return make_hs256_token(base, secret)


def test_valid_jwt_maps_to_principal():
    reg = _oidc_reg()
    p = reg.authenticate("Bearer " + _token({}), now=1_000_000)
    assert p.tenant_id == "acme" and p.role == "analyst" and p.key_id == "alice"
    assert "reports:ingest" in p.scopes


def test_jwt_role_becomes_scopes():
    reg = _oidc_reg()
    admin = reg.authenticate("Bearer " + _token({"role": "admin"}), now=1_000_000)
    assert admin.has("admin")
    ro = reg.authenticate("Bearer " + _token({"role": "auditor"}), now=1_000_000)
    assert ro.has("reports:export") and not ro.has("reports:ingest")


def test_jwt_bad_signature_rejected():
    reg = _oidc_reg()
    forged = _token({}, secret="wrong-secret")
    try:
        reg.authenticate("Bearer " + forged, now=1_000_000)
        raise AssertionError("accepted a forged JWT")
    except AuthError:
        pass


def test_jwt_expired_rejected():
    reg = _oidc_reg()
    tok = _token({"exp": 1000})
    try:
        reg.authenticate("Bearer " + tok, now=1_000_000)
        raise AssertionError("accepted an expired JWT")
    except AuthError:
        pass


def test_jwt_issuer_and_audience_enforced():
    reg = _oidc_reg()
    for bad in ({"iss": "https://evil"}, {"aud": "someone-else"}):
        try:
            reg.authenticate("Bearer " + _token(bad), now=1_000_000)
            raise AssertionError(f"accepted JWT with {bad}")
        except AuthError:
            pass


def test_api_keys_still_work_alongside_oidc():
    reg = _oidc_reg()
    # a plain API key (not a JWT) is still accepted
    assert reg.authenticate("admin-key").role == "admin"


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
    print(f"\n{len(tests) - failed}/{len(tests)} auth tests passed")
    sys.exit(1 if failed else 0)
