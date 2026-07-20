"""
test_attestation.py
===================
Strict signed-attestation schema (Wave-N): required fields, HMAC signature,
future-date rejection — an invalid attestation can only ever yield
MANUAL_PENDING, never PASS.

    python3 -m compliance_reporting.test_attestation
"""

from __future__ import annotations

from .attestation import (
    AttestationKeyRing,
    INVALID,
    VERIFIED,
    make_attestation,
    sign_attestation,
    verify_attestation,
)
from .fixtures import demo_batch, demo_config_snapshot
from .manual_evidence import evaluate_manual
from .registry import FrameworkRegistry
from .report_builder import build_report

_RING = AttestationKeyRing({"attest-key-1": "s3cret-signing-key"})
_REG = FrameworkRegistry.from_snapshot()
_GEN = "2026-07-19T12:00:00+00:00"


def _att(**over):
    base = dict(spec_id="MAN-PENTEST", attester="ciso@acme",
               attested_at="2026-03-01T00:00:00+00:00", evidence_ref="PT-2026",
               statement="pentest completed", tenant="acme", scope="prod",
               key_id="attest-key-1", keyring=_RING)
    base.update(over)
    return make_attestation(**base)


# ── signature + schema ────────────────────────────────────────────────────────
def test_valid_signed_attestation_verifies():
    att = _att()
    status, reasons = verify_attestation(att, _RING, tenant="acme", as_of=_GEN)
    assert status == VERIFIED and reasons == []


def test_missing_field_is_invalid():
    att = _att()
    del att["evidence_ref"]
    status, reasons = verify_attestation(att, _RING, tenant="acme", as_of=_GEN)
    assert status == INVALID and any("missing fields" in r for r in reasons)


def test_tampered_statement_breaks_signature():
    att = _att()
    att["statement"] = "actually we didn't do it"   # signature no longer matches
    status, reasons = verify_attestation(att, _RING, tenant="acme", as_of=_GEN)
    assert status == INVALID and any("signature" in r for r in reasons)


def test_future_dated_is_invalid():
    att = _att(attested_at="2027-01-01T00:00:00+00:00")
    status, reasons = verify_attestation(att, _RING, tenant="acme", as_of=_GEN)
    assert status == INVALID and any("future" in r for r in reasons)


def test_tenant_mismatch_is_invalid():
    att = _att(tenant="acme")
    status, reasons = verify_attestation(att, _RING, tenant="globex", as_of=_GEN)
    assert status == INVALID and any("tenant" in r for r in reasons)


def test_unknown_key_is_invalid():
    att = _att()
    att["key_id"] = "no-such-key"
    status, reasons = verify_attestation(att, _RING, tenant="acme", as_of=_GEN)
    assert status == INVALID and any("key_id" in r for r in reasons)


# ── evaluate_manual strictness ────────────────────────────────────────────────
def test_valid_attestation_passes_control():
    results = {r["spec_id"]: r for r in evaluate_manual([_att()], as_of=_GEN,
                                                        keyring=_RING, tenant="acme")}
    r = results["MAN-PENTEST"]
    assert r["status"] == "pass" and r["evidence"][0]["verification_status"] == "verified"


def test_invalid_attestation_is_manual_pending_not_pass():
    tampered = _att()
    tampered["statement"] = "forged"
    results = {r["spec_id"]: r for r in evaluate_manual([tampered], as_of=_GEN,
                                                        keyring=_RING, tenant="acme")}
    r = results["MAN-PENTEST"]
    assert r["status"] == "manual_pending" and r["status_reason"] == "attestation_invalid"


def test_future_dated_attestation_cannot_pass_in_report():
    future = _att(attested_at="2027-06-01T00:00:00+00:00")
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN,
                     config_snapshot=demo_config_snapshot(), attestations=[future],
                     attestation_keyring=_RING, tenant="acme", config_as_of=_GEN)
    by_id = {c["control_id"]: c for c in r["controls"]}
    assert by_id["Control 18"]["status"] != "compliant"   # future pentest → not compliant


def test_signed_attestation_makes_control_compliant_in_report():
    atts = [_att(spec_id=s, evidence_ref=f"E-{s}") for s in
            ("MAN-EMAIL-BROWSER", "MAN-SEC-TRAINING", "MAN-INCIDENT-EXERCISE", "MAN-PENTEST")]
    r = build_report(demo_batch(), registry=_REG, generated_at=_GEN,
                     config_snapshot=demo_config_snapshot(), attestations=atts,
                     attestation_keyring=_RING, tenant="acme", config_as_of=_GEN)
    by_id = {c["control_id"]: c for c in r["controls"]}
    for cid in ("Control 9", "Control 14", "Control 17", "Control 18"):
        assert by_id[cid]["status"] == "compliant", (cid, by_id[cid]["status"])


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
    print(f"\n{len(tests) - failed}/{len(tests)} attestation tests passed")
    sys.exit(1 if failed else 0)
