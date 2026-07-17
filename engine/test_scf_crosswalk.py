"""
test_scf_crosswalk.py
=====================
Unit tests for the SCF-JSON crosswalk derivation. The parser tests run anywhere;
the integration test runs against the REAL scf-full-2026.2.json when present
(env FURIX_SCF_JSON, or the default research-folder path), else it self-skips.

    python3 test_scf_crosswalk.py
"""

from __future__ import annotations

import os
from pathlib import Path

import scf_crosswalk as X

_DEFAULT_SCF = "/Users/preetham/compliance research/SCF-2026-2/JSON/scf-full-2026.2.json"
_SCF_PATH = os.environ.get("FURIX_SCF_JSON", _DEFAULT_SCF)


# ── parser unit tests (the format gotchas the JSON introduced) ────────────────
def test_cis_control_handles_bare_and_dotted():
    assert X.cis_control("1") == "Control 1"        # bare top-level ref (JSON has these)
    assert X.cis_control("1.1") == "Control 1"
    assert X.cis_control("13.9") == "Control 13"
    assert X.cis_control("2.4") == "Control 2"
    assert X.cis_control("x") is None


def test_pci_requirement_extracts_parent():
    assert X.pci_requirement("6.3.2") == "Req 6"
    assert X.pci_requirement("9.5.1.1") == "Req 9"
    assert X.pci_requirement("11.2") == "Req 11"
    assert X.pci_requirement("") is None


def test_hipaa_section_handles_section_sign_prefix():
    # the JSON prefixes with "§ " — re.match would fail; we search.
    assert X.hipaa_section("§ 164.308(a)(7)(ii)(E)") == "164.308"
    assert X.hipaa_section("164.312(a)(2)(ii)") == "164.312"
    assert X.hipaa_section("§ 164.310(d)(1)") == "164.310"
    assert X.hipaa_section("no section here") is None


def test_nist_keeps_subcategories_drops_categories():
    raw = "ID.AM\nID.AM-01\nID.AM-02\nGV.SC-04\nGV"
    assert X.nist_subcategories(raw) == ["ID.AM-01", "ID.AM-02", "GV.SC-04"]


def test_derive_on_synthetic_controls():
    controls = [
        {"scf_id": "AST-01", "mappings": {
            X.CIS_KEY: "6\n6.3",
            X.NIST_KEY: "PR.AA\nPR.AA-01\nPR.AA-05",
            X.PCI_KEY: "8.3\n7.2.1",
            X.HIPAA_SEC_KEY: "§ 164.308(a)(4)",
        }},
        {"scf_id": "AST-02", "mappings": {
            X.CIS_KEY: "3.1",
            X.NIST_KEY: "PR.DS-01",
            X.PCI_KEY: "3.5",
        }},
    ]
    cw = X.derive_crosswalks(controls)
    assert cw.cis_to_nist["Control 6"] == ["PR.AA-01", "PR.AA-05"]
    assert cw.cis_to_pci["Control 6"] == ["Req 7", "Req 8"]      # 7.2.1→Req7, 8.3→Req8, sorted
    assert cw.cis_to_pci["Control 3"] == ["Req 3"]
    assert cw.hipaa_to_nist["164.308"] == ["PR.AA-01", "PR.AA-05"]
    assert cw.cis_to_hipaa["Control 6"] == ["164.308"]          # CIS 6 ↔ HIPAA via AST-01
    # provenance records which SCF control produced an edge
    assert cw.cis_nist_provenance[("Control 6", "PR.AA-01")] == ["AST-01"]


# ── integration test against the real SCF JSON ────────────────────────────────
def test_real_scf_json_derivation():
    if not Path(_SCF_PATH).exists():
        print(f"  (skipped: SCF JSON not found at {_SCF_PATH}; set FURIX_SCF_JSON)")
        return
    cw = X.derive_from_file(_SCF_PATH)

    # non-empty crosswalks
    assert cw.cis_to_nist and cw.hipaa_to_nist and cw.cis_to_pci

    # every CIS key is "Control N"; every PCI value is "Req N"
    for k in cw.cis_to_nist:
        assert k.startswith("Control "), k
    for reqs in cw.cis_to_pci.values():
        for r in reqs:
            assert r.startswith("Req "), r

    # every NIST value is a valid subcategory; every HIPAA key is 164.NNN
    for subs in cw.cis_to_nist.values():
        for s in subs:
            assert X._NIST_SUBCAT_RE.match(s), s
    for h in cw.hipaa_to_nist:
        assert h.startswith("164."), h

    # spot-checks: access-control CIS controls should reach PR.AA and PCI Req 8
    assert "Control 6" in cw.cis_to_nist
    assert any(s.startswith("PR.AA") for s in cw.cis_to_nist["Control 6"]), cw.cis_to_nist["Control 6"]
    assert "Control 6" in cw.cis_to_pci
    assert "Req 8" in cw.cis_to_pci["Control 6"], cw.cis_to_pci["Control 6"]

    # HIPAA technical + administrative safeguards both present
    assert "164.312" in cw.hipaa_to_nist and "164.308" in cw.hipaa_to_nist

    # CIS→HIPAA derived (registry needs this direction); Control 6 reaches a section
    assert cw.cis_to_hipaa and "Control 6" in cw.cis_to_hipaa
    for secs in cw.cis_to_hipaa.values():
        for s in secs:
            assert s.startswith("164."), s

    print(f"  real SCF: cis_to_nist={len(cw.cis_to_nist)} controls, "
          f"hipaa_to_nist={len(cw.hipaa_to_nist)} sections, "
          f"cis_to_pci={len(cw.cis_to_pci)} controls | edges "
          f"cis-nist={cw.stats['cis_nist_edges']} hipaa-nist={cw.stats['hipaa_nist_edges']} "
          f"cis-pci={cw.stats['cis_pci_edges']}")
    print(f"  Control 6 → NIST {cw.cis_to_nist['Control 6']}")
    print(f"  Control 6 → PCI  {cw.cis_to_pci['Control 6']}")


if __name__ == "__main__":
    import sys, traceback
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
    print(f"\n{len(tests) - failed}/{len(tests)} scf_crosswalk tests passed")
    sys.exit(1 if failed else 0)
