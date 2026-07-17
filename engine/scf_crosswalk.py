"""
scf_crosswalk.py
================
Pure, dependency-free derivation of framework crosswalks from the Secure
Controls Framework machine-readable JSON (`scf-full-2026.2.json`).

This replaces the fragile column-index parsing of the SCF Excel workbook in
`phase1_scf_ingest.py`. The JSON exposes, per control, a `mappings` dict keyed
by framework name — version-proof (no column drift) and it makes PCI DSS just
another key instead of a hunted-for column.

Nothing here touches a database or the network — it's a deterministic function
from the SCF JSON to three crosswalk dicts, so it is fully unit-testable against
the real data offline. `phase1_scf_ingest.py` calls `derive_crosswalks()` and
writes the result into Postgres; the reporting layer consumes the same dicts.

Exact SCF 2026.2 mapping keys (verified against the shipped JSON):
    CIS Controls v8.1   → "CIS CSC 8.1"
    NIST CSF 2.0        → "NIST CSF 2.0"
    HIPAA Security Rule → "US HIPAA Security Rule / NIST SP 800-66 R2"
    PCI DSS 4.0.1       → "PCI DSS 4.0.1"
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# ── Exact framework keys in the SCF `mappings` dict ───────────────────────────
CIS_KEY = "CIS CSC 8.1"
NIST_KEY = "NIST CSF 2.0"
HIPAA_SEC_KEY = "US HIPAA Security Rule / NIST SP 800-66 R2"
HIPAA_ADMIN_KEY = "US HIPAA Administrative Simplification 2013"
PCI_KEY = "PCI DSS 4.0.1"

# ── Format parsers (tuned to the JSON's actual value shapes) ──────────────────
# NIST CSF 2.0 subcategory, e.g. "ID.AM-01", "PR.AA-05", "GV.SC-04".
_NIST_SUBCAT_RE = re.compile(r"^[A-Z]{2}\.[A-Z]{2}-\d{2}$")
# Leading integer of a dotted requirement id, tolerant of bare ints and
# leading whitespace: "1" / "1.1" / "13.9" / "6.3.2" → 1 / 1 / 13 / 6.
_LEADING_INT_RE = re.compile(r"^\s*(\d+)")
# HIPAA CFR section anywhere in a reference like "§ 164.308(a)(7)(ii)(E)".
# NOTE: the JSON prefixes values with "§ ", so we SEARCH (not match-at-start).
_HIPAA_SECTION_RE = re.compile(r"(164\.\d{3})")


def _split_cell(value: Any) -> list[str]:
    """Newline-separated multi-value string → clean list (blank/None → [])."""
    if value is None:
        return []
    text = str(value).strip()
    if not text:
        return []
    return [item.strip() for item in text.splitlines() if item.strip()]


def cis_control(safeguard_id: str) -> str | None:
    """
    CIS safeguard/control id → parent control string.
        "1"    → "Control 1"     (bare top-level ref — present in the JSON)
        "1.1"  → "Control 1"
        "13.9" → "Control 13"
    Returns None if no leading integer.
    """
    m = _LEADING_INT_RE.match(safeguard_id)
    return f"Control {int(m.group(1))}" if m else None


def pci_requirement(ref: str) -> str | None:
    """
    PCI DSS 4.0.1 requirement id → parent requirement string.
        "6.3.2"   → "Req 6"
        "9.5.1.1" → "Req 9"
        "11.2"    → "Req 11"
    Returns None if no leading integer.
    """
    m = _LEADING_INT_RE.match(ref)
    return f"Req {int(m.group(1))}" if m else None


def hipaa_section(cfr_ref: str) -> str | None:
    """
    HIPAA reference → top-level CFR section.
        "§ 164.308(a)(7)(ii)(E)" → "164.308"
        "164.312(a)(2)(ii)"      → "164.312"
    Returns None if no 164.NNN section is present.
    """
    m = _HIPAA_SECTION_RE.search(cfr_ref)
    return m.group(1) if m else None


def nist_subcategories(raw: Any) -> list[str]:
    """Split a NIST cell and keep only valid subcategory ids (drop categories/functions)."""
    return [x for x in _split_cell(raw) if _NIST_SUBCAT_RE.match(x)]


def _ctrl_num(label: str) -> int:
    m = re.search(r"\d+", label)
    return int(m.group()) if m else 0


# ── Load ──────────────────────────────────────────────────────────────────────
def load_scf_controls(path: str | Path) -> list[dict]:
    """Load the `controls` array from scf-full-*.json."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    controls = data.get("controls")
    if not isinstance(controls, list):
        raise ValueError(f"{path}: expected a top-level 'controls' array")
    return controls


# ── Derive ────────────────────────────────────────────────────────────────────
@dataclass
class Crosswalks:
    """
    Aggregated crosswalk dicts (what the runtime consumes) plus provenance edges
    (what the DB tables store) and stats (for verification).
    """
    cis_to_nist: dict[str, list[str]]
    hipaa_to_nist: dict[str, list[str]]
    cis_to_pci: dict[str, list[str]]
    cis_to_hipaa: dict[str, list[str]]   # CIS control → HIPAA CFR sections (for the reporting registry)
    # provenance: edge (left, right) -> sorted list of contributing SCF ids
    cis_nist_provenance: dict[tuple[str, str], list[str]]
    hipaa_nist_provenance: dict[tuple[str, str], list[str]]
    cis_pci_provenance: dict[tuple[str, str], list[str]]
    cis_hipaa_provenance: dict[tuple[str, str], list[str]]
    stats: dict = field(default_factory=dict)


def _aggregate(edges: dict[tuple[str, str], set], *, valuekey=None) -> dict[str, list[str]]:
    """{(left,right): scf_ids} → {left: sorted[right]}."""
    out: dict[str, set] = {}
    for (left, right) in edges:
        out.setdefault(left, set()).add(right)
    return {
        left: sorted(rights, key=valuekey) if valuekey else sorted(rights)
        for left, rights in sorted(out.items(), key=lambda kv: _ctrl_num(kv[0]))
    }


def derive_crosswalks(controls: Iterable[dict]) -> Crosswalks:
    """
    Build CIS↔NIST, HIPAA↔NIST, and CIS↔PCI crosswalks by joining through each
    SCF control that maps to both sides (the SCF-as-Rosetta-Stone method).
    Every derived edge records the SCF control ids that produced it (provenance).
    """
    cis_nist: dict[tuple[str, str], set] = {}
    hipaa_nist: dict[tuple[str, str], set] = {}
    cis_pci: dict[tuple[str, str], set] = {}
    cis_hipaa: dict[tuple[str, str], set] = {}

    for c in controls:
        scf_id = c.get("scf_id", "")
        m = c.get("mappings") or {}
        if not isinstance(m, dict):
            continue

        cis = sorted({cc for x in _split_cell(m.get(CIS_KEY)) if (cc := cis_control(x))},
                     key=_ctrl_num)
        nist = sorted(set(nist_subcategories(m.get(NIST_KEY))))
        pci = sorted({pp for x in _split_cell(m.get(PCI_KEY)) if (pp := pci_requirement(x))},
                     key=_ctrl_num)
        hipaa = sorted({hh for x in _split_cell(m.get(HIPAA_SEC_KEY)) if (hh := hipaa_section(x))})

        for a in cis:
            for b in nist:
                cis_nist.setdefault((a, b), set()).add(scf_id)
            for p in pci:
                cis_pci.setdefault((a, p), set()).add(scf_id)
            for h in hipaa:
                cis_hipaa.setdefault((a, h), set()).add(scf_id)
        for h in hipaa:
            for b in nist:
                hipaa_nist.setdefault((h, b), set()).add(scf_id)

    stats = {
        "scf_controls_seen": sum(1 for _ in controls) if isinstance(controls, list) else None,
        "cis_nist_edges": len(cis_nist),
        "hipaa_nist_edges": len(hipaa_nist),
        "cis_pci_edges": len(cis_pci),
        "cis_hipaa_edges": len(cis_hipaa),
    }

    return Crosswalks(
        cis_to_nist=_aggregate(cis_nist),
        hipaa_to_nist=_aggregate(hipaa_nist),
        cis_to_pci=_aggregate(cis_pci, valuekey=_ctrl_num),
        cis_to_hipaa=_aggregate(cis_hipaa),
        cis_nist_provenance={k: sorted(v) for k, v in cis_nist.items()},
        hipaa_nist_provenance={k: sorted(v) for k, v in hipaa_nist.items()},
        cis_pci_provenance={k: sorted(v) for k, v in cis_pci.items()},
        cis_hipaa_provenance={k: sorted(v) for k, v in cis_hipaa.items()},
        stats=stats,
    )


def derive_from_file(path: str | Path) -> Crosswalks:
    return derive_crosswalks(load_scf_controls(path))
