"""
registry.py
===========
The static ground truth of the reporting layer:

  * TEST_CATALOG    — the 15 policy rules (Furix's atomic checks), keyed POL-xxx.
                      Mirrors policy_engine.py exactly; a unit test asserts the
                      mirror stays in sync when policy_engine is importable.
  * CONTROL_CATALOG — the 18 CIS Controls v8.1 (the neutral middle layer).
  * FrameworkRegistry — control → framework-requirement crosswalk, injected
                      from the live SCF-derived dicts when available, else
                      loaded from the bundled snapshot.

No imports of db_connections/config at module level — the live crosswalk is
resolved lazily so this package imports cleanly on any machine.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

_SNAPSHOT_PATH = Path(__file__).with_name("crosswalk_snapshot.json")

SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")


def severity_rank(severity: str) -> int:
    """Rank a severity for worst-of comparisons; unknown values rank lowest."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return -1


# ── Test catalog — mirrors policy_engine.py POL-001..POL-015 ─────────────────
@dataclass(frozen=True)
class TestSpec:
    test_id: str
    title: str
    severity: str
    control_ids: tuple[str, ...]  # composite rules map to >1 control


TEST_CATALOG: dict[str, TestSpec] = {
    spec.test_id: spec
    for spec in (
        TestSpec("POL-001", "Unauthorised Account Creation", "high", ("Control 5",)),
        TestSpec("POL-002", "Privilege Escalation Detected", "high", ("Control 6",)),
        TestSpec("POL-003", "Brute Force with Successful Authentication", "critical", ("Control 6",)),
        TestSpec("POL-004", "Failed Authentication Attempts", "medium", ("Control 6",)),
        TestSpec("POL-005", "Known CVE Exploitation Detected", "high", ("Control 7",)),
        TestSpec("POL-006", "Malware or C2 Activity Confirmed", "critical", ("Control 10",)),
        TestSpec("POL-007", "Multi-Stage Attack — Incident Response Required", "critical", ("Control 17",)),
        TestSpec("POL-008", "External Source IP on High-Severity Event", "high", ("Control 12",)),
        TestSpec("POL-009", "Privilege Escalation from External Source", "critical", ("Control 6", "Control 12")),
        TestSpec("POL-010", "Data Exfiltration or Sensitive Data Access", "high", ("Control 3",)),
        TestSpec("POL-011", "CVE Exploitation with Vulnerability Management Gap", "high", ("Control 7",)),
        TestSpec("POL-012", "Secure Configuration Failure", "medium", ("Control 4",)),
        TestSpec("POL-013", "Audit Log Integrity Event", "medium", ("Control 8",)),
        TestSpec("POL-014", "Lateral Movement Detected", "high", ("Control 13",)),
        TestSpec("POL-015", "Cloud Privileged Role Assignment", "high", ("Control 6", "Control 15")),
    )
}


# ── Control catalog — CIS Controls v8.1 (titles mirror setup_ingestion.py) ───
CONTROL_CATALOG: dict[str, str] = {
    "Control 1": "Inventory and Control of Enterprise Assets",
    "Control 2": "Inventory and Control of Software Assets",
    "Control 3": "Data Protection",
    "Control 4": "Secure Configuration of Enterprise Assets and Software",
    "Control 5": "Account Management",
    "Control 6": "Access Control Management",
    "Control 7": "Continuous Vulnerability Management",
    "Control 8": "Audit Log Management",
    "Control 9": "Email and Web Browser Protections",
    "Control 10": "Malware Defenses",
    "Control 11": "Data Recovery",
    "Control 12": "Network Infrastructure Management",
    "Control 13": "Network Monitoring and Defense",
    "Control 14": "Security Awareness and Skills Training",
    "Control 15": "Service Provider Management",
    "Control 16": "Application Software Security",
    "Control 17": "Incident Response Management",
    "Control 18": "Penetration Testing",
}

CONTROLS_BY_TEST: dict[str, tuple[str, ...]] = {
    t.test_id: t.control_ids for t in TEST_CATALOG.values()
}

TESTS_BY_CONTROL: dict[str, tuple[str, ...]] = {
    ctrl: tuple(
        sorted(t.test_id for t in TEST_CATALOG.values() if ctrl in t.control_ids)
    )
    for ctrl in CONTROL_CATALOG
}


# ── Framework crosswalk registry ──────────────────────────────────────────────
@dataclass(frozen=True)
class FrameworkRegistry:
    """
    Control → framework-requirement edges for the three reported frameworks.

    cis_to_nist  : {"Control 6": ("PR.AA-01", ...), ...}
    cis_to_hipaa : {"Control 6": ("164.308",), ...}
    cis_to_pci   : {"Control 6": ("Req 7", "Req 8"), ...}
    provenance   : where the edges came from (live DB vs bundled snapshot) —
                   surfaced verbatim in the report so auditors can see it.
    """

    cis_to_nist: Mapping[str, tuple[str, ...]]
    cis_to_hipaa: Mapping[str, tuple[str, ...]]
    cis_to_pci: Mapping[str, tuple[str, ...]]
    provenance: str = field(default="unspecified")

    @classmethod
    def from_snapshot(cls, path: Path = _SNAPSHOT_PATH) -> "FrameworkRegistry":
        """Load the bundled offline snapshot (dev/test; replace in prod)."""
        data = json.loads(path.read_text())
        return cls(
            cis_to_nist={k: tuple(v) for k, v in data["cis_to_nist"].items()},
            cis_to_hipaa={k: tuple(v) for k, v in data["cis_to_hipaa"].items()},
            cis_to_pci={k: tuple(v) for k, v in data.get("cis_to_pci", {}).items()},
            provenance=data["provenance"],
        )

    @classmethod
    def from_scf_json(cls, path: str | Path) -> "FrameworkRegistry":
        """
        Derive ALL THREE crosswalks (CIS→NIST, CIS→HIPAA, CIS→PCI) directly from
        the Secure Controls Framework JSON via scf_crosswalk. This is the best
        source: real, complete (all 18 controls), version-proof, and needs no
        database. `scf_crosswalk` lives beside the pipeline and is imported
        lazily so this package still imports cleanly where it is absent.
        """
        import scf_crosswalk  # noqa: PLC0415 — lazy, pipeline-adjacent, zero-dep

        cw = scf_crosswalk.derive_from_file(path)
        return cls(
            cis_to_nist={k: tuple(v) for k, v in cw.cis_to_nist.items()},
            cis_to_hipaa={k: tuple(v) for k, v in cw.cis_to_hipaa.items()},
            cis_to_pci={k: tuple(v) for k, v in cw.cis_to_pci.items()},
            provenance=f"SCF 2026.2 JSON crosswalk ({os.path.basename(str(path))})",
        )

    @classmethod
    def from_live(cls) -> "FrameworkRegistry":
        """
        Resolve the best available crosswalk source, in order:
          1. SCF JSON (env FURIX_SCF_JSON) — real, complete, version-proof.
          2. furix_det DB via db_connections — real NIST, hardcoded HIPAA, snapshot PCI.
          3. bundled snapshot — offline dev/test fallback.
        """
        # 1) SCF JSON — the authoritative source for all three frameworks.
        scf_path = os.environ.get("FURIX_SCF_JSON")
        if scf_path and Path(scf_path).exists():
            try:
                return cls.from_scf_json(scf_path)
            except Exception:  # pragma: no cover — degrade gracefully
                pass

        # 2) furix_det DB (legacy path; PCI/HIPAA are partial here).
        try:
            from db_connections import CIS_TO_NIST_MAPPINGS  # noqa: PLC0415

            if CIS_TO_NIST_MAPPINGS:
                from policy_engine import _CIS_TO_HIPAA  # noqa: PLC0415

                snapshot = cls.from_snapshot()
                return cls(
                    cis_to_nist={k: tuple(v) for k, v in CIS_TO_NIST_MAPPINGS.items()},
                    cis_to_hipaa={k: (v,) for k, v in _CIS_TO_HIPAA.items()},
                    cis_to_pci=snapshot.cis_to_pci,
                    provenance=(
                        "NIST: furix_det; HIPAA: policy_engine table; PCI: bundled snapshot"
                    ),
                )
        except Exception:  # pragma: no cover — import-environment dependent
            pass

        # 3) bundled snapshot.
        return cls.from_snapshot()

    def nist_requirements(self) -> dict[str, tuple[str, ...]]:
        """Invert to {nist_id: (contributing control ids...)}."""
        return _invert(self.cis_to_nist)

    def hipaa_requirements(self) -> dict[str, tuple[str, ...]]:
        """Invert to {hipaa_section: (contributing control ids...)}."""
        return _invert(self.cis_to_hipaa)

    def pci_requirements(self) -> dict[str, tuple[str, ...]]:
        """Invert to {pci_requirement: (contributing control ids...)}."""
        return _invert(self.cis_to_pci)


def _invert(edges: Mapping[str, Sequence[str]]) -> dict[str, tuple[str, ...]]:
    inverted: dict[str, list[str]] = {}
    for control_id, requirements in edges.items():
        for req in requirements:
            inverted.setdefault(req, []).append(control_id)
    return {req: tuple(sorted(ctrls)) for req, ctrls in sorted(inverted.items())}


def export_snapshot_from_live(path: Path) -> None:
    """
    Dump the live furix_det crosswalk to a snapshot JSON so offline
    environments report against the real SCF-derived edges. Run on a machine
    with the DB up:  python -c "from compliance_reporting.registry import \
    export_snapshot_from_live; export_snapshot_from_live(Path('crosswalk_snapshot.json'))"
    """
    registry = FrameworkRegistry.from_live()
    if registry.provenance.startswith("bundled"):
        raise RuntimeError("Live crosswalk unavailable — refusing to overwrite snapshot with itself.")
    path.write_text(
        json.dumps(
            {
                "provenance": registry.provenance,
                "cis_to_nist": {k: list(v) for k, v in registry.cis_to_nist.items()},
                "cis_to_hipaa": {k: list(v) for k, v in registry.cis_to_hipaa.items()},
                "cis_to_pci": {k: list(v) for k, v in registry.cis_to_pci.items()},
            },
            indent=2,
            sort_keys=True,
        )
    )
