"""
attack_enrich.py
================
Wires the zero-dependency ATT&CK / Sigma pivot (compliance_reporting.detection)
into the live pipeline. After the keyword engine maps a log to CIS controls,
this runs the Sigma ruleset over the same raw log — each rule that fires resolves
to MITRE ATT&CK techniques, and each technique resolves (via the CTID-style
technique→control map) to CIS controls. Those controls are merged into the
mapping, so the existing policy rules fire on attacks the keyword table misses,
and a full control ← technique ← Sigma-rule provenance chain is attached.

Toggle with FURIX_ATTACK_PIVOT (default "1" = on). The pivot is pure-Python and
loaded once per process, so this adds negligible per-log cost.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

_SEV_ORDER = ["informational", "low", "medium", "high", "critical"]


def _sev_rank(sev: str) -> int:
    try:
        return _SEV_ORDER.index(sev)
    except ValueError:
        return 0


@lru_cache(maxsize=1)
def _resolver():
    from compliance_reporting.detection import AttackPivotResolver  # noqa: PLC0415
    return AttackPivotResolver.load()


def _ctrl_num(label: str) -> int:
    try:
        return int(label.split()[-1])
    except (ValueError, IndexError):
        return 0


def enrich_findings(raw_log: str, log_type: str, findings: dict) -> dict[str, Any]:
    """
    Merge Sigma-pivot controls into findings['cis_controls_mapping']['control_ids']
    and return the pivot provenance (empty dict if disabled / nothing fired).

    Mutates `findings` in place (adds controls + an 'attack_pivot' block).
    Never raises — detection enrichment must not break the pipeline.
    """
    if os.environ.get("FURIX_ATTACK_PIVOT", "1") != "1":
        return {}
    try:
        result = _resolver().resolve(raw_log, log_type)
    except Exception as exc:  # noqa: BLE001 — enrichment is best-effort
        print(f"  [attack-pivot] skipped ({exc})")
        return {}

    if not result.control_ids:
        return {}

    mapping = findings.setdefault("cis_controls_mapping", {})
    existing = list(mapping.get("control_ids") or [])
    added = [c for c in result.control_ids if c not in existing]
    merged = sorted(set(existing) | set(result.control_ids), key=_ctrl_num)
    mapping["control_ids"] = merged

    # Raise severity to the fired rules' worst level if higher — a confirmed
    # Sigma detection (e.g. reverse shell = critical) shouldn't sit at "low"
    # just because the pipeline's own density gate under-rated the raw text.
    # This lets the control-gated policy rules (POL-006/010/013/…) fire.
    cur_sev = findings.get("severity", "low")
    if _sev_rank(result.worst_level) > _sev_rank(cur_sev):
        findings["severity"] = result.worst_level

    provenance = {
        "technique_ids": result.technique_ids,
        "controls_from_pivot": result.control_ids,
        "controls_added": added,          # controls the keyword engine had missed
        "worst_level": result.worst_level,
        "trace": result.provenance(),     # control ← technique ← rule rows
    }
    findings["attack_pivot"] = provenance
    if added:
        print(f"  [attack-pivot] +{len(added)} control(s) via "
              f"{', '.join(result.technique_ids)}: {', '.join(added)}")
    return provenance
