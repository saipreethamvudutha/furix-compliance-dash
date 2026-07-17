"""
resolver.py
===========
The ATT&CK pivot, end to end:

    raw log  →  Sigma rules that fire  →  ATT&CK techniques  →  CIS Controls
                                                              (via TechniqueMap)

This replaces the keyword→control table's *job* while fixing its flaws: every
mapped control now carries a full provenance chain (which rule fired, which
technique it tagged, which mapping edge produced the control), the matching is
anchored (no `"c2"`-matches-inside-`dc2` bugs), and the rules are individually
schema-validated and fixture-tested.

The output is intentionally shaped to drop into the existing reporting layer:
`detect_controls()` returns the same `["Control 6", ...]` list the keyword
engine produced, plus a `provenance` structure the report can surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .sigma import Ruleset, SigmaRule
from .technique_map import MappingEdge, TechniqueMap

_RULES_DIR = Path(__file__).with_name("rules")

_LEVEL_TO_SEVERITY = {
    "informational": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


@dataclass(frozen=True)
class TechniqueHit:
    """One fired rule, resolved to the techniques and controls it implies."""

    rule_id: str
    rule_title: str
    level: str
    technique_ids: tuple[str, ...]
    control_ids: tuple[str, ...]
    edges: tuple[MappingEdge, ...]


@dataclass
class DetectionResult:
    """Everything the ATT&CK pivot found in one log, with full provenance."""

    log_type: str
    hits: list[TechniqueHit] = field(default_factory=list)

    @property
    def control_ids(self) -> list[str]:
        """De-duplicated CIS controls, sorted by control number."""
        controls = {c for hit in self.hits for c in hit.control_ids}
        return sorted(controls, key=lambda c: int(c.split()[-1]))

    @property
    def technique_ids(self) -> list[str]:
        return sorted({t for hit in self.hits for t in hit.technique_ids})

    @property
    def worst_level(self) -> str:
        order = ["informational", "low", "medium", "high", "critical"]
        levels = [hit.level for hit in self.hits]
        return max(levels, key=order.index) if levels else "informational"

    def provenance(self) -> list[dict[str, Any]]:
        """The audit trail: control ← technique ← rule, for the report."""
        rows: list[dict[str, Any]] = []
        for hit in self.hits:
            for edge in hit.edges:
                rows.append({
                    "control_id": edge.capability_id,
                    "control_name": edge.capability_name,
                    "technique_id": edge.attack_object_id,
                    "technique_name": edge.attack_object_name,
                    "relationship": edge.relationship,
                    "rule_id": hit.rule_id,
                    "rule_title": hit.rule_title,
                    "rule_level": hit.level,
                })
        return sorted(rows, key=lambda r: (r["control_id"], r["technique_id"], r["rule_id"]))


class AttackPivotResolver:
    """Loads the ruleset + technique map once; resolves logs deterministically."""

    def __init__(self, ruleset: Ruleset, technique_map: TechniqueMap):
        self.ruleset = ruleset
        self.technique_map = technique_map

    @classmethod
    def load(cls, rules_dir: Path = _RULES_DIR) -> "AttackPivotResolver":
        return cls(Ruleset.from_dir(rules_dir), TechniqueMap.load())

    def resolve(self, raw_log: str, log_type: str) -> DetectionResult:
        result = DetectionResult(log_type=log_type)
        for rule in self.ruleset.match(raw_log, log_type):
            hit = self._resolve_rule(rule)
            if hit.control_ids:  # a rule with no mappable technique adds nothing
                result.hits.append(hit)
        result.hits.sort(key=lambda h: h.rule_id)
        return result

    def _resolve_rule(self, rule: SigmaRule) -> TechniqueHit:
        edges: list[MappingEdge] = []
        for tid in rule.technique_ids:
            edges.extend(self.technique_map.controls_for(tid))
        controls = tuple(sorted(
            {e.capability_id for e in edges}, key=lambda c: int(c.split()[-1])
        ))
        return TechniqueHit(
            rule_id=rule.rule_id,
            rule_title=rule.title,
            level=_LEVEL_TO_SEVERITY.get(rule.level, "low"),
            technique_ids=rule.technique_ids,
            control_ids=controls,
            edges=tuple(edges),
        )

    def detect_controls(self, raw_log: str, log_type: str) -> list[str]:
        """Keyword-engine-compatible output: just the CIS control id list."""
        return self.resolve(raw_log, log_type).control_ids
