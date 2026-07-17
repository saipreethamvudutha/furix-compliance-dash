"""
compliance_reporting.detection
==============================
The ATT&CK pivot: a deterministic, zero-dependency detection layer that maps a
raw log to CIS Controls through portable Sigma rules and a MITRE-CTID-style
technique→control crosswalk — replacing the hand-maintained keyword table.

    from compliance_reporting.detection import AttackPivotResolver
    resolver = AttackPivotResolver.load()
    result = resolver.resolve(raw_log, log_type)
    result.control_ids     # ["Control 5", "Control 6", ...]
    result.provenance()    # control ← technique ← rule audit trail
"""

from .resolver import AttackPivotResolver, DetectionResult, TechniqueHit
from .sigma import Ruleset, SigmaRule, SigmaRuleError
from .technique_map import MappingEdge, TechniqueMap

__all__ = [
    "AttackPivotResolver",
    "DetectionResult",
    "TechniqueHit",
    "Ruleset",
    "SigmaRule",
    "SigmaRuleError",
    "MappingEdge",
    "TechniqueMap",
]
