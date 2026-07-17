"""
technique_map.py
================
The ATT&CK-technique → CIS-Control crosswalk — the edge that Furix's keyword
table was implicitly (and unmaintainably) encoding. Modelled on the MITRE CTID
"mitigates" mapping schema so a production ingest of the CTID mappings-explorer
JSON is a drop-in replacement.

Each edge is a typed MappingEdge with provenance, mirroring the OLIR/CTID
industry pattern rather than a boolean dict.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

_MAP_PATH = Path(__file__).with_name("technique_map.json")


@dataclass(frozen=True)
class MappingEdge:
    attack_object_id: str      # e.g. "T1110.001"
    attack_object_name: str
    capability_id: str         # e.g. "Control 6"
    capability_name: str
    relationship: str          # CTID mapping_type, e.g. "mitigates"


class TechniqueMap:
    """Immutable technique→control lookup with sub-technique fallback."""

    def __init__(self, edges: list[MappingEdge], provenance: str):
        self.edges = edges
        self.provenance = provenance
        self._by_technique: dict[str, list[MappingEdge]] = {}
        for edge in edges:
            self._by_technique.setdefault(edge.attack_object_id, []).append(edge)

    @classmethod
    def load(cls, path: Path = _MAP_PATH) -> "TechniqueMap":
        data = json.loads(path.read_text(encoding="utf-8"))
        edges = [
            MappingEdge(
                attack_object_id=e["attack_object_id"],
                attack_object_name=e["attack_object_name"],
                capability_id=e["capability_id"],
                capability_name=e["capability_name"],
                relationship=e.get("relationship", data.get("mapping_type", "mitigates")),
            )
            for e in data["edges"]
        ]
        return cls(edges, data.get("provenance", "unspecified"))

    def controls_for(self, technique_id: str) -> list[MappingEdge]:
        """
        Edges for a technique. If a sub-technique (T1110.001) has no direct
        edge, fall back to its parent (T1110) — the CTID convention.
        """
        if technique_id in self._by_technique:
            return list(self._by_technique[technique_id])
        parent = technique_id.split(".")[0]
        return list(self._by_technique.get(parent, []))

    def all_technique_ids(self) -> set[str]:
        return set(self._by_technique)
