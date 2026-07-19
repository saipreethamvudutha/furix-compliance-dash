"""
connectors.py
=============
Config-posture evidence connectors (Wave 2, FUR-CMP-009).

The detection engine answers "did a bad thing happen?" from log *events*. A
compliance program also needs "is the control positively in place?" from config
*state* — MFA enforced in the IdP, root MFA on in AWS, branch protection on in
GitHub. That state is what makes a control legitimately PASS.

A connector normalizes a provider's configuration into a uniform stream of
`Resource` records plus an `expected_counts` manifest (how many resources of
each type SHOULD exist), so a positive assertion can reconcile the population it
saw against the population it expected — partial config coverage can never read
as compliant.

These connectors are deterministic and read a JSON **snapshot** (the exact shape
a real API client would produce). Swapping in a live AWS/Okta/GitHub client is a
drop-in later: it just has to emit the same snapshot shape.

Snapshot shape:
    {
      "source": "okta",
      "collected_at": "2026-07-19T12:00:00+00:00",
      "boundary": "prod",
      "expected_counts": {"okta_app": 4, "okta_user": 3},
      "resources": [
        {"resource_id": "app-portal", "resource_type": "okta_app",
         "observed_at": "...", "attributes": {"internet_facing": true, "mfa_enforced": true}},
        ...
      ]
    }
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

# Providers this module knows how to normalize. Unknown sources are accepted
# as-is (attributes passed through) so new providers need no code change if
# they already emit the snapshot shape.
KNOWN_SOURCES = ("okta", "aws_iam", "github")


@dataclass(frozen=True)
class Resource:
    """One normalized configuration resource — a positive-assertion subject."""

    resource_id: str
    resource_type: str
    source: str
    boundary: str
    observed_at: str | None
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def attr(self, key: str, default: Any = None) -> Any:
        return self.attributes.get(key, default)


@dataclass(frozen=True)
class ConfigSnapshot:
    """A connector's output: resources + the expected-population manifest."""

    source: str
    boundary: str
    collected_at: str | None
    resources: tuple[Resource, ...]
    expected_counts: Mapping[str, int]

    def of_type(self, resource_type: str) -> list[Resource]:
        return [r for r in self.resources if r.resource_type == resource_type]

    def observed_count(self, resource_type: str) -> int:
        return sum(1 for r in self.resources if r.resource_type == resource_type)

    def expected_count(self, resource_type: str) -> int:
        return int(self.expected_counts.get(resource_type, self.observed_count(resource_type)))


def parse_snapshot(raw: Mapping[str, Any]) -> ConfigSnapshot:
    """
    Normalize a raw snapshot mapping into a ConfigSnapshot. Deterministic and
    dependency-free; validates the minimum shape and passes attributes through.
    """
    if not isinstance(raw, Mapping):
        raise TypeError("snapshot must be a mapping")
    source = str(raw.get("source", "unknown"))
    boundary = str(raw.get("boundary", "default"))
    collected_at = raw.get("collected_at")
    resources: list[Resource] = []
    for r in raw.get("resources", []) or []:
        if not isinstance(r, Mapping):
            continue
        resources.append(
            Resource(
                resource_id=str(r.get("resource_id", "")),
                resource_type=str(r.get("resource_type", "")),
                source=source,
                boundary=boundary,
                observed_at=r.get("observed_at"),
                attributes=dict(r.get("attributes", {}) or {}),
            )
        )
    # resources sorted for deterministic evaluation order
    resources.sort(key=lambda x: (x.resource_type, x.resource_id))
    expected = {str(k): int(v) for k, v in (raw.get("expected_counts", {}) or {}).items()}
    return ConfigSnapshot(
        source=source,
        boundary=boundary,
        collected_at=collected_at,
        resources=tuple(resources),
        expected_counts=expected,
    )


def merge_snapshots(snapshots: list[ConfigSnapshot]) -> ConfigSnapshot:
    """Combine multiple provider snapshots into one (for a multi-source ingest)."""
    all_resources: list[Resource] = []
    expected: dict[str, int] = {}
    sources = sorted({s.source for s in snapshots})
    collected = sorted((s.collected_at for s in snapshots if s.collected_at))
    for s in snapshots:
        all_resources.extend(s.resources)
        for k, v in s.expected_counts.items():
            expected[k] = expected.get(k, 0) + v
    all_resources.sort(key=lambda x: (x.resource_type, x.resource_id))
    return ConfigSnapshot(
        source="+".join(sources),
        boundary="multi",
        collected_at=collected[-1] if collected else None,
        resources=tuple(all_resources),
        expected_counts=expected,
    )
