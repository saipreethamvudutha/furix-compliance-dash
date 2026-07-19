"""
config_assertions.py
====================
Positive control assertions over config-posture evidence (Wave 2,
FUR-CMP-008). Unlike the detection rules (negative predicates — "a bad thing
was observed"), these evaluate whether a control is *positively in place* over
an expected population of resources. A positive assertion is the only thing
that can make a control legitimately PASS / a requirement `met`.

Each `ConfigAssertionSpec` declares:
  * the resource_type it evaluates,
  * `applies` — which resources are in scope (applicability),
  * `predicate` — the positive check each in-scope resource must satisfy,
  * the CIS controls it evidences, and a severity + rationale.

Evaluation reconciles the population: if the connector saw fewer resources than
expected, the assertion is UNKNOWN (incomplete population) — never PASS. A PASS
requires the FULL expected population observed AND every in-scope resource
satisfying the predicate. This is what stops partial config coverage from
masquerading as compliant.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable

from .connectors import ConfigSnapshot, Resource
from .versions import RULE_PACK_VERSION

# result states (mirror the report test vocabulary)
PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"


@dataclass(frozen=True)
class ConfigAssertionSpec:
    spec_id: str
    title: str
    resource_type: str
    control_edges: tuple[str, ...]
    severity: str
    applies: Callable[[Resource], bool]
    predicate: Callable[[Resource], bool]
    rationale: str
    fail_attr: str = ""              # which attribute a failure points at
    freshness_slo_seconds: int = 86_400  # config is expected fresh within a day
    mode: str = "positive"
    predicate_kind: str = "positive"
    policy_version: str = RULE_PACK_VERSION

    def evaluator_hash(self) -> str:
        basis = {
            "spec_id": self.spec_id,
            "resource_type": self.resource_type,
            "control_edges": list(self.control_edges),
            "mode": self.mode,
            "predicate_kind": self.predicate_kind,
            "policy_version": self.policy_version,
        }
        return hashlib.sha256(
            json.dumps(basis, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


def _truthy(r: Resource, key: str) -> bool:
    return bool(r.attr(key))


# ── the catalog — 9 positive assertions across CIS 3 / 5 / 6 / 16 ─────────────
CONFIG_ASSERTION_CATALOG: dict[str, ConfigAssertionSpec] = {
    s.spec_id: s for s in (
        ConfigAssertionSpec(
            "CFG-IDP-MFA-EXTERNAL", "MFA enforced on externally-exposed apps",
            "okta_app", ("Control 6",), "high",
            applies=lambda r: bool(r.attr("internet_facing")),
            predicate=lambda r: _truthy(r, "mfa_enforced"),
            rationale="Every internet-facing app must enforce MFA (CIS 6.3).",
            fail_attr="mfa_enforced",
        ),
        ConfigAssertionSpec(
            "CFG-IDP-ADMIN-MFA", "MFA enrolled for all admins",
            "okta_user", ("Control 6",), "high",
            applies=lambda r: bool(r.attr("is_admin")),
            predicate=lambda r: _truthy(r, "mfa_enrolled"),
            rationale="Every administrative account must have MFA enrolled.",
            fail_attr="mfa_enrolled",
        ),
        ConfigAssertionSpec(
            "CFG-IDP-DORMANT", "No dormant active accounts (>90d)",
            "okta_user", ("Control 5",), "medium",
            applies=lambda r: r.attr("status") == "active",
            predicate=lambda r: int(r.attr("days_since_login", 0)) <= 90,
            rationale="Active accounts unused for >90 days must be disabled (CIS 5.3).",
            fail_attr="days_since_login",
        ),
        ConfigAssertionSpec(
            "CFG-AWS-ROOT-MFA", "Root account MFA enabled",
            "aws_account", ("Control 6",), "critical",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "root_mfa_enabled"),
            rationale="The AWS root account must have MFA enabled (CIS AWS 1.5).",
            fail_attr="root_mfa_enabled",
        ),
        ConfigAssertionSpec(
            "CFG-AWS-KEY-ROTATION", "Access keys rotated within 90 days",
            "aws_access_key", ("Control 5",), "medium",
            applies=lambda r: r.attr("status") == "active",
            predicate=lambda r: int(r.attr("age_days", 0)) <= 90,
            rationale="Active access keys older than 90 days must be rotated.",
            fail_attr="age_days",
        ),
        ConfigAssertionSpec(
            "CFG-AWS-PUBLIC-BUCKET", "No public object storage",
            "aws_s3_bucket", ("Control 3",), "high",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "public_access_blocked"),
            rationale="S3 buckets must block public access unless explicitly approved.",
            fail_attr="public_access_blocked",
        ),
        ConfigAssertionSpec(
            "CFG-GH-BRANCH-PROTECTION", "Default branch protected",
            "github_repo", ("Control 16",), "high",
            applies=lambda r: bool(r.attr("default_branch")),
            predicate=lambda r: _truthy(r, "branch_protected"),
            rationale="The default branch must have protection enabled (CIS 16.x).",
            fail_attr="branch_protected",
        ),
        ConfigAssertionSpec(
            "CFG-GH-REVIEW-REQUIRED", "Pull-request review required",
            "github_repo", ("Control 16",), "medium",
            applies=lambda r: True,
            predicate=lambda r: int(r.attr("required_reviews", 0)) >= 1,
            rationale="At least one approving review must be required before merge.",
            fail_attr="required_reviews",
        ),
        ConfigAssertionSpec(
            "CFG-GH-SECRET-SCANNING", "Secret scanning enabled",
            "github_repo", ("Control 16",), "medium",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "secret_scanning"),
            rationale="Repositories must have secret scanning enabled.",
            fail_attr="secret_scanning",
        ),
    )
}

# Controls that config-posture assertions can positively demonstrate.
CONFIG_CONTROLS: frozenset[str] = frozenset(
    c for s in CONFIG_ASSERTION_CATALOG.values() for c in s.control_edges
)


def _evidence_row(r: Resource, spec: ConfigAssertionSpec, passed: bool) -> dict[str, Any]:
    detail = f"{spec.fail_attr}={r.attr(spec.fail_attr)!r}" if spec.fail_attr else ""
    return {
        "resource_id": r.resource_id,
        "resource_type": r.resource_type,
        "source": r.source,
        "observed_at": r.observed_at,
        "result": "pass" if passed else "fail",
        "detail": detail,
    }


def evaluate(snapshot: ConfigSnapshot) -> list[dict[str, Any]]:
    """
    Evaluate every applicable config assertion over a snapshot. Returns one
    result dict per assertion whose resource_type appears (observed or
    expected), each with a reconciled population and resource-level evidence.
    """
    results: list[dict[str, Any]] = []
    for spec in CONFIG_ASSERTION_CATALOG.values():
        expected = snapshot.expected_count(spec.resource_type)
        observed_all = snapshot.of_type(spec.resource_type)
        observed = len(observed_all)
        # assertion only reported when its resource_type is in play
        if expected == 0 and observed == 0:
            continue

        in_scope = [r for r in observed_all if spec.applies(r)]
        passing = [r for r in in_scope if spec.predicate(r)]
        failing = [r for r in in_scope if not spec.predicate(r)]

        if observed < expected:
            status, reason = UNKNOWN, "incomplete_population"
        elif failing:
            status, reason = FAIL, "violations_present"
        elif in_scope:
            status, reason = PASS, "all_in_scope_satisfied"
        else:
            status, reason = UNKNOWN, "no_subjects_in_scope"

        reconciled = observed >= expected
        coverage = round(100.0 * observed / expected, 1) if expected else 100.0
        evidence = [_evidence_row(r, spec, r in passing)
                    for r in sorted(in_scope, key=lambda x: x.resource_id)]
        results.append({
            "spec_id": spec.spec_id,
            "title": spec.title,
            "control_ids": list(spec.control_edges),
            "severity": spec.severity,
            "mode": spec.mode,
            "predicate_kind": spec.predicate_kind,
            "policy_version": spec.policy_version,
            "evaluator_hash": spec.evaluator_hash(),
            "resource_type": spec.resource_type,
            "status": status,
            "status_reason": reason,
            "rationale": spec.rationale,
            "population": {
                "expected": expected,
                "observed": observed,
                "in_scope": len(in_scope),
                "passing": len(passing),
                "failing": len(failing),
                "coverage_pct": coverage,
                "reconciled": reconciled,
            },
            "evidence": evidence,
        })
    results.sort(key=lambda r: r["spec_id"])
    return results
