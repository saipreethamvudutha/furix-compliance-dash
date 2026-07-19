"""
config_assertions.py
====================
Positive control assertions over config-posture evidence (Wave 2,
FUR-CMP-008). Unlike the detection rules (negative predicates), these evaluate
whether a control is *positively in place* over an expected population of
resources. A positive assertion is the only thing that can make a control PASS.

Rules are **declarative** (FUR-CMP verification-kernel hardening): each spec's
applicability and predicate are canonical `{attr, op, value}` clauses, not
opaque lambdas. The `evaluator_hash` is computed over the FULL normalized rule
— applies + predicate + parameters + runtime version — so two assertions with
opposing logic can never collide on the same hash (the P0 the audit flagged).
The generic evaluator applies the clauses; there is no hidden Python logic the
hash doesn't see.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .connectors import ConfigSnapshot, Resource
from .versions import RULE_PACK_VERSION

# result states (mirror the report test vocabulary)
PASS, FAIL, UNKNOWN, STALE = "pass", "fail", "unknown", "stale"

# The declarative rule language the evaluator_hash fully covers. Each op is a
# pure, total function of (resource attribute, clause value).
_OPS = {
    "truthy":  lambda a, v: bool(a),
    "falsy":   lambda a, v: not bool(a),
    "eq":      lambda a, v: a == v,
    "ne":      lambda a, v: a != v,
    "gte":     lambda a, v: _num(a) >= v,
    "lte":     lambda a, v: _num(a) <= v,
    "present": lambda a, v: a not in (None, "", [], {}),
    "always":  lambda a, v: True,
}


def _num(a: Any) -> float:
    try:
        return float(a)
    except (TypeError, ValueError):
        return float("-inf")


def _match(clause: Mapping[str, Any], r: Resource) -> bool:
    op = clause["op"]
    attr = r.attr(clause.get("attr", "")) if clause.get("attr") else None
    return _OPS[op](attr, clause.get("value"))


def _rule_version() -> str:
    """Bump when the op semantics change — part of every evaluator hash."""
    return "rulelang-1"


@dataclass(frozen=True)
class ConfigAssertionSpec:
    spec_id: str
    title: str
    resource_type: str
    control_edges: tuple[str, ...]
    severity: str
    applies_clause: Mapping[str, Any]      # declarative applicability
    predicate_clause: Mapping[str, Any]    # declarative positive predicate
    rationale: str
    freshness_slo_seconds: int = 86_400
    mode: str = "positive"
    predicate_kind: str = "positive"
    policy_version: str = RULE_PACK_VERSION

    @property
    def fail_attr(self) -> str:
        return self.predicate_clause.get("attr", "")

    def applies(self, r: Resource) -> bool:
        return _match(self.applies_clause, r)

    def predicate(self, r: Resource) -> bool:
        return _match(self.predicate_clause, r)

    def evaluator_hash(self) -> str:
        """
        Content hash over the ENTIRE normalized rule — including the actual
        applies/predicate logic, the rule-language version, the resource type,
        the control edges and the policy version. Two opposing predicates
        (e.g. op 'truthy' vs 'falsy' on the same attr) hash differently.
        """
        basis = {
            "spec_id": self.spec_id,
            "resource_type": self.resource_type,
            "control_edges": list(self.control_edges),
            "applies": dict(self.applies_clause),
            "predicate": dict(self.predicate_clause),
            "mode": self.mode,
            "predicate_kind": self.predicate_kind,
            "rule_language": _rule_version(),
            "policy_version": self.policy_version,
        }
        return hashlib.sha256(
            json.dumps(basis, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


def _spec(sid, title, rtype, controls, sev, applies, predicate, rationale, slo=86_400):
    return ConfigAssertionSpec(sid, title, rtype, controls, sev, applies, predicate, rationale,
                               freshness_slo_seconds=slo)


_TRUE = {"op": "always"}


# ── the catalog — 30 positive assertions across CIS 1,2,3,4,5,6,7,8,10,11,12,13,16 ─
CONFIG_ASSERTION_CATALOG: dict[str, ConfigAssertionSpec] = {s.spec_id: s for s in (
    # CIS 6 — Access Control
    _spec("CFG-IDP-MFA-EXTERNAL", "MFA enforced on externally-exposed apps", "okta_app",
          ("Control 6",), "high", {"op": "truthy", "attr": "internet_facing"},
          {"op": "truthy", "attr": "mfa_enforced"},
          "Every internet-facing app must enforce MFA (CIS 6.3)."),
    _spec("CFG-IDP-ADMIN-MFA", "MFA enrolled for all admins", "okta_user",
          ("Control 6",), "high", {"op": "truthy", "attr": "is_admin"},
          {"op": "truthy", "attr": "mfa_enrolled"},
          "Every administrative account must have MFA enrolled."),
    _spec("CFG-AWS-ROOT-MFA", "Root account MFA enabled", "aws_account",
          ("Control 6",), "critical", _TRUE, {"op": "truthy", "attr": "root_mfa_enabled"},
          "The AWS root account must have MFA enabled (CIS AWS 1.5)."),
    # CIS 5 — Account Management
    _spec("CFG-IDP-DORMANT", "No dormant active accounts (>90d)", "okta_user",
          ("Control 5",), "medium", {"op": "eq", "attr": "status", "value": "active"},
          {"op": "lte", "attr": "days_since_login", "value": 90},
          "Active accounts unused for >90 days must be disabled (CIS 5.3)."),
    _spec("CFG-AWS-KEY-ROTATION", "Access keys rotated within 90 days", "aws_access_key",
          ("Control 5",), "medium", {"op": "eq", "attr": "status", "value": "active"},
          {"op": "lte", "attr": "age_days", "value": 90},
          "Active access keys older than 90 days must be rotated."),
    # CIS 3 — Data Protection
    _spec("CFG-AWS-PUBLIC-BUCKET", "No public object storage", "aws_s3_bucket",
          ("Control 3",), "high", _TRUE, {"op": "truthy", "attr": "public_access_blocked"},
          "S3 buckets must block public access unless explicitly approved."),
    _spec("CFG-DATA-ENCRYPTION-REST", "Object storage encrypted at rest", "aws_s3_bucket",
          ("Control 3",), "high", _TRUE, {"op": "truthy", "attr": "encrypted_at_rest"},
          "Data stores must be encrypted at rest (CIS 3.11)."),
    # CIS 16 — Application Software Security
    _spec("CFG-GH-BRANCH-PROTECTION", "Default branch protected", "github_repo",
          ("Control 16",), "high", {"op": "present", "attr": "default_branch"},
          {"op": "truthy", "attr": "branch_protected"},
          "The default branch must have protection enabled (CIS 16.x)."),
    _spec("CFG-GH-REVIEW-REQUIRED", "Pull-request review required", "github_repo",
          ("Control 16",), "medium", _TRUE, {"op": "gte", "attr": "required_reviews", "value": 1},
          "At least one approving review must be required before merge."),
    _spec("CFG-GH-SECRET-SCANNING", "Secret scanning enabled", "github_repo",
          ("Control 16",), "medium", _TRUE, {"op": "truthy", "attr": "secret_scanning"},
          "Repositories must have secret scanning enabled."),
    _spec("CFG-GH-DEPENDABOT", "Dependency scanning enabled", "github_repo",
          ("Control 16",), "medium", _TRUE, {"op": "truthy", "attr": "dependabot_enabled"},
          "Repositories must have automated dependency scanning."),
    # CIS 1 — Inventory of Enterprise Assets
    _spec("CFG-ASSET-OWNER", "Every asset has an accountable owner", "asset",
          ("Control 1",), "medium", _TRUE, {"op": "present", "attr": "owner"},
          "Every enterprise asset must have a documented owner (CIS 1.1)."),
    _spec("CFG-ASSET-AUTHORIZED", "No unauthorized assets", "asset",
          ("Control 1",), "high", _TRUE, {"op": "truthy", "attr": "authorized"},
          "Unauthorized assets must be removed or authorized (CIS 1.2)."),
    # CIS 2 — Inventory of Software Assets
    _spec("CFG-SW-SUPPORTED", "No unsupported/end-of-life software", "software",
          ("Control 2",), "high", _TRUE, {"op": "truthy", "attr": "supported"},
          "Unsupported software must be removed (CIS 2.2)."),
    _spec("CFG-SW-INVENTORIED", "Software is inventoried", "software",
          ("Control 2",), "medium", _TRUE, {"op": "truthy", "attr": "inventoried"},
          "All software must be tracked in inventory (CIS 2.1)."),
    # CIS 4 — Secure Configuration
    _spec("CFG-CONFIG-BENCHMARK", "Passes secure-configuration benchmark", "config_item",
          ("Control 4",), "high", _TRUE, {"op": "truthy", "attr": "benchmark_pass"},
          "Systems must pass the secure-config baseline (CIS 4.1)."),
    _spec("CFG-CONFIG-NO-DEFAULT-CREDS", "No default credentials", "config_item",
          ("Control 4",), "critical", _TRUE, {"op": "truthy", "attr": "no_default_creds"},
          "Default accounts/passwords must be changed (CIS 4.7)."),
    # CIS 7 — Vulnerability Management
    _spec("CFG-VULN-SLA", "No vulnerability past remediation SLA", "vuln_scan",
          ("Control 7",), "high", _TRUE, {"op": "truthy", "attr": "within_sla"},
          "Vulnerabilities must be remediated within SLA (CIS 7.7)."),
    _spec("CFG-VULN-AUTH-SCAN", "Authenticated vulnerability scanning", "vuln_scan",
          ("Control 7",), "medium", _TRUE, {"op": "truthy", "attr": "authenticated"},
          "Scans must be authenticated for full coverage (CIS 7.5)."),
    # CIS 8 — Audit Log Management
    _spec("CFG-LOG-ENABLED", "Audit logging enabled on all sources", "log_source",
          ("Control 8",), "high", _TRUE, {"op": "truthy", "attr": "logging_enabled"},
          "Audit logging must be enabled on all systems (CIS 8.2)."),
    _spec("CFG-LOG-RETENTION", "Log retention ≥ 90 days", "log_source",
          ("Control 8",), "medium", _TRUE, {"op": "gte", "attr": "retention_days", "value": 90},
          "Audit logs must be retained ≥90 days (CIS 8.3)."),
    _spec("CFG-LOG-CENTRAL", "Centralized log collection", "log_source",
          ("Control 8",), "medium", _TRUE, {"op": "truthy", "attr": "centralized"},
          "Logs must be centrally collected (CIS 8.9)."),
    # CIS 10 — Malware Defenses
    _spec("CFG-EDR-DEPLOYED", "EDR deployed on all endpoints", "endpoint",
          ("Control 10",), "high", _TRUE, {"op": "truthy", "attr": "edr_deployed"},
          "Anti-malware/EDR must be deployed on endpoints (CIS 10.1)."),
    _spec("CFG-EDR-CURRENT", "Malware signatures current", "endpoint",
          ("Control 10",), "medium", {"op": "truthy", "attr": "edr_deployed"},
          {"op": "truthy", "attr": "signatures_current"},
          "Anti-malware signatures must be kept current (CIS 10.2)."),
    # CIS 11 — Data Recovery
    _spec("CFG-BACKUP-ENABLED", "Backups configured", "backup_job",
          ("Control 11",), "high", _TRUE, {"op": "truthy", "attr": "enabled"},
          "Automated backups must be configured (CIS 11.1)."),
    _spec("CFG-BACKUP-TESTED", "Backup restore tested", "backup_job",
          ("Control 11",), "medium", {"op": "truthy", "attr": "enabled"},
          {"op": "truthy", "attr": "restore_tested"},
          "Recovery must be tested periodically (CIS 11.5)."),
    _spec("CFG-BACKUP-ENCRYPTED", "Backups encrypted", "backup_job",
          ("Control 11",), "high", {"op": "truthy", "attr": "enabled"},
          {"op": "truthy", "attr": "encrypted"},
          "Backup data must be encrypted (CIS 11.3)."),
    # CIS 12 — Network Infrastructure
    _spec("CFG-NET-FIREWALL-REVIEWED", "Firewall rules reviewed", "firewall_rule",
          ("Control 12",), "medium", _TRUE, {"op": "truthy", "attr": "recently_reviewed"},
          "Firewall rulesets must be reviewed periodically (CIS 12.x)."),
    _spec("CFG-NET-SEGMENTATION", "Network segmentation in place", "network_zone",
          ("Control 12",), "medium", _TRUE, {"op": "truthy", "attr": "segmented"},
          "Sensitive assets must be network-segmented (CIS 12.2)."),
    # CIS 13 — Network Monitoring
    _spec("CFG-NET-IDS", "Network intrusion detection deployed", "network_monitor",
          ("Control 13",), "high", _TRUE, {"op": "truthy", "attr": "ids_deployed"},
          "Network IDS/IPS must be deployed (CIS 13.3)."),
)}

CONFIG_CONTROLS: frozenset[str] = frozenset(
    c for s in CONFIG_ASSERTION_CATALOG.values() for c in s.control_edges
)


def canonical_resource(r: Resource) -> str:
    return json.dumps(
        {"resource_id": r.resource_id, "resource_type": r.resource_type,
         "source": r.source, "boundary": r.boundary, "attributes": dict(r.attributes)},
        sort_keys=True, separators=(",", ":"),
    )


def resource_sha256(r: Resource) -> str:
    return hashlib.sha256(canonical_resource(r).encode("utf-8")).hexdigest()


def _age_seconds(collected_at: str | None, as_of: str | None) -> int | None:
    if not collected_at or not as_of:
        return None
    try:
        return int((datetime.fromisoformat(as_of) - datetime.fromisoformat(collected_at)).total_seconds())
    except ValueError:
        return None


def _evidence_row(r: Resource, spec: ConfigAssertionSpec, passed: bool) -> dict[str, Any]:
    detail = f"{spec.fail_attr}={r.attr(spec.fail_attr)!r}" if spec.fail_attr else ""
    sha = resource_sha256(r)
    return {
        "resource_id": r.resource_id, "resource_type": r.resource_type, "source": r.source,
        "observed_at": r.observed_at, "result": "pass" if passed else "fail", "detail": detail,
        "resource_sha256": sha, "raw_uri": f"furix-evidence://{sha}",
    }


def evaluate(snapshot: ConfigSnapshot, as_of: str | None = None) -> list[dict[str, Any]]:
    """
    Evaluate every applicable config assertion. `as_of` is an explicit
    evaluation time (never wall-clock) for freshness (FUR-CMP-010). An
    incomplete or unverified population (see connectors) can never PASS; stale
    evidence downgrades a PASS to STALE.
    """
    as_of = as_of or snapshot.collected_at
    age = _age_seconds(snapshot.collected_at, as_of)
    results: list[dict[str, Any]] = []
    for spec in CONFIG_ASSERTION_CATALOG.values():
        expected = snapshot.expected_count(spec.resource_type)
        population_verified = snapshot.has_expected(spec.resource_type)
        observed_all = snapshot.of_type(spec.resource_type)
        observed = len(observed_all)
        if expected == 0 and observed == 0 and population_verified:
            continue
        if observed == 0 and not population_verified:
            continue  # nothing declared, nothing seen — not this snapshot's concern

        in_scope = [r for r in observed_all if spec.applies(r)]
        passing = [r for r in in_scope if spec.predicate(r)]
        failing = [r for r in in_scope if not spec.predicate(r)]

        if not population_verified:
            status, reason = UNKNOWN, "population_unverified"   # no declared expected count
        elif observed < expected:
            status, reason = UNKNOWN, "incomplete_population"
        elif failing:
            status, reason = FAIL, "violations_present"
        elif in_scope:
            status, reason = PASS, "all_in_scope_satisfied"
        else:
            status, reason = UNKNOWN, "no_subjects_in_scope"

        stale = age is not None and age > spec.freshness_slo_seconds
        if stale and status == PASS:
            status, reason = STALE, "evidence_stale"

        reconciled = population_verified and observed >= expected
        coverage = round(100.0 * observed / expected, 1) if expected else (100.0 if reconciled else 0.0)
        evidence = [_evidence_row(r, spec, r in passing)
                    for r in sorted(in_scope, key=lambda x: x.resource_id)]
        results.append({
            "spec_id": spec.spec_id, "title": spec.title, "control_ids": list(spec.control_edges),
            "severity": spec.severity, "mode": spec.mode, "predicate_kind": spec.predicate_kind,
            "policy_version": spec.policy_version, "evaluator_hash": spec.evaluator_hash(),
            "resource_type": spec.resource_type, "status": status, "status_reason": reason,
            "rationale": spec.rationale,
            "population": {
                "expected": expected, "observed": observed, "in_scope": len(in_scope),
                "passing": len(passing), "failing": len(failing), "coverage_pct": coverage,
                "reconciled": reconciled, "population_verified": population_verified,
            },
            "freshness": {
                "as_of": as_of, "collected_at": snapshot.collected_at, "age_seconds": age,
                "slo_seconds": spec.freshness_slo_seconds, "stale": bool(stale),
            },
            "evidence": evidence,
        })
    results.sort(key=lambda r: r["spec_id"])
    return results
