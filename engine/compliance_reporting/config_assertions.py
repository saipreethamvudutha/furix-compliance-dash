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
from datetime import datetime
from typing import Any, Callable

from .connectors import ConfigSnapshot, Resource
from .versions import RULE_PACK_VERSION

# result states (mirror the report test vocabulary)
PASS, FAIL, UNKNOWN, STALE = "pass", "fail", "unknown", "stale"


def _age_seconds(collected_at: str | None, as_of: str | None) -> int | None:
    """Deterministic evidence age from two ISO timestamps (no wall-clock)."""
    if not collected_at or not as_of:
        return None
    try:
        return int((datetime.fromisoformat(as_of) - datetime.fromisoformat(collected_at)).total_seconds())
    except ValueError:
        return None


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
        ConfigAssertionSpec(
            "CFG-GH-DEPENDABOT", "Dependency scanning enabled",
            "github_repo", ("Control 16",), "medium",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "dependabot_enabled"),
            rationale="Repositories must have automated dependency scanning.",
            fail_attr="dependabot_enabled",
        ),
        # ── CIS 3 — Data Protection ───────────────────────────────────────────
        ConfigAssertionSpec(
            "CFG-DATA-ENCRYPTION-REST", "Object storage encrypted at rest",
            "aws_s3_bucket", ("Control 3",), "high",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "encrypted_at_rest"),
            rationale="Data stores must be encrypted at rest (CIS 3.11).",
            fail_attr="encrypted_at_rest",
        ),
        # ── CIS 1 — Inventory & Control of Enterprise Assets ─────────────────
        ConfigAssertionSpec(
            "CFG-ASSET-OWNER", "Every asset has an accountable owner",
            "asset", ("Control 1",), "medium",
            applies=lambda r: True,
            predicate=lambda r: bool(r.attr("owner")),
            rationale="Every enterprise asset must have a documented owner (CIS 1.1).",
            fail_attr="owner",
        ),
        ConfigAssertionSpec(
            "CFG-ASSET-AUTHORIZED", "No unauthorized assets",
            "asset", ("Control 1",), "high",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "authorized"),
            rationale="Unauthorized assets must be removed or authorized (CIS 1.2).",
            fail_attr="authorized",
        ),
        # ── CIS 2 — Inventory & Control of Software Assets ───────────────────
        ConfigAssertionSpec(
            "CFG-SW-SUPPORTED", "No unsupported/end-of-life software",
            "software", ("Control 2",), "high",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "supported"),
            rationale="Unsupported software must be removed (CIS 2.2).",
            fail_attr="supported",
        ),
        ConfigAssertionSpec(
            "CFG-SW-INVENTORIED", "Software is inventoried",
            "software", ("Control 2",), "medium",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "inventoried"),
            rationale="All software must be tracked in inventory (CIS 2.1).",
            fail_attr="inventoried",
        ),
        # ── CIS 4 — Secure Configuration ─────────────────────────────────────
        ConfigAssertionSpec(
            "CFG-CONFIG-BENCHMARK", "Passes secure-configuration benchmark",
            "config_item", ("Control 4",), "high",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "benchmark_pass"),
            rationale="Systems must pass the secure-config baseline (CIS 4.1).",
            fail_attr="benchmark_pass",
        ),
        ConfigAssertionSpec(
            "CFG-CONFIG-NO-DEFAULT-CREDS", "No default credentials",
            "config_item", ("Control 4",), "critical",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "no_default_creds"),
            rationale="Default accounts/passwords must be changed (CIS 4.7).",
            fail_attr="no_default_creds",
        ),
        # ── CIS 7 — Continuous Vulnerability Management ──────────────────────
        ConfigAssertionSpec(
            "CFG-VULN-SLA", "No vulnerability past remediation SLA",
            "vuln_scan", ("Control 7",), "high",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "within_sla"),
            rationale="Vulnerabilities must be remediated within SLA (CIS 7.7).",
            fail_attr="within_sla",
        ),
        ConfigAssertionSpec(
            "CFG-VULN-AUTH-SCAN", "Authenticated vulnerability scanning",
            "vuln_scan", ("Control 7",), "medium",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "authenticated"),
            rationale="Scans must be authenticated for full coverage (CIS 7.5).",
            fail_attr="authenticated",
        ),
        # ── CIS 8 — Audit Log Management ─────────────────────────────────────
        ConfigAssertionSpec(
            "CFG-LOG-ENABLED", "Audit logging enabled on all sources",
            "log_source", ("Control 8",), "high",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "logging_enabled"),
            rationale="Audit logging must be enabled on all systems (CIS 8.2).",
            fail_attr="logging_enabled",
        ),
        ConfigAssertionSpec(
            "CFG-LOG-RETENTION", "Log retention ≥ 90 days",
            "log_source", ("Control 8",), "medium",
            applies=lambda r: True,
            predicate=lambda r: int(r.attr("retention_days", 0)) >= 90,
            rationale="Audit logs must be retained ≥90 days (CIS 8.3).",
            fail_attr="retention_days",
        ),
        ConfigAssertionSpec(
            "CFG-LOG-CENTRAL", "Centralized log collection",
            "log_source", ("Control 8",), "medium",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "centralized"),
            rationale="Logs must be centrally collected (CIS 8.9).",
            fail_attr="centralized",
        ),
        # ── CIS 10 — Malware Defenses ────────────────────────────────────────
        ConfigAssertionSpec(
            "CFG-EDR-DEPLOYED", "EDR deployed on all endpoints",
            "endpoint", ("Control 10",), "high",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "edr_deployed"),
            rationale="Anti-malware/EDR must be deployed on endpoints (CIS 10.1).",
            fail_attr="edr_deployed",
        ),
        ConfigAssertionSpec(
            "CFG-EDR-CURRENT", "Malware signatures current",
            "endpoint", ("Control 10",), "medium",
            applies=lambda r: _truthy(r, "edr_deployed"),
            predicate=lambda r: _truthy(r, "signatures_current"),
            rationale="Anti-malware signatures must be kept current (CIS 10.2).",
            fail_attr="signatures_current",
        ),
        # ── CIS 11 — Data Recovery ───────────────────────────────────────────
        ConfigAssertionSpec(
            "CFG-BACKUP-ENABLED", "Backups configured",
            "backup_job", ("Control 11",), "high",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "enabled"),
            rationale="Automated backups must be configured (CIS 11.1).",
            fail_attr="enabled",
        ),
        ConfigAssertionSpec(
            "CFG-BACKUP-TESTED", "Backup restore tested",
            "backup_job", ("Control 11",), "medium",
            applies=lambda r: _truthy(r, "enabled"),
            predicate=lambda r: _truthy(r, "restore_tested"),
            rationale="Recovery must be tested periodically (CIS 11.5).",
            fail_attr="restore_tested",
        ),
        ConfigAssertionSpec(
            "CFG-BACKUP-ENCRYPTED", "Backups encrypted",
            "backup_job", ("Control 11",), "high",
            applies=lambda r: _truthy(r, "enabled"),
            predicate=lambda r: _truthy(r, "encrypted"),
            rationale="Backup data must be encrypted (CIS 11.3).",
            fail_attr="encrypted",
        ),
        # ── CIS 12 — Network Infrastructure Management ───────────────────────
        ConfigAssertionSpec(
            "CFG-NET-FIREWALL-REVIEWED", "Firewall rules reviewed",
            "firewall_rule", ("Control 12",), "medium",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "recently_reviewed"),
            rationale="Firewall rulesets must be reviewed periodically (CIS 12.x).",
            fail_attr="recently_reviewed",
        ),
        ConfigAssertionSpec(
            "CFG-NET-SEGMENTATION", "Network segmentation in place",
            "network_zone", ("Control 12",), "medium",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "segmented"),
            rationale="Sensitive assets must be network-segmented (CIS 12.2).",
            fail_attr="segmented",
        ),
        # ── CIS 13 — Network Monitoring & Defense ────────────────────────────
        ConfigAssertionSpec(
            "CFG-NET-IDS", "Network intrusion detection deployed",
            "network_monitor", ("Control 13",), "high",
            applies=lambda r: True,
            predicate=lambda r: _truthy(r, "ids_deployed"),
            rationale="Network IDS/IPS must be deployed (CIS 13.3).",
            fail_attr="ids_deployed",
        ),
    )
}

# Controls that config-posture assertions can positively demonstrate.
CONFIG_CONTROLS: frozenset[str] = frozenset(
    c for s in CONFIG_ASSERTION_CATALOG.values() for c in s.control_edges
)


def canonical_resource(r: Resource) -> str:
    """Stable serialisation of a resource — the basis for its evidence hash."""
    return json.dumps(
        {"resource_id": r.resource_id, "resource_type": r.resource_type,
         "source": r.source, "boundary": r.boundary, "attributes": dict(r.attributes)},
        sort_keys=True, separators=(",", ":"),
    )


def resource_sha256(r: Resource) -> str:
    return hashlib.sha256(canonical_resource(r).encode("utf-8")).hexdigest()


def _evidence_row(r: Resource, spec: ConfigAssertionSpec, passed: bool) -> dict[str, Any]:
    detail = f"{spec.fail_attr}={r.attr(spec.fail_attr)!r}" if spec.fail_attr else ""
    sha = resource_sha256(r)
    return {
        "resource_id": r.resource_id,
        "resource_type": r.resource_type,
        "source": r.source,
        "observed_at": r.observed_at,
        "result": "pass" if passed else "fail",
        "detail": detail,
        # lineage parity with log evidence (FUR-CMP-007): a resolvable pointer
        # into the immutable evidence store, written at config-ingest time.
        "resource_sha256": sha,
        "raw_uri": f"furix-evidence://{sha}",
    }


def evaluate(snapshot: ConfigSnapshot, as_of: str | None = None) -> list[dict[str, Any]]:
    """
    Evaluate every applicable config assertion over a snapshot. Returns one
    result dict per assertion whose resource_type appears (observed or
    expected), each with a reconciled population, freshness, and resource-level
    evidence.

    Freshness (FUR-CMP-010): `as_of` is an explicit evaluation time (never
    wall-clock, for determinism). If the snapshot's evidence is older than an
    assertion's freshness SLO, a would-be PASS becomes STALE — stale evidence
    can never make a control compliant. `as_of` defaults to the snapshot's own
    collected_at (age 0 = fresh).
    """
    as_of = as_of or snapshot.collected_at
    age = _age_seconds(snapshot.collected_at, as_of)
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

        stale = age is not None and age > spec.freshness_slo_seconds
        if stale and status == PASS:
            # cannot claim a control is in place on stale evidence
            status, reason = STALE, "evidence_stale"

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
            "freshness": {
                "as_of": as_of,
                "collected_at": snapshot.collected_at,
                "age_seconds": age,
                "slo_seconds": spec.freshness_slo_seconds,
                "stale": bool(stale),
            },
            "evidence": evidence,
        })
    results.sort(key=lambda r: r["spec_id"])
    return results
