"""
policy_engine.py
================
Phase 3 — Deterministic Policy Evaluation Engine (Stage A findings output).

Sits between Phase 1e (severity correction) and Phase 2 (RAG retrieval) in
run_full_pipeline(). Receives the fully corrected findings dict and raw log,
evaluates 14 signal-based compliance policy rules, and returns a list of
PolicyFinding objects plus a policy_summary dict.

Design decisions (confirmed before coding):
  - Rules are signal-based, NOT log-type-based. They work on the normalised
    findings dict produced by Phases 1–1e, so they fire correctly regardless
    of which log format arrived.
  - NIST IDs come from CIS_TO_NIST_MAPPINGS (already loaded in memory from
    furix_det at startup). No additional DB calls at evaluation time.
  - Only FAIL findings are produced. No PASS sweep — silence means the control
    was not triggered, not that it passed. A policy_summary dict lists which
    controls were evaluated with no violation, giving auditors coverage context
    without polluting the findings list.
  - Composite rules (e.g. failed_logins AND successful_logins) are used where
    production SIEM correlation logic demands it. Single-signal rules are kept
    where the signal is inherently high-fidelity (e.g. account_creation_detected).
  - Every field in PolicyFinding maps directly to an OSCAL Assessment Results
    field for Phase 4 serialisation:
        rule_id          → finding.uuid prefix
        title            → finding.title
        description      → finding.description
        verdict          → finding-target.status.state ("not-satisfied")
        cis_control      → finding-target.target-id
        nist_csf_ids     → related-observations
        hipaa_cfr        → props
        severity         → props
        triggered_field  → observation.description
        triggered_value  → observation.relevant-evidence
        scf_version      → props (provenance)
        timestamp        → observation.collected

Rules implemented (14 total):
  POL-001  Unauthorised Account Creation
  POL-002  Privilege Escalation
  POL-003  Brute Force with Successful Authentication (composite)
  POL-004  Failed Authentication — Standalone
  POL-005  Known CVE Exploitation
  POL-006  Malware or C2 Activity Confirmed (composite)
  POL-007  Multi-Stage Attack — Incident Response Required (composite)
  POL-008  External Source IP on High-Severity Event (composite)
  POL-009  Privilege Escalation from External Source (composite — highest value)
  POL-010  Data Exfiltration or Sensitive Data Access (composite)
  POL-011  CVE with Unpatched Vulnerability Management Control (composite)
  POL-012  Secure Configuration Failure (composite)
  POL-013  Audit Log Integrity Event (composite)
  POL-014  Lateral Movement Detected
"""

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from db_connections import CIS_TO_NIST_MAPPINGS

# ── Constants ─────────────────────────────────────────────────────────────────

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]

# RFC 1918 private address ranges — used by external-IP rules
_RFC1918 = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),  # link-local
    re.compile(r"^::1$"),        # IPv6 loopback
    re.compile(r"^fc"),          # IPv6 ULA
    re.compile(r"^fd"),          # IPv6 ULA
]

# HIPAA CFR sections most commonly cited per CIS control area
# Used to populate hipaa_cfr field without a DB lookup
_CIS_TO_HIPAA: dict = {
    "Control 3":  "164.312",   # Technical Safeguards — data protection
    "Control 4":  "164.312",   # Technical Safeguards — configuration
    "Control 5":  "164.308",   # Administrative Safeguards — workforce security
    "Control 6":  "164.308",   # Administrative Safeguards — access management
    "Control 7":  "164.308",   # Administrative Safeguards — risk analysis
    "Control 8":  "164.312",   # Technical Safeguards — audit controls
    "Control 10": "164.308",   # Administrative Safeguards — malicious software
    "Control 12": "164.312",   # Technical Safeguards — transmission security
    "Control 13": "164.308",   # Administrative Safeguards — security incident
    "Control 17": "164.308",   # Administrative Safeguards — incident response
}

SCF_VERSION = "2026.1"


# ── PolicyFinding dataclass ───────────────────────────────────────────────────

@dataclass
class PolicyFinding:
    """
    One structured compliance policy finding.

    Produced by the policy engine for every rule that fires (verdict=FAIL).
    All fields map directly to OSCAL Assessment Results for Phase 4.
    """
    rule_id:         str            # Stable rule identifier e.g. "POL-001"
    title:           str            # Short human-readable title
    description:     str            # One-sentence finding description
    verdict:         str            # "FAIL" (only value produced; see module docstring)
    cis_control:     str            # e.g. "Control 5"
    nist_csf_ids:    list           # From CIS_TO_NIST_MAPPINGS — list of NIST subcategory IDs
    hipaa_cfr:       str            # e.g. "164.308" or "" if not applicable
    severity:        str            # "critical"|"high"|"medium"|"low"|"informational"
    triggered_field: str            # Which findings field triggered this rule
    triggered_value: Any            # Actual extracted value (IP, CVE ID, True, etc.)
    scf_version:     str = SCF_VERSION
    timestamp:       str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finding_uuid:    str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        """Serialise to plain dict for inclusion in pipeline return dict."""
        return {
            "finding_uuid":    self.finding_uuid,
            "rule_id":         self.rule_id,
            "title":           self.title,
            "description":     self.description,
            "verdict":         self.verdict,
            "cis_control":     self.cis_control,
            "nist_csf_ids":    self.nist_csf_ids,
            "hipaa_cfr":       self.hipaa_cfr,
            "severity":        self.severity,
            "triggered_field": self.triggered_field,
            "triggered_value": self.triggered_value,
            "scf_version":     self.scf_version,
            "timestamp":       self.timestamp,
        }


# ── Helper functions ──────────────────────────────────────────────────────────

def _nist_ids_for(cis_control: str) -> list:
    """
    Returns NIST CSF 2.0 subcategory IDs for a CIS control from the
    in-memory CIS_TO_NIST_MAPPINGS dict (loaded from furix_det at startup).
    Returns empty list if the control is not in the mapping.
    """
    return list(CIS_TO_NIST_MAPPINGS.get(cis_control, []))


def _hipaa_for(cis_control: str) -> str:
    """Returns the most relevant HIPAA CFR section for a CIS control."""
    return _CIS_TO_HIPAA.get(cis_control, "")


def _severity_gte(actual: str, threshold: str) -> bool:
    """Returns True if actual severity is >= threshold in the severity order."""
    try:
        return SEVERITY_ORDER.index(actual) >= SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False


def _mapped_controls(findings: dict) -> set:
    """Returns the set of CIS control IDs mapped by Phase 1d."""
    return set(
        findings.get("cis_controls_mapping", {}).get("control_ids", [])
    )


def _external_ips(findings: dict) -> list:
    """
    Returns source IPs that are NOT RFC1918 / private / loopback.
    These are the IPs that indicate external attacker origin.
    """
    raw_ips = findings.get("source_details", {}).get("source_ip", [])
    return [
        ip for ip in raw_ips
        if ip and not any(pat.match(ip) for pat in _RFC1918)
    ]


def _cves(findings: dict) -> list:
    """Returns CVE IDs present in findings (excludes the placeholder "NAN")."""
    raw = findings.get("threat_intelligence", {}).get("cve_ids", ["NAN"])
    return [c for c in raw if c and c.upper() != "NAN"]


def _make_finding(
    rule_id: str,
    title: str,
    description: str,
    cis_control: str,
    severity: str,
    triggered_field: str,
    triggered_value: Any,
    nist_override: list = None,
    hipaa_override: str = None,
) -> PolicyFinding:
    """
    Factory for PolicyFinding — resolves NIST IDs and HIPAA CFR automatically
    unless overrides are supplied (used for multi-control composite rules).
    """
    return PolicyFinding(
        rule_id         = rule_id,
        title           = title,
        description     = description,
        verdict         = "FAIL",
        cis_control     = cis_control,
        nist_csf_ids    = nist_override if nist_override is not None else _nist_ids_for(cis_control),
        hipaa_cfr       = hipaa_override if hipaa_override is not None else _hipaa_for(cis_control),
        severity        = severity,
        triggered_field = triggered_field,
        triggered_value = triggered_value,
    )


# ── The 15 policy rules ───────────────────────────────────────────────────────

def _pol_001(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-001 — Unauthorised Account Creation
    Signal: user_activity.account_creation_detected == True
    Single-signal rule. Account creation is always a standalone compliance
    finding — it is inherently high-fidelity because Phase 1 only sets this
    flag on specific EventID 4720, CreateUser API calls, useradd commands, etc.
    """
    ua = findings.get("user_activity", {})
    if not ua.get("account_creation_detected"):
        return None

    usernames = ua.get("usernames", [])
    value = usernames if usernames else True

    return _make_finding(
        rule_id         = "POL-001",
        title           = "Unauthorised Account Creation",
        description     = (
            "Account creation detected in log — authorisation must be verified "
            "against approved change records and access management policy."
        ),
        cis_control     = "Control 5",
        severity        = "high",
        triggered_field = "user_activity.account_creation_detected",
        triggered_value = value,
    )


def _pol_002(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-002 — Privilege Escalation Detected
    Signal: user_activity.privilege_escalation_detected == True
    Single-signal. Phase 1 only sets this on specific patterns (sudo, SeBackup,
    key="priv_esc", etc.) so the signal is already high-fidelity.
    """
    ua = findings.get("user_activity", {})
    if not ua.get("privilege_escalation_detected"):
        return None
    # Suppress on confirmed benign logs — authorised sudo operations
    # (e.g. sudo systemctl, sudo rsync) should not generate a violation.
    if is_benign:
        return None
    primary = findings.get("security_findings", {}).get("primary_finding", "")
    value = primary[:200] if primary else True

    return _make_finding(
        rule_id         = "POL-002",
        title           = "Privilege Escalation Detected",
        description     = (
            "Privilege escalation activity detected — review against least-privilege "
            "policy and authorised change records to confirm this was an approved action."
        ),
        cis_control     = "Control 6",
        severity        = "high",
        triggered_field = "user_activity.privilege_escalation_detected",
        triggered_value = value,
    )


def _pol_003(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-003 — Brute Force with Successful Authentication (COMPOSITE)
    Signal: failed_logins == True AND successful_logins == True
    This is the highest-value authentication finding — a confirmed credential
    compromise following a brute force campaign. Severity is critical because
    it indicates active breach, not just an attempt.
    """
    ua = findings.get("user_activity", {})
    if not (ua.get("failed_logins") and ua.get("successful_logins")):
        return None

    usernames = ua.get("usernames", [])
    value = usernames if usernames else True

    return _make_finding(
        rule_id         = "POL-003",
        title           = "Brute Force with Successful Authentication",
        description     = (
            "Failed authentication attempts followed by a successful login detected — "
            "this pattern indicates a likely credential compromise following brute force. "
            "Immediate account review and MFA verification required."
        ),
        cis_control     = "Control 6",
        severity        = "critical",
        triggered_field = "user_activity.failed_logins + user_activity.successful_logins",
        triggered_value = value,
    )


def _pol_004(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-004 — Failed Authentication Attempts (Standalone)
    Signal: failed_logins == True AND successful_logins == False
    Separated from POL-003. Failed logins alone are medium severity — they
    indicate an attempt, not a confirmed breach.
    """
    ua = findings.get("user_activity", {})
    if not ua.get("failed_logins"):
        return None
    if ua.get("successful_logins"):
        return None  # POL-003 covers this case

    usernames = ua.get("usernames", [])
    value = usernames if usernames else True

    return _make_finding(
        rule_id         = "POL-004",
        title           = "Failed Authentication Attempts",
        description     = (
            "Failed authentication attempts detected without a subsequent successful "
            "login — review account lockout policy and brute-force protection controls."
        ),
        cis_control     = "Control 6",
        severity        = "medium",
        triggered_field = "user_activity.failed_logins",
        triggered_value = value,
    )


def _pol_005(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-005 — Known CVE Exploitation
    Signal: cve_ids != ["NAN"]
    Single-signal. CVE IDs are extracted by exact regex match in Phase 1 —
    the signal is definitionally high-fidelity because it requires a verbatim
    CVE-YYYY-NNNNN string in the log.
    """
    cves = _cves(findings)
    if not cves:
        return None

    return _make_finding(
        rule_id         = "POL-005",
        title           = "Known CVE Exploitation Detected",
        description     = (
            f"CVE identifier(s) {cves} detected in log — verify patch status and "
            "confirm affected systems are remediated within the required SLA."
        ),
        cis_control     = "Control 7",
        severity        = "high",
        triggered_field = "threat_intelligence.cve_ids",
        triggered_value = cves,
    )


def _pol_006(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-006 — Malware or C2 Activity Confirmed (COMPOSITE)
    Signal: Control 10 in mapped controls AND severity >= high
    Composite because severity has been corrected by two deterministic rounds
    before Phase 3 runs. Control 10 + high/critical = keyword engine found
    specific malware signals AND severity correction confirmed them.
    """
    controls = _mapped_controls(findings)
    if "Control 10" not in controls:
        return None
    if not _severity_gte(findings.get("severity", "low"), "high"):
        return None

    primary = findings.get("security_findings", {}).get("primary_finding", "")
    value = primary[:200] if primary else findings.get("severity", "high")

    return _make_finding(
        rule_id         = "POL-006",
        title           = "Malware or C2 Activity Confirmed",
        description     = (
            "Malware or command-and-control activity confirmed at high or critical "
            "severity — EDR containment, malware defence review, and incident "
            "declaration procedures must be activated immediately."
        ),
        cis_control     = "Control 10",
        severity        = "critical",
        triggered_field = "cis_controls_mapping.control_ids + findings.severity",
        triggered_value = value,
    )


def _pol_007(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-007 — Multi-Stage Attack, Incident Response Required (COMPOSITE)
    Signal: Control 17 in mapped controls AND severity >= high
    Control 17 only fires in the keyword engine when 3+ attack stages are
    present. Combined with high/critical severity this is a reliable active
    incident indicator.
    """
    controls = _mapped_controls(findings)
    if "Control 17" not in controls:
        return None
    if not _severity_gte(findings.get("severity", "low"), "high"):
        return None

    primary = findings.get("security_findings", {}).get("primary_finding", "")
    value = primary[:200] if primary else findings.get("severity", "high")

    return _make_finding(
        rule_id         = "POL-007",
        title           = "Multi-Stage Attack — Incident Response Required",
        description     = (
            "Multiple attack stages detected at high or critical severity — "
            "incident response plan must be activated, chain of custody preserved, "
            "and affected systems isolated pending forensic investigation."
        ),
        cis_control     = "Control 17",
        severity        = "critical",
        triggered_field = "cis_controls_mapping.control_ids + findings.severity",
        triggered_value = value,
    )


def _pol_008(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-008 — External Source IP on High-Severity Event (COMPOSITE)
    Signal: non-RFC1918 source IP present AND severity >= high
    External IP alone is informational. External IP on a high-severity event
    changes the risk profile — it indicates the attack origin is outside the
    network perimeter, affecting network control assessments.
    """
    if not _severity_gte(findings.get("severity", "low"), "high"):
        return None
    ext_ips = _external_ips(findings)
    if not ext_ips:
        return None

    return _make_finding(
        rule_id         = "POL-008",
        title           = "External Source IP on High-Severity Event",
        description     = (
            f"External IP address(es) {ext_ips} detected as source on a high or "
            "critical severity event — network access controls, firewall rules, and "
            "ingress filtering must be reviewed."
        ),
        cis_control     = "Control 12",
        severity        = "high",
        triggered_field = "source_details.source_ip + findings.severity",
        triggered_value = ext_ips,
    )


def _pol_009(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-009 — Privilege Escalation from External Source (COMPOSITE — highest value)
    Signal: privilege_escalation_detected == True AND non-RFC1918 source IP present
    This is the exact pattern Google's privileged account monitoring highlights
    as the strongest confirmed compromise indicator: external source + privilege
    escalation = almost certainly an active attack, not a legitimate operation.
    Maps to both Control 6 (access control) and Control 12 (network infra).
    Also extracts IPs directly from raw_log as a fallback for log formats
    (e.g. Okta JSON) where the findings dict source_ip may be empty.
    """
    if is_benign:
        return None
    ua = findings.get("user_activity", {})
    if not ua.get("privilege_escalation_detected"):
        return None

    # Primary: use IPs from findings dict
    ext_ips = _external_ips(findings)

    # Fallback: extract directly from raw_log for formats like Okta JSON
    # where ipAddress field may not have been captured in source_details
    if not ext_ips:
        _raw_ip_re = re.compile(
            r'(?:ipAddress|sourceIPAddress|src_ip|callerIp|'
            r'sourceIp|client_ip|remoteIp)\s*[=:"\'\\s]+([0-9]{1,3}(?:\.[0-9]{1,3}){3})',
            re.IGNORECASE
        )
        raw_ips = list(dict.fromkeys(_raw_ip_re.findall(raw_log)))
        ext_ips = [
            ip for ip in raw_ips
            if ip and not any(pat.match(ip) for pat in _RFC1918)
        ]

    if not ext_ips:
        return None

    # Composite NIST IDs: union of Control 6 and Control 12 mappings
    nist_combined = list(dict.fromkeys(
        _nist_ids_for("Control 6") + _nist_ids_for("Control 12")
    ))

    return PolicyFinding(
        rule_id         = "POL-009",
        title           = "Privilege Escalation from External Source",
        description     = (
            f"Privilege escalation detected originating from external IP(s) {ext_ips} — "
            "this combination is a strong indicator of active compromise. Immediate "
            "account suspension, network isolation, and incident response required."
        ),
        verdict         = "FAIL",
        cis_control     = "Control 6 + Control 12",
        nist_csf_ids    = nist_combined,
        hipaa_cfr       = "164.308",
        severity        = "critical",
        triggered_field = "user_activity.privilege_escalation_detected + source_details.source_ip",
        triggered_value = ext_ips,
    )


def _pol_010(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-010 — Data Exfiltration or Sensitive Data Access (COMPOSITE)
    Signal: Control 3 in mapped controls AND severity >= medium
    Control 3 alone at low severity could be routine. At medium or above it
    indicates the data access is anomalous and requires compliance review.
    """
    controls = _mapped_controls(findings)
    if "Control 3" not in controls:
        return None
    if not _severity_gte(findings.get("severity", "low"), "medium"):
        return None

    primary = findings.get("security_findings", {}).get("primary_finding", "")
    value = primary[:200] if primary else True

    return _make_finding(
        rule_id         = "POL-010",
        title           = "Data Exfiltration or Sensitive Data Access",
        description     = (
            "Data protection control triggered at medium or above severity — "
            "review data access logs against data classification policy, DLP controls, "
            "and authorised data handling procedures."
        ),
        cis_control     = "Control 3",
        severity        = "high",
        triggered_field = "cis_controls_mapping.control_ids + findings.severity",
        triggered_value = value,
    )


def _pol_011(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-011 — CVE with Unpatched Vulnerability Management Control (COMPOSITE)
    Signal: Control 7 in mapped controls AND cve_ids != ["NAN"]
    Stronger than POL-005. Control 7 fires when the keyword engine found
    vulnerability management signals (scan findings, unpatched service indicators)
    in addition to the CVE ID. The combination means both detection and the
    underlying patch process failure are evident in the same log.
    """
    controls = _mapped_controls(findings)
    if "Control 7" not in controls:
        return None
    cves = _cves(findings)
    if not cves:
        return None

    return _make_finding(
        rule_id         = "POL-011",
        title           = "CVE Exploitation with Vulnerability Management Gap",
        description     = (
            f"CVE(s) {cves} detected alongside vulnerability management control signals — "
            "this indicates both exploitation and a patch management process failure. "
            "Verify patch schedule compliance and remediate immediately."
        ),
        cis_control     = "Control 7",
        severity        = "high",
        triggered_field = "cis_controls_mapping.control_ids + threat_intelligence.cve_ids",
        triggered_value = cves,
    )


def _pol_012(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-012 — Secure Configuration Failure (COMPOSITE)
    Signal: Control 4 in mapped controls AND severity >= medium
    Configuration issues at low severity are informational. At medium or above
    they represent exploitable misconfigurations requiring compliance review.
    """
    controls = _mapped_controls(findings)
    if "Control 4" not in controls:
        return None
    if not _severity_gte(findings.get("severity", "low"), "medium"):
        return None

    primary = findings.get("security_findings", {}).get("primary_finding", "")
    value = primary[:200] if primary else True

    return _make_finding(
        rule_id         = "POL-012",
        title           = "Secure Configuration Failure",
        description     = (
            "Secure configuration control triggered at medium or above severity — "
            "review baseline hardening standards, CIS benchmark compliance, and "
            "change management records for the affected asset."
        ),
        cis_control     = "Control 4",
        severity        = "medium",
        triggered_field = "cis_controls_mapping.control_ids + findings.severity",
        triggered_value = value,
    )


def _pol_013(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-013 — Audit Log Integrity Event (COMPOSITE)
    Signal: Control 8 in mapped controls AND severity >= medium
    Audit log events at low severity are routine collection. At medium or above
    they indicate anomalous log activity — tampering, deletion, or unexpected
    log patterns — which directly impacts auditability and compliance evidence.
    """
    controls = _mapped_controls(findings)
    if "Control 8" not in controls:
        return None
    if not _severity_gte(findings.get("severity", "low"), "medium"):
        return None

    return _make_finding(
        rule_id         = "POL-013",
        title           = "Audit Log Integrity Event",
        description     = (
            "Audit log management control triggered at medium or above severity — "
            "verify log integrity, completeness, and centralisation. Investigate "
            "any log tampering, deletion, or unexpected gaps in audit trail."
        ),
        cis_control     = "Control 8",
        severity        = "medium",
        triggered_field = "cis_controls_mapping.control_ids + findings.severity",
        triggered_value = findings.get("severity", "medium"),
    )


def _pol_014(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-014 — Lateral Movement Detected
    Signal: user_activity.lateral_movement_detected == True
    Single-signal. Phase 1 only sets this on specific patterns (SMB lateral,
    pass-the-hash indicators, rapid multi-system access). High-fidelity signal.
    """
    ua = findings.get("user_activity", {})
    if not ua.get("lateral_movement_detected"):
        return None

    primary = findings.get("security_findings", {}).get("primary_finding", "")
    value = primary[:200] if primary else True

    return _make_finding(
        rule_id         = "POL-014",
        title           = "Lateral Movement Detected",
        description     = (
            "Lateral movement indicators present in log — network segmentation, "
            "east-west traffic monitoring controls, and host isolation procedures "
            "must be reviewed and activated."
        ),
        cis_control     = "Control 13",
        severity        = "high",
        triggered_field = "user_activity.lateral_movement_detected",
        triggered_value = value,
    )

def _pol_015(findings: dict, raw_log: str, is_benign: bool = False):
    """
    POL-015 — Cloud Privileged Role Assignment (COMPOSITE)
    Signal: Control 6 in mapped controls AND Control 15 in mapped controls
            AND severity >= high
    Captures cloud IAM privilege escalation patterns that do not trigger
    privilege_escalation_detected (which is OS-level) — e.g. Global Admin
    role added in Azure AD, roles/owner assigned in GCP, AdministratorAccess
    attached in CloudTrail. The combination of Control 6 (access) + Control 15
    (cloud service provider) at HIGH severity is specific to this pattern.
    """
    if is_benign:
        return None
    controls = _mapped_controls(findings)
    if "Control 6" not in controls or "Control 15" not in controls:
        return None
    if not _severity_gte(findings.get("severity", "low"), "high"):
        return None

    primary = findings.get("security_findings", {}).get("primary_finding", "")
    ext_ips = _external_ips(findings)
    value   = ext_ips if ext_ips else (primary[:200] if primary else True)

    nist_combined = list(dict.fromkeys(
        _nist_ids_for("Control 6") + _nist_ids_for("Control 15")
    ))

    return PolicyFinding(
        rule_id         = "POL-015",
        title           = "Cloud Privileged Role Assignment",
        description     = (
            "Privileged cloud role assignment detected at high or critical severity — "
            "verify this role change is authorised, review IAM policies, and confirm "
            "MFA was enforced for the account performing the assignment."
        ),
        verdict         = "FAIL",
        cis_control     = "Control 6 + Control 15",
        nist_csf_ids    = nist_combined,
        hipaa_cfr       = "164.308",
        severity        = "high",
        triggered_field = "cis_controls_mapping.control_ids + findings.severity",
        triggered_value = value,
    )
# ── Rule registry — ordered by severity priority ──────────────────────────────
# Evaluated in this order. Each rule is a callable taking (findings, raw_log)
# and returning PolicyFinding | None.

_RULES = [
    _pol_009,  # highest value composite first — external + priv esc
    _pol_015,  # cloud privileged role assignment (high) ← add here
    _pol_003,  # brute force + success (critical)
    _pol_007,  # multi-stage attack (critical)
    _pol_006,  # malware / C2 (critical)
    _pol_001,  # account creation (high)
    _pol_002,  # privilege escalation (high)
    _pol_005,  # CVE exploitation (high)
    _pol_011,  # CVE + vuln mgmt gap (high)
    _pol_008,  # external IP + high severity (high)
    _pol_010,  # data exfiltration (high)
    _pol_014,  # lateral movement (high)
    _pol_004,  # failed auth standalone (medium)
    _pol_012,  # secure config failure (medium)
    _pol_013,  # audit log event (medium)
]


# ── Main entry point ──────────────────────────────────────────────────────────

def evaluate_policy(findings: dict, raw_log: str, is_benign: bool = False) -> tuple:
    """
    Evaluate all 14 policy rules against the normalised findings dict.

    Called by run_full_pipeline() between Phase 1e and Phase 2.

    Args:
        findings:   The fully corrected findings dict from Phases 1–1e.
        raw_log:    The original raw log string (available for rules that
                    need to inspect specific log content beyond the findings).

    Returns:
        (policy_findings, policy_summary) where:
          policy_findings: list of PolicyFinding.to_dict() for each rule that
                           fired (verdict=FAIL). Empty list if no violations.
          policy_summary:  dict with evaluation metadata:
            {
              "rules_evaluated":   14,
              "violations_found":  N,
              "rules_fired":       ["POL-001", ...],
              "controls_violated": ["Control 5", ...],
              "controls_evaluated_clean": ["Control 12", ...],
              "log_severity":      "high",
              "scf_version":       "2026.1",
            }
    """
    sep = "-" * 72
    print(f"\n{sep}")
    print("  PHASE 3 — POLICY EVALUATION ENGINE")
    print(f"  Log severity : {findings.get('severity', 'unknown').upper()}")
    print(f"  Mapped controls: {_mapped_controls(findings)}")
    print(sep)

    fired_findings  = []
    fired_rule_ids  = []

    for rule_fn in _RULES:
        try:
            result = rule_fn(findings, raw_log, is_benign)
            if result is not None:
                fired_findings.append(result)
                fired_rule_ids.append(result.rule_id)
                print(f"  [{result.rule_id}] FAIL  {result.title}")
                print(f"           Control  : {result.cis_control}")
                print(f"           Severity : {result.severity.upper()}")
                print(f"           Field    : {result.triggered_field}")
                val_str = str(result.triggered_value)
                print(f"           Value    : {val_str[:120]}")
        except Exception as e:
            print(f"  [RULE ERROR] {rule_fn.__name__}: {e} — skipping rule")

    if not fired_findings:
        print("  No policy violations detected.")

    # Controls that were mapped but had no violation rule fire
    all_mapped = _mapped_controls(findings)
    violated   = set()
    for pf in fired_findings:
        # Handle composite control labels like "Control 6 + Control 12"
        for part in pf.cis_control.split("+"):
            violated.add(part.strip())
    clean = sorted(all_mapped - violated)
    controls_rule_only = sorted(violated - all_mapped)

    policy_summary = {
        "rules_evaluated":          len(_RULES),
        "violations_found":         len(fired_findings),
        "rules_fired":              fired_rule_ids,
        "controls_violated":        sorted(violated & all_mapped),
        "controls_rule_only":       controls_rule_only,
        "controls_evaluated_clean": clean,
        "log_severity":             findings.get("severity", "unknown"),
        "scf_version":              SCF_VERSION,
    }

    print(f"\n  Summary: {len(fired_findings)} violation(s) found across "
          f"{len(violated & all_mapped)} control(s)")
    if clean:
        print(f"  Controls with no violation : {clean}")
    print(sep)

    return (
        [pf.to_dict() for pf in fired_findings],
        policy_summary,
    )