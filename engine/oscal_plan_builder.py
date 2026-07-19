"""
oscal_plan_builder.py
=====================
Phase 4 companion — generates a valid OSCAL 1.1.2 Assessment Plan document.

The Assessment Plan is what import-ap in the Assessment Results file
references. Without it, the import-ap link is unresolvable and strict
OSCAL validators generate a warning. This file fixes that.

What an OSCAL Assessment Plan defines:
  - Who is being assessed (the system / organisation)
  - Who is doing the assessing (the tool / assessor)
  - What the scope is (which controls are in scope)
  - What the methodology is (how evidence is collected)
  - What the objectives are (what pass/fail criteria look like)

Usage:
  Run once per engagement to generate the plan file:
      python oscal_plan_builder.py

  Or import and call build_assessment_plan() to generate programmatically:
      from oscal_plan_builder import write_assessment_plan
      plan_path, plan_uuid = write_assessment_plan(
          system_name="Acme Corp Production Environment",
          system_id="acme-prod-001",
          assessor_org="Furix Security",
      )

  The returned plan_uuid should be used to update oscal_serialiser.py's
  import-ap href to point to the actual plan file instead of the stub.

Output:
  Writes OSCAL_AP_<system_id>.json to OUTPUT_DIR.
  The Assessment Results import-ap href should be updated to reference
  this file: "href": "OSCAL_AP_<system_id>.json"

OSCAL Assessment Plan required fields (schema v1.1.2):
  assessment-plan:
    uuid, metadata, import-ssp, reviewed-controls, assessment-subjects,
    assessment-assets, tasks
"""

import json
import uuid
import os
from datetime import datetime, timezone

from config import OUTPUT_DIR

# Single version source (FUR-CMP-017)
try:
    from compliance_reporting.versions import (
        ENGINE_VERSION as _TOOL_VERSION,
        OSCAL_VERSION as _OSCAL_VERSION,
        SCF_VERSION as _SCF_VERSION,
    )
except ImportError:
    _SCF_VERSION, _OSCAL_VERSION, _TOOL_VERSION = "2026.2", "1.1.2", "2.2.0"
_TOOL_NAME     = "Furix Deterministic Compliance Pipeline"


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _prop(name: str, value: str, ns: str = None) -> dict:
    p = {"name": name, "value": str(value)}
    if ns:
        p["ns"] = ns
    return p


def build_assessment_plan(
    system_name:   str = "Target System",
    system_id:     str = "target-system-001",
    assessor_org:  str = "Furix Security",
    assessor_email: str = "",
    scope_note:    str = "",
) -> dict:
    """
    Build a complete OSCAL Assessment Plan dict.

    Args:
        system_name:    Human-readable name of the system being assessed.
        system_id:      Machine-readable ID slug for the system.
        assessor_org:   Organisation performing the assessment.
        assessor_email: Contact email for the assessor (optional).
        scope_note:     Free-text scope description (optional).

    Returns:
        Complete OSCAL Assessment Plan dict ready for json.dumps().
    """
    plan_uuid    = _uuid()
    now          = _now()
    assessor_uuid = _uuid()
    system_uuid  = _uuid()

    # ── CIS Controls in scope ─────────────────────────────────────────────────
    # All 18 CIS Controls v8.1.2 are in scope for this assessment methodology.
    # The policy engine evaluates 15 rules covering Controls 3-17.
    cis_controls_in_scope = [
        {"control-id": f"control-{i}"} for i in range(1, 19)
    ]

    # ── Assessment objectives per CIS control ────────────────────────────────
    # Each objective maps to the policy rules that evaluate it.
    objectives = [
        {
            "uuid":        _uuid(),
            "description": (
                "Evaluate security log events against CIS Controls v8.1.2 using "
                "deterministic signal-based rules. Each control is assessed by "
                "analysing normalised log findings for specific violation signals. "
                "Evidence is collected automatically from log content."
            ),
            "props": [
                _prop("methodology",   "Automated log analysis"),
                _prop("evidence-type", "Security event logs"),
                _prop("rules-engine",  f"{_TOOL_NAME} v{_TOOL_VERSION}"),
                _prop("scf-version",   _SCF_VERSION),
                _prop("nist-csf",      "2.0"),
                _prop("hipaa-rule",    "Security Rule (45 CFR Part 164)"),
            ],
        }
    ]

    # ── Assessment tasks ──────────────────────────────────────────────────────
    tasks = [
        {
            "uuid":        _uuid(),
            "type":        "action",
            "title":       "Phase 0 — Threat Density Assessment",
            "description": (
                "Scan raw log for threat and benign signal patterns. "
                "Compute net threat score. Set is_benign flag. "
                "Apply severity floors for structured risk log types."
            ),
            "props": [_prop("phase", "0")],
        },
        {
            "uuid":        _uuid(),
            "type":        "action",
            "title":       "Phase 1 — Deterministic Log Analysis",
            "description": (
                "Extract entities (IPs, CVEs, usernames, boolean activity flags) "
                "from raw log using compiled regex patterns. No LLM used for known "
                "log types. Map CIS Controls using weighted keyword rule engine (~200 "
                "patterns). Apply severity corrections."
            ),
            "props": [_prop("phase", "1")],
        },
        {
            "uuid":        _uuid(),
            "type":        "action",
            "title":       "Phase 3 — Policy Evaluation",
            "description": (
                "Evaluate 15 signal-based compliance policy rules against normalised "
                "findings. Rules are log-format-agnostic — they operate on the "
                "standardised findings dict. Produce PolicyFinding objects for each "
                "violation. No PASS sweep — silence means not triggered."
            ),
            "props": [
                _prop("phase",      "3"),
                _prop("rules",      "POL-001 through POL-015"),
                _prop("scf-source", f"SCF {_SCF_VERSION} via furix_det database"),
            ],
        },
        {
            "uuid":        _uuid(),
            "type":        "action",
            "title":       "Phase 2 — Evidence Retrieval (RAG)",
            "description": (
                "Retrieve relevant compliance evidence chunks from pgvector store "
                "using SecureBERT-768 embeddings. Scope NIST CSF queries using "
                "SCF-derived CIS→NIST crosswalk. Apply Apache AGE graph expansion "
                "for related controls. Rerank with cross-encoder ensuring minimum "
                "7 CIS / 5 NIST / 5 HIPAA results per log."
            ),
            "props": [
                _prop("phase",        "2"),
                _prop("embed-model",  "cisco-ai/SecureBERT2.0-biencoder"),
                _prop("rerank-model", "cisco-ai/SecureBERT2.0-cross_encoder"),
            ],
        },
        {
            "uuid":        _uuid(),
            "type":        "action",
            "title":       "Phase 4 — OSCAL Assessment Results Output",
            "description": (
                "Serialise all PolicyFinding objects to OSCAL 1.1.2 Assessment "
                "Results JSON. Each finding produces one observation (evidence) "
                "and one finding (verdict with status.state = not-satisfied). "
                "Write timestamped file to output directory."
            ),
            "props": [
                _prop("phase",         "4"),
                _prop("oscal-version", _OSCAL_VERSION),
                _prop("output-format", "JSON"),
            ],
        },
    ]

    # ── Assemble full plan ────────────────────────────────────────────────────
    plan = {
        "assessment-plan": {
            "uuid": plan_uuid,
            "metadata": {
                "title":         f"Furix Compliance Assessment Plan — {system_name}",
                "last-modified": now,
                "version":       now,
                "oscal-version": _OSCAL_VERSION,
                "props": [
                    _prop("tool-name",    _TOOL_NAME),
                    _prop("tool-version", _TOOL_VERSION),
                    _prop("scf-version",  _SCF_VERSION),
                    _prop("system-id",    system_id),
                ],
                "roles": [
                    {"id": "assessor",      "title": "Automated Assessor"},
                    {"id": "system-owner",  "title": "System Owner"},
                ],
                "parties": [
                    {
                        "uuid":          assessor_uuid,
                        "type":          "organization",
                        "name":          assessor_org,
                        "email-addresses": [assessor_email] if assessor_email else [],
                    },
                    {
                        "uuid": system_uuid,
                        "type": "organization",
                        "name": system_name,
                    },
                ],
                "responsible-parties": [
                    {
                        "role-id":     "assessor",
                        "party-uuids": [assessor_uuid],
                    },
                    {
                        "role-id":     "system-owner",
                        "party-uuids": [system_uuid],
                    },
                ],
            },
            # import-ssp is required by OSCAL but may reference a stub
            # if no formal System Security Plan exists yet.
            "import-ssp": {
                "href": f"#system-security-plan-{system_id}",
                "remarks": (
                    "System Security Plan stub. Replace with actual OSCAL SSP "
                    "document URI when a formal SSP is established."
                ),
            },
            "reviewed-controls": {
                "description": (
                    f"CIS Controls v8.1.2 — all 18 controls in scope for this "
                    f"assessment. Crosswalk to NIST CSF 2.0 and HIPAA Security Rule "
                    f"sourced from SCF {_SCF_VERSION}. Assessment covers automated "
                    f"log analysis for {system_name}."
                    + (f" Scope: {scope_note}" if scope_note else "")
                ),
                "control-selections": [
                    {
                        "description":    "CIS Controls v8.1.2 — all 18 controls",
                        "include-controls": cis_controls_in_scope,
                    }
                ],
                "control-objective-selections": [
                    {
                        "description": "Policy rule evaluation against log signals",
                        "include-all": {},
                    }
                ],
            },
            "assessment-subjects": [
                {
                    "uuid":  _uuid(),
                    "type":  "component",
                    "title": f"Security Logs — {system_name}",
                    "description": (
                        "Security event logs submitted for compliance assessment. "
                        "Supported formats: syslog, Windows EVTX, AWS CloudTrail, "
                        "GCP Audit, Azure AD, Okta SSO, Suricata IDS, Zeek, "
                        "CrowdStrike Falcon, Microsoft Defender, Palo Alto, "
                        "Cisco ASA, EDR, DNS, O365, VPN, DHCP, auditd, "
                        "Wazuh SIEM, nmap, and generic formats."
                    ),
                    "props": [
                        _prop("system-id",  system_id),
                        _prop("log-formats", "25 known + generic fallback"),
                    ],
                    "include-all": {},
                }
            ],
            "assessment-assets": {
                "components": [
                    {
                        "uuid":           _uuid(),
                        "type":           "software",
                        "title":          _TOOL_NAME,
                        "description":    (
                            f"{_TOOL_NAME} v{_TOOL_VERSION}. Deterministic compliance "
                            f"mapping engine. No LLM on critical path for known log types. "
                            f"SCF {_SCF_VERSION} crosswalk sourced from furix_det database."
                        ),
                        "props": [
                            _prop("tool-version",  _TOOL_VERSION),
                            _prop("scf-version",   _SCF_VERSION),
                            _prop("oscal-version", _OSCAL_VERSION),
                            _prop("embed-model",   "cisco-ai/SecureBERT2.0-biencoder"),
                            _prop("rerank-model",  "cisco-ai/SecureBERT2.0-cross_encoder"),
                        ],
                        "status": {"state": "operational"},
                        "responsible-roles": [
                            {"role-id": "assessor", "party-uuids": [assessor_uuid]}
                        ],
                    }
                ]
            },
            "tasks": tasks,
            "local-definitions": {
                "objectives-and-methods": objectives,
            },
        }
    }

    return plan, plan_uuid


def write_assessment_plan(
    system_name:    str = "Target System",
    system_id:      str = "target-system-001",
    assessor_org:   str = "Furix Security",
    assessor_email: str = "",
    scope_note:     str = "",
) -> tuple:
    """
    Build and write an OSCAL Assessment Plan JSON file.

    Returns:
        (file_path, plan_uuid) — the path to the written file and the
        plan UUID to use in Assessment Results import-ap href.
    """
    plan, plan_uuid = build_assessment_plan(
        system_name=system_name,
        system_id=system_id,
        assessor_org=assessor_org,
        assessor_email=assessor_email,
        scope_note=scope_note,
    )

    filename = f"OSCAL_AP_{system_id}.json"
    filepath = os.path.join(OUTPUT_DIR, filename)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(plan, f, indent=2, ensure_ascii=False)

    ctrl_count = len(
        plan["assessment-plan"]["reviewed-controls"]
        ["control-selections"][0]["include-controls"]
    )
    task_count = len(plan["assessment-plan"]["tasks"])

    print(f"\n{'=' * 72}")
    print(f"  OSCAL ASSESSMENT PLAN WRITTEN")
    print(f"  File           : {filepath}")
    print(f"  Plan UUID      : {plan_uuid}")
    print(f"  System         : {system_name}")
    print(f"  Controls       : {ctrl_count} (CIS Controls v8.1.2 — all 18)")
    print(f"  Tasks          : {task_count} (Phases 0, 1, 2, 3, 4)")
    print(f"  OSCAL version  : {_OSCAL_VERSION}")
    print(f"  SCF version    : {_SCF_VERSION}")
    print(f"\n  To link Assessment Results to this plan, set import-ap href to:")
    print(f'    "href": "{filename}"')
    print(f"{'=' * 72}\n")

    return filepath, plan_uuid


def update_ar_import_ap(ar_filepath: str, plan_filename: str) -> None:
    """
    Update an existing Assessment Results JSON file to point import-ap
    at the real Assessment Plan file instead of the stub.

    Args:
        ar_filepath:    Path to the OSCAL Assessment Results JSON file.
        plan_filename:  Filename of the Assessment Plan (e.g. OSCAL_AP_acme.json).
    """
    with open(ar_filepath, encoding="utf-8") as f:
        ar = json.load(f)

    old_href = ar["assessment-results"]["import-ap"]["href"]
    ar["assessment-results"]["import-ap"]["href"] = plan_filename
    ar["assessment-results"]["import-ap"].pop("remarks", None)

    with open(ar_filepath, "w", encoding="utf-8") as f:
        json.dump(ar, f, indent=2, ensure_ascii=False)

    print(f"✅ Updated {ar_filepath}")
    print(f"   import-ap: {old_href!r} → {plan_filename!r}")


if __name__ == "__main__":
    import sys

    # Default: generate a plan for a generic target system
    # Override by passing system_name, system_id, assessor_org as args
    system_name  = sys.argv[1] if len(sys.argv) > 1 else "Target System"
    system_id    = sys.argv[2] if len(sys.argv) > 2 else "target-system-001"
    assessor_org = sys.argv[3] if len(sys.argv) > 3 else "Furix Security"

    plan_path, plan_uuid = write_assessment_plan(
        system_name=system_name,
        system_id=system_id,
        assessor_org=assessor_org,
    )

    # Optionally update the most recent Assessment Results file
    # Find most recent oscal_ar.json in OUTPUT_DIR
    try:
        from config import OUTPUT_DIR as _od
        ar_files = sorted(
            [f for f in os.listdir(_od) if f.endswith("_oscal_ar.json")],
            reverse=True
        )
        if ar_files:
            ar_path = os.path.join(_od, ar_files[0])
            update_ar_import_ap(ar_path, os.path.basename(plan_path))
    except Exception as e:
        print(f"  Note: Could not auto-update Assessment Results: {e}")
        print(f"  Run update_ar_import_ap() manually if needed.")
