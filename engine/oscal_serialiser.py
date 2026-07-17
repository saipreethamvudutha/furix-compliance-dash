"""
oscal_serialiser.py
===================
Phase 4 — OSCAL Assessment Results JSON serialiser.

Takes the policy_findings and policy_summary produced by Phase 3
(policy_engine.py) and serialises them into a valid OSCAL Assessment
Results document conforming to oscal_assessment-results_schema.json.

OSCAL structure produced:
  assessment-results
    metadata          — run timestamp, tool version, SCF version
    import-ap         — reference to the assessment plan (stub)
    results[]         — one result per pipeline run
      reviewed-controls — which CIS controls were in scope
      observations[]  — one per policy_finding (the evidence)
      findings[]      — one per policy_finding (the verdict)
        target        — finding-target with status.state = "not-satisfied"
        props[]       — rule_id, cis_control, severity, hipaa_cfr, scf_version
        related-observations[] — links finding to its observation

Design decisions:
  - One OSCAL file per pipeline run (all logs in one assessment-results doc)
  - Each PolicyFinding → one observation + one finding pair
  - NIST CSF IDs → related-observations (each NIST subcategory gets its
    own observation entry so auditors can trace evidence to framework)
  - Only FAIL findings are serialised (no satisfied/pass entries)
  - policy_summary → result.props (rules_evaluated, violations_found, etc.)
  - File written to OUTPUT_DIR as YYYYMMDDHHMMSS_oscal_ar.json

Called by pipeline.py after complete_log_pipeline_run() finishes,
receiving the aggregated findings from all logs in the run.
"""

import json
import uuid
import os
from datetime import datetime, timezone

from config import OUTPUT_DIR

# SCF version — matches policy_engine.py
_SCF_VERSION   = "2026.1"
_OSCAL_VERSION = "1.1.2"
_TOOL_NAME     = "Furix Deterministic Compliance Pipeline"
_TOOL_VERSION  = "2.0.0"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _prop(name: str, value: str, ns: str = None) -> dict:
    """Build an OSCAL property object."""
    p = {"name": name, "value": str(value)}
    if ns:
        p["ns"] = ns
    return p


def _finding_to_oscal(pf: dict) -> tuple:
    """
    Convert one PolicyFinding dict to an (observation, finding) OSCAL pair.

    Returns:
        observation: OSCAL observation object (the evidence)
        finding:     OSCAL finding object (the verdict)
    """
    obs_uuid     = pf.get("finding_uuid", _uuid())
    finding_uuid = _uuid()

    # ── Observation ───────────────────────────────────────────────────────────
    # Captures the raw evidence: what field triggered the rule,
    # what value was found, and when.
    triggered_value = pf.get("triggered_value", "")
    if not isinstance(triggered_value, str):
        triggered_value = json.dumps(triggered_value)

    observation = {
        "uuid":        obs_uuid,
        "title":       f"Evidence for {pf.get('rule_id', 'UNKNOWN')} — {pf.get('title', '')}",
        "description": (
            f"Rule {pf.get('rule_id')} triggered on field "
            f"'{pf.get('triggered_field', '')}'. "
            f"Observed value: {triggered_value[:500]}"
        ),
        "methods":  ["AUTOMATED"],
        "types":    ["finding"],
        "collected": pf.get("timestamp", _now()),
        "relevant-evidence": [
            {
                "description": (
                    f"Field '{pf.get('triggered_field', '')}' "
                    f"produced value: {triggered_value[:500]}"
                )
            }
        ],
        "props": [
            _prop("rule-id",      pf.get("rule_id",     "")),
            _prop("cis-control",  pf.get("cis_control", "")),
            _prop("severity",     pf.get("severity",    "")),
            _prop("scf-version",  pf.get("scf_version", _SCF_VERSION)),
        ],
    }

    # Add HIPAA CFR if present
    if pf.get("hipaa_cfr"):
        observation["props"].append(_prop("hipaa-cfr", pf["hipaa_cfr"]))

    # Add NIST CSF subcategory IDs as individual props
    for nist_id in pf.get("nist_csf_ids", []):
        if nist_id and nist_id != "NAN":
            observation["props"].append(_prop("nist-csf-id", nist_id))

    # ── Finding ───────────────────────────────────────────────────────────────
    # The verdict: which control, what status, why it failed.
    finding = {
        "uuid":        finding_uuid,
        "title":       pf.get("title", ""),
        "description": pf.get("description", ""),
        "target": {
            "type":      "objective-id",
            "target-id": pf.get("cis_control", "unknown").replace(" ", "-").lower(),
            "status": {
                "state":  "not-satisfied",
                "reason": "fail",
            },
            "props": [
                _prop("cis-control",  pf.get("cis_control", "")),
                _prop("severity",     pf.get("severity",    "")),
            ],
        },
        "props": [
            _prop("rule-id",      pf.get("rule_id",     "")),
            _prop("cis-control",  pf.get("cis_control", "")),
            _prop("severity",     pf.get("severity",    "")),
            _prop("scf-version",  pf.get("scf_version", _SCF_VERSION)),
            _prop("verdict",      pf.get("verdict",     "FAIL")),
        ],
        "related-observations": [
            {"observation-uuid": obs_uuid}
        ],
    }

    if pf.get("hipaa_cfr"):
        finding["props"].append(_prop("hipaa-cfr", pf["hipaa_cfr"]))

    return observation, finding


def _build_reviewed_controls(all_controls_in_scope: set) -> dict:
    """
    Build the reviewed-controls section listing all CIS controls
    that were in scope for this assessment run.
    """
    control_selections = []
    for ctrl in sorted(all_controls_in_scope):
        control_selections.append({
            "include-controls": [
                {"control-id": ctrl.replace(" ", "-").lower()}
            ]
        })

    return {
        "description": (
            "CIS Controls v8.1.2 evaluated during this assessment run. "
            "Mapping sourced from SCF 2026.1 via furix_det database."
        ),
        "control-selections": control_selections if control_selections else [
            {"include-all": {}}
        ],
    }


# ── Main serialiser ───────────────────────────────────────────────────────────

def serialise_run(
    all_log_results: list,
    run_timestamp:   str = None,
) -> dict:
    """
    Build a complete OSCAL Assessment Results document from all log results
    in a pipeline run.

    Args:
        all_log_results: List of run_full_pipeline() return dicts — one per log.
                         Each must contain 'policy_findings' and 'policy_summary'.
        run_timestamp:   ISO8601 UTC string for the run start time.
                         Defaults to now if not provided.

    Returns:
        Complete OSCAL Assessment Results dict ready for json.dumps().
    """
    run_timestamp = run_timestamp or _now()
    ar_uuid       = _uuid()
    result_uuid   = _uuid()

    # ── Collect all findings and observations across all logs ─────────────────
    all_observations    = []
    all_findings        = []
    all_controls        = set()
    total_violations    = 0
    total_logs          = len(all_log_results)
    logs_with_violations = 0
    rule_frequency      = {}

    for log_result in all_log_results:
        policy_findings = log_result.get("policy_findings", [])
        policy_summary  = log_result.get("policy_summary",  {})
        log_type        = log_result.get("_log_type", "unknown")

        if not policy_findings:
            continue

        logs_with_violations += 1
        total_violations     += len(policy_findings)

        for pf in policy_findings:
            # Track controls in scope
            for part in pf.get("cis_control", "").split("+"):
                c = part.strip()
                if c:
                    all_controls.add(c)

            # Track rule frequency
            rule_id = pf.get("rule_id", "UNKNOWN")
            rule_frequency[rule_id] = rule_frequency.get(rule_id, 0) + 1

            # Add log_type as a prop to each finding for traceability
            pf_with_log = dict(pf)
            obs, finding = _finding_to_oscal(pf_with_log)

            # Tag observation with log type for traceability
            obs["props"].append(_prop("log-type", log_type))
            obs["props"].append(_prop("log-severity",
                                      log_result.get("findings", {})
                                      .get("severity", "unknown")))

            all_observations.append(obs)
            all_findings.append(finding)

    # ── Build result props from aggregate summary ─────────────────────────────
    result_props = [
        _prop("tool-name",            _TOOL_NAME),
        _prop("tool-version",         _TOOL_VERSION),
        _prop("scf-version",          _SCF_VERSION),
        _prop("total-logs-evaluated", str(total_logs)),
        _prop("logs-with-violations", str(logs_with_violations)),
        _prop("total-violations",     str(total_violations)),
        _prop("controls-in-scope",    str(len(all_controls))),
    ]

    # Add rule frequency as individual props
    for rule_id, count in sorted(rule_frequency.items()):
        result_props.append(_prop(f"rule-frequency-{rule_id}", str(count)))

    # ── Assemble the full OSCAL document ──────────────────────────────────────
    oscal_doc = {
        "assessment-results": {
            "uuid": ar_uuid,
            "metadata": {
                "title":          f"Furix Compliance Assessment — {run_timestamp[:10]}",
                "last-modified":  _now(),
                "version":        run_timestamp,
                "oscal-version":  _OSCAL_VERSION,
                "props": [
                    _prop("tool-name",    _TOOL_NAME),
                    _prop("tool-version", _TOOL_VERSION),
                    _prop("scf-version",  _SCF_VERSION),
                ],
                "roles": [
                    {
                        "id":    "assessor",
                        "title": "Automated Assessment Engine",
                    }
                ],
                "parties": [
                    {
                        "uuid":  _uuid(),
                        "type":  "tool",
                        "name":  _TOOL_NAME,
                    }
                ],
            },
            "import-ap": {
                "href": "#furix-assessment-plan",
                "remarks": (
                    "Assessment plan stub. Replace with actual OSCAL Assessment "
                    "Plan UUID when a formal plan is established."
                ),
            },
            "results": [
                {
                    "uuid":        result_uuid,
                    "title":       f"Compliance Assessment Run — {run_timestamp}",
                    "description": (
                        f"Automated compliance assessment of {total_logs} security log "
                        f"events against CIS Controls v8.1.2, NIST CSF 2.0, and HIPAA "
                        f"Security Rule. Crosswalk sourced from SCF {_SCF_VERSION}. "
                        f"Found {total_violations} policy violation(s) across "
                        f"{logs_with_violations} log(s)."
                    ),
                    "start":              run_timestamp,
                    "end":                _now(),
                    "props":              result_props,
                    "reviewed-controls":  _build_reviewed_controls(all_controls),
                    "observations":       all_observations,
                    "findings":           all_findings,
                }
            ],
        }
    }

    return oscal_doc


def write_oscal_file(
    all_log_results: list,
    run_timestamp:   str = None,
) -> str:
    """
    Serialise all log results to an OSCAL Assessment Results JSON file.

    Args:
        all_log_results: List of run_full_pipeline() return dicts.
        run_timestamp:   ISO8601 UTC string for the run start time.

    Returns:
        Path to the written OSCAL JSON file.
    """
    run_timestamp = run_timestamp or _now()
    oscal_doc     = serialise_run(all_log_results, run_timestamp)

    # Build filename: YYYYMMDDHHMMSS_oscal_ar.json
    ts_slug = run_timestamp.replace("-", "").replace(":", "").replace("T", "").replace("Z", "")[:14]
    filename = f"{ts_slug}_oscal_ar.json"
    filepath = os.path.join(OUTPUT_DIR, filename)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(oscal_doc, f, indent=2, ensure_ascii=False)

    findings_count     = len(oscal_doc["assessment-results"]["results"][0]["findings"])
    observations_count = len(oscal_doc["assessment-results"]["results"][0]["observations"])

    print(f"\n{'=' * 72}")
    print(f"  PHASE 4 — OSCAL ASSESSMENT RESULTS WRITTEN")
    print(f"  File       : {filepath}")
    print(f"  Findings   : {findings_count}")
    print(f"  Observations: {observations_count}")
    print(f"  OSCAL ver  : {_OSCAL_VERSION}")
    print(f"  SCF ver    : {_SCF_VERSION}")
    print(f"{'=' * 72}\n")

    return filepath
