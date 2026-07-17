"""
hipaa_data.py
=============
Loads the HIPAA Security Rule JSON file and builds four lookup structures.
This runs once on import — it is a fast JSON read with no DB calls,
no model loading, and no PDF extraction.

Exported for use by retrieval_engine.py:
  hipaa_json            : full parsed HIPAA JSON dict
  CSF_TO_HIPAA_SPECS    : CSF category prefix → list of HIPAA spec codes
                          e.g. "PR.AA" → ["AS-WS-AS", "TS-AC-UUI", ...]
  HIPAA_SPEC_REGISTRY   : spec code → full metadata dict
                          e.g. "AS-SMP-RA" → {name, cfr, csf, ctl, ...}
  MITRE_TACTIC_TO_CSF   : MITRE tactic name → list of NIST CSF category prefixes
  BEHAVIOR_TO_HIPAA_SPEC: user_activity boolean field → list of HIPAA spec codes
"""

import json
from config import HIPAA_JSON_PATH

# ── Load HIPAA JSON ───────────────────────────────────────────────────────────
with open(HIPAA_JSON_PATH) as f:
    hipaa_json = json.load(f)

# ── Index 1: CSF category prefix → list of spec codes ────────────────────────
# e.g. "PR.AA" → ["AS-WS-AS", "TS-AC-UUI", ...]
CSF_TO_HIPAA_SPECS: dict = {}

# ── Index 2: spec code → full metadata ───────────────────────────────────────
# e.g. "AS-SMP-RA" → {name, cfr, csf, ctl, designation, ...}
HIPAA_SPEC_REGISTRY: dict = {}

for _category in hipaa_json["safeguard_categories"]:
    for _standard in _category["standards"]:
        _code = _standard["code"]
        HIPAA_SPEC_REGISTRY[_code] = {
            "name":        _standard["name"],
            "cfr":         _standard["cfr"],
            "csf":         _standard.get("csf", []),
            "ctl":         _standard.get("ctl", []),
            "designation": _standard.get("designation", ""),
            "category":    _category["category"],
        }
        for _csf_cat in _standard.get("csf", []):
            CSF_TO_HIPAA_SPECS.setdefault(_csf_cat, []).append(_code)

        for _spec in _standard.get("specs", []):
            _scode = _spec["code"]
            HIPAA_SPEC_REGISTRY[_scode] = {
                "name":          _spec["name"],
                "cfr":           _spec["cfr"],
                "csf":           _spec.get("csf", []),
                "ctl":           _spec.get("ctl", []),
                "designation":   _spec.get("designation", ""),
                "proposed_2026": _spec.get("proposed_2026", ""),
                "category":      _category["category"],
                "parent_code":   _code,
            }
            for _csf_cat in _spec.get("csf", []):
                CSF_TO_HIPAA_SPECS.setdefault(_csf_cat, []).append(_scode)

print(f"✅ HIPAA JSON indices built")
print(f"   Spec registry entries : {len(HIPAA_SPEC_REGISTRY)}")
print(f"   CSF_TO_HIPAA_SPECS keys (sample): {sorted(CSF_TO_HIPAA_SPECS.keys())[:5]}")

# ── MITRE tactic → CSF category mapping ──────────────────────────────────────
MITRE_TACTIC_TO_CSF: dict = {
    "Initial Access":        ["PR.AA", "PR.IR"],
    "Credential Access":     ["PR.AA", "DE.CM"],
    "Privilege Escalation":  ["PR.AA", "DE.AE"],
    "Lateral Movement":      ["PR.AA", "DE.CM", "RS.MA"],
    "Defense Evasion":       ["DE.CM", "DE.AE"],
    "Exfiltration":          ["PR.DS", "DE.CM", "RS.AN"],
    "Command and Control":   ["DE.CM", "RS.MA"],
    "Persistence":           ["PR.AA", "PR.PS", "DE.CM"],
    "Discovery":             ["DE.CM", "ID.AM"],
    "Collection":            ["PR.DS", "DE.AE"],
    "Impact":                ["PR.DS", "RC.RP", "RS.MA"],
    "Brute Force":           ["PR.AA", "DE.CM", "DE.AE"],
}

# ── Behavioral signal → HIPAA spec code mapping ───────────────────────────────
# Keys match user_activity boolean fields from analyze_log_with_llm()
BEHAVIOR_TO_HIPAA_SPEC: dict = {
    "privilege_escalation_detected": ["AS-WS-AS", "AS-IAM-AA",  "TS-AC-UUI"],
    "failed_logins":                 ["AS-SAT-LM", "TS-PEA",    "TS-AC-UUI"],
    "account_creation_detected":     ["AS-WS-TP",  "AS-IAM-AEM","TS-AC-UUI"],
    "lateral_movement_detected":     ["AS-IAM-IH", "TS-AC",     "TS-TS"],
    "successful_logins":             ["AS-SAT-LM", "TS-AC-UUI"],
}

print(f"✅ MITRE->CSF and behavior->HIPAA spec tables loaded")
