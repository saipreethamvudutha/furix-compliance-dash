"""
versions.py
===========
The single version manifest for the Furix compliance engine (FUR-CMP-017/019).

Every component that stamps a version — findings, policy summaries, reports,
OSCAL exports, the API banner — MUST import from here. A report is only
reproducible if the exact versions that produced it are pinned inside it, so
the whole manifest is embedded in every report payload (inside the content
hash: change a version, change the report identity).

Rules:
  * Never hardcode a version string anywhere else in the engine.
  * Bump ENGINE_VERSION on any change to verdict-affecting logic.
  * SCF_VERSION must match the shipped crosswalk JSON (scf-full-<ver>.json).
"""

from __future__ import annotations

ENGINE_VERSION = "2.2.0"          # verdict-affecting engine logic
REPORT_SCHEMA_VERSION = "2.0"     # report payload shape + status vocabulary
SCF_VERSION = "2026.2"            # matches deploy/source_data/scf-full-2026.2.json
RULE_PACK_VERSION = "POL-15.1"    # the 15 policy rules (bump on rule changes)
SIGMA_PACK_VERSION = "SIG-22.1"   # the 22 Sigma detection rules + technique map
OSCAL_VERSION = "1.2.1"           # OSCAL model version our serialisers emit

VERSION_MANIFEST: dict[str, str] = {
    "engine": ENGINE_VERSION,
    "report_schema": REPORT_SCHEMA_VERSION,
    "scf": SCF_VERSION,
    "rule_pack": RULE_PACK_VERSION,
    "sigma_pack": SIGMA_PACK_VERSION,
    "oscal": OSCAL_VERSION,
}
