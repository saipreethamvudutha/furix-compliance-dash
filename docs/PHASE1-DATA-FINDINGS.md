# Phase 1 Data Prep — Findings (for Opus 4.8)

**Authored in Fable 5, 2026-07-16.** Companion to `HANDOVER-PLAN-OPUS.md`.
Read this before executing Phase 1 (§3 of the plan). It resolves the plan's
open data questions and changes one recommendation.

---

## 1. Data is located (working dir: `/Users/preetham/compliance research/`)

| Prerequisite | Status | Path |
|---|---|---|
| **SCF 2026.2 workbook (.xlsx)** | ✅ present | `SCF-2026-2/Secure Controls Framework (SCF) - 2026.2.xlsx` |
| **SCF 2026.2 machine-readable JSON** | ✅ present (use this) | `SCF-2026-2/JSON/scf-full-2026.2.json` (22 MB) |
| **NIST CSF 2.0 PDF** | ✅ present | `NIST.CSWP.29 (1).pdf` (NIST CSWP 29 = CSF 2.0) |
| **CIS Controls v8.1 PDF** | ❌ still needed | for `setup_ingestion` RAG evidence embeddings only |

Also in the SCF package (bonus, for later framework expansion / OSCAL work):
`SCF-2026-2/JSON/oscal-catalog-2026.2.json` (78 MB) and
`oscal-assessment-plan-2026.2.json`.

**Version note:** this is SCF **2026.2**, but the current
`phase1_scf_ingest.py` hard-codes sheet name `"SCF 2026.1"` and column indices
verified against 2026.1. Column positions can drift between releases — another
reason to switch to the JSON (below).

---

## 2. RECOMMENDATION: ingest from the SCF JSON, not the xlsx columns

The current `phase1_scf_ingest.py` reads the workbook by hard-coded column
index (`COL_CIS_V8=37`, `COL_NIST_CSF=102`, `COL_HIPAA_ADMIN=156`,
`COL_HIPAA_SEC=157`). The 2026.2 JSON exposes the **same data as a structured
per-control `mappings` dict**, keyed by framework name. This is version-proof
(no column drift), needs no openpyxl, and answers the "PCI column index"
question entirely — PCI is just another key.

**JSON shape** (`scf-full-2026.2.json`):
```
{ "metadata": {...}, "domains": [...], "controls": [ <control>, ... ], ... }

<control> = {
  "scf_id": "AST-02",
  "scf_domain": "...",
  "scf_control_name": "Asset Inventories",
  "description": "...",
  "nist_csf_function_grouping": "Identify",
  "mappings": { "<framework name>": "<newline-separated ids>", ... },
  ...
}
```

**Exact mapping keys for our 4 frameworks** (verified against the file):

| Framework | JSON key (exact) | Value example |
|---|---|---|
| CIS Controls v8.1 | `CIS CSC 8.1` | `"1\n1.1\n2\n2.1\n13.9"` |
| NIST CSF 2.0 | `NIST CSF 2.0` | `"ID.AM\nID.AM-01\nID.AM-02"` |
| HIPAA Security Rule | `US HIPAA Security Rule / NIST SP 800-66 R2` | `"§ 164.308(a)(7)(ii)(E)\n§ 164.310(d)(1)"` |
| HIPAA Admin (optional 2nd) | `US HIPAA Administrative Simplification 2013` | same shape |
| PCI DSS 4.0.1 | `PCI DSS 4.0.1` | `"6.3.2\n9.5.1\n11.2\n11.2.2"` |

Ignore the IG1/IG2/IG3 and PCI SAQ variants (`CIS CSC 8.1 IG1`,
`PCI DSS 4.0.1 SAQ A`, …) — use the base keys above.

**Coverage across the 1,534 SCF controls:** CIS 234 · NIST CSF 250 · HIPAA
(Security Rule) 136 · PCI 371. Good density for real crosswalks.

**Value format = newline-separated string** — identical to the xlsx cells, so
the existing `_split_cell()` helper works unchanged. The rest of the existing
derivation logic reuses cleanly:
- `_cis_safeguard_to_control()` turns `13.9` / `1` → `"Control 13"` / `"Control 1"`.
- NIST validity filter `^[A-Z]{2}\.[A-Z]{2}-\d{2}$` keeps subcategories
  (`ID.AM-01`), drops bare categories (`ID.AM`).
- `_extract_hipaa_cfr_section()` regex `(164\.\d{3})` turns
  `§ 164.308(a)(7)...` → `164.308`.

---

## 3. NEW work for PCI (the one genuinely new parser)

PCI values are dotted requirement ids like `6.3.2`, `9.5.1`, `11.2`. For the
`cis_to_pci` table, derive the **parent requirement** = the leading integer
before the first dot → `Req N`:
```
"6.3.2" → "Req 6"     "11.2.2" → "Req 11"     "9.5.1.1" → "Req 9"
```
(Mirror how CIS safeguards collapse to parent controls.) Then build
`cis_to_pci` exactly like `cis_to_nist` is built: for each SCF control that has
BOTH a `CIS CSC 8.1` mapping and a `PCI DSS 4.0.1` mapping, take the Cartesian
product of (derived CIS controls × derived PCI requirements) and upsert edges
with `source_scf_ids` provenance.

---

## 4. Concrete Phase 1 adjustments to the plan

1. **Refactor `phase1_scf_ingest.py`** to read `scf-full-2026.2.json` (parameter:
   `SCF_JSON_PATH` env) instead of the xlsx. Keep the xlsx path as a fallback if
   you want, but JSON is primary. Drop the sheet-name / column-index constants.
2. **Add `cis_to_pci`** table + the `Req N` parser (§3). Add
   `CIS_TO_PCI_MAPPINGS` load in `db_connections.py`; make
   `FrameworkRegistry.from_live()` read real PCI (replaces the snapshot stub).
3. **NIST CSF PDF for `setup_ingestion`**: use `NIST.CSWP.29 (1).pdf`. Rename to
   something stable (e.g. `nist_csf_2.0.pdf`) when copying into
   `engine/bootstrap/data/`.
4. **CIS Controls v8.1 PDF is still missing** — the only remaining data gap. It
   feeds `setup_ingestion`'s RAG evidence chunks (pgvector). Impact if absent:
   the verdict + control/framework mapping are UNAFFECTED (those come from the
   SCF crosswalk + policy engine); only the retrieved *evidence text* for CIS is
   empty. Acceptable to bootstrap without it and add later. Ask the user, but do
   not block Phase 1 on it.

**Net effect:** Phase 1's data is unblocked except for the optional CIS PDF, and
the fragile column-index / version-mismatch risk is eliminated by moving to the
SCF JSON. Update `HANDOVER-PLAN-OPUS.md` §3b and §8 accordingly when you start.
