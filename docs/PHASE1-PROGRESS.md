# Phase 1 — SCF/PCI Crosswalk: LOCAL WORK COMPLETE

**Done in Opus 4.8, 2026-07-16.** The data-derivation half of Phase 1 is built
and verified against the **real SCF 2026.2 JSON**. The infra half (Postgres +
pgvector + AGE bring-up, `setup_ingestion` embeddings) remains server-side.

## What was built (all locally verified — 49 tests green)

| File | What | Status |
|---|---|---|
| `scf_crosswalk.py` | Pure, zero-dep derivation of CIS↔NIST, HIPAA↔NIST, CIS↔PCI, CIS↔HIPAA crosswalks from `scf-full-2026.2.json`, with provenance. Replaces fragile Excel column-index parsing. | ✅ + 6 tests vs real data |
| `test_scf_crosswalk.py` | Parser unit tests (bare-CIS-int, `§`-prefix HIPAA, NIST subcat filter, PCI `Req N`) + integration test vs the real 1,534-control SCF JSON. | ✅ 6/6 |
| `compliance_reporting/registry.py` | New `from_scf_json()`; `from_live()` now prefers SCF JSON (`FURIX_SCF_JSON`) → furix_det DB → snapshot. Real crosswalks for all 4 frameworks, no DB needed. | ✅ + test |
| `ingest_scf_json.py` | Server ingest: derives via `scf_crosswalk`, writes `cis_to_nist` / `hipaa_to_nist` / **`cis_to_pci`** to `furix_det` with `source_scf_ids` provenance. Correct DB bootstrap (creates furix_det from the `postgres` maintenance DB). | ✅ compiles (server-run) |
| `db_connections.py` | Loads new `CIS_TO_PCI_MAPPINGS`; falls back to deriving all crosswalks from the SCF JSON when `furix_det` is empty. | ✅ compiles (server-run) |

## Real crosswalk numbers (from the actual SCF 2026.2 JSON)

```
cis_to_nist  = 18 CIS controls  → 184 edges   (Control 6 → PR.AA-01/03/04/05, ID.AM-01/02)
hipaa_to_nist=  6 HIPAA sections → 162 edges
cis_to_pci   = 18 CIS controls  →  96 edges   (Control 6 → Req 1/6/7/8/9/11)
```

Proof the reporting layer now uses real crosswalks (demo with `FURIX_SCF_JSON` set):
NIST CSF went from ~14 requirements (snapshot) to **65** (all CIS controls mapped
to their full subcategory sets); PCI now has all 12 requirements; reports still
**verify** (369 checks, 0 failures). The two format gotchas the JSON introduced
(bare CIS integers like `"1"`, and HIPAA values prefixed with `§ `) are handled
and regression-tested.

## Format-key reference (verified; also in PHASE1-DATA-FINDINGS.md)

| Framework | SCF JSON key | value example | parser |
|---|---|---|---|
| CIS v8.1 | `CIS CSC 8.1` | `"1\n2.1\n13.9"` | leading int → `Control N` |
| NIST CSF 2.0 | `NIST CSF 2.0` | `"ID.AM\nID.AM-01"` | keep `^[A-Z]{2}\.[A-Z]{2}-\d{2}$` |
| HIPAA | `US HIPAA Security Rule / NIST SP 800-66 R2` | `"§ 164.308(a)(1)"` | search `164.\d{3}` |
| PCI DSS 4.0 | `PCI DSS 4.0.1` | `"6.3.2\n11.2"` | leading int → `Req N` |

## ⬜ Server-side steps (run on the Ubuntu box; need Postgres)

```bash
# 0) SCF JSON present and env pointed at it (also used by the reporting fallback)
export FURIX_SCF_JSON=/path/to/scf-full-2026.2.json
export PG_HOST=... PG_USER=... PG_PASSWORD=...   # furix_det target

# 1) Populate furix_det crosswalk tables from the SCF JSON
python3 ingest_scf_json.py "$FURIX_SCF_JSON"
#   → "furix_det populated: cis_to_nist=184  hipaa_to_nist=162  cis_to_pci=96 rows"

# 2) Confirm db_connections sees them
python3 -c "import db_connections; print('CIS', len(db_connections.CIS_TO_NIST_MAPPINGS), \
'HIPAA', len(db_connections.HIPAA_TO_NIST_MAPPINGS), 'PCI', len(db_connections.CIS_TO_PCI_MAPPINGS))"
#   → CIS 18 HIPAA 6 PCI 18
```

Note: `db_connections` now falls back to the SCF JSON automatically, so the
reporting layer and crosswalk lookups work even before `ingest_scf_json.py` runs
(as long as `FURIX_SCF_JSON` is set). The furix_det tables are still needed by
the heavy pipeline's own consumers (detection/retrieval engines) and for
provenance/audit queries.

## Still remaining in Phase 1 (server-only, not code)
- Postgres 15 + **pgvector** + **Apache AGE** container (docker-compose).
- `setup_ingestion.py` — chunk + embed the CIS/NIST PDFs into `compliance_chunks`
  (pgvector) and build the AGE `compliance_graph`. Needs the CIS PDF (still
  missing — RAG evidence only) and SecureBERT (CPU ok). NIST PDF is staged
  (`NIST.CSWP.29 (1).pdf`).
- These are the Phase 5 docker-compose + RUNBOOK work.
