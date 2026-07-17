# Phase 0 — Pipeline Hardening: COMPLETE

**Done in Opus 4.8, 2026-07-16. Edits made in place in `Furix_compliance_1/`.**
All changes are import-safety / configurability only — **no compliance logic
changed**. The 42 `compliance_reporting` tests remain green.

## What changed (6 edits across 5 files)

| # | File | Change | Why |
|---|---|---|---|
| 1 | `pipeline.py` | Wrapped the smoke-test block (~L445) **and** the batch execution block (~L957) in `if __name__ == "__main__":` | `import pipeline` no longer runs a full batch / per-log pipeline. The API can import `run_full_pipeline` safely. |
| 2 | `pipeline.py` | Import-time `os.makedirs(DLQ_DIR)` wrapped in try/except; `_dlq_save` self-heals the dir | Import never crashes on an unwritable default `OUTPUT_DIR`; real DLQ writes still work. |
| 3 | `models.py` | `device="cuda"` → `_resolve_device()` (env `FURIX_DEVICE`, else auto-detect CUDA, else CPU) | Boots on a CPU-only box instead of crashing on hard-coded cuda. |
| 4 | `config.py` | DB creds + all source paths + `OUTPUT_DIR` + `LOG_INPUT_PATH` → `os.environ.get(...)` with current values as defaults; added `SCF_JSON_PATH` | Containerizable; deployment injects config via env. `SCF_JSON_PATH` readies Phase 1. |
| 5 | `detection_engine.py` | Removed the 4 local redefinitions of `SEVERITY_ORDER`, `SEVERITY_FLOOR`, `BENIGN_SEVERITY_CEILING`, `STRUCTURED_RISK_LOG_TYPES` (byte-identical to config) | Config is now the single source of truth; tuning it actually takes effect. **Zero behavior change** (values were identical). |
| 6 | `retrieval_engine.py` | Close `cur`/`conn` before the success return in `retrieve_cis_controls_llm` | Fixes a PG connection leak of one connection **per ingested log** that would exhaust the pool on the API server. |

## New environment variables (all optional; safe defaults preserved)

```
# compute
FURIX_DEVICE=cpu|cuda|mps           # default: auto-detect

# data paths (deployment sets these; defaults = original /home/yashwanth layout)
FURIX_DATA_DIR=/path/to/source_data # base dir for the files below
FURIX_CIS_PDF=...                    # CIS Controls v8.1 PDF (optional; RAG evidence only)
FURIX_NIST_PDF=...                   # NIST CSF 2.0 PDF  → use NIST.CSWP.29 (1).pdf
FURIX_HIPAA_JSON=...                 # HIPAA security rule JSON
FURIX_SCF_JSON=...                   # SCF 2026.2 JSON → scf-full-2026.2.json (Phase 1)
FURIX_OUTPUT_DIR=/path/to/output     # reports, DLQ, run logs
FURIX_LOG_INPUT=/path/to/incoming_logs.txt

# database (Postgres + pgvector + AGE)
PG_HOST PG_PORT PG_DBNAME PG_DBNAME_DET PG_USER PG_PASSWORD

# Gemma / Ollama (already existed)
GEMMA_MODEL  GEMMA_BASE_URL          # point at the Ollama host on the server
```

## Local verification done (in this environment)

- `python3 -m py_compile config.py models.py pipeline.py detection_engine.py retrieval_engine.py` → all compile.
- `config` env override proven (PG_HOST/PG_PORT/OUTPUT_DIR/SCF_JSON_PATH resolve from env; defaults preserved when unset).
- Both driver blocks confirmed under `__main__`; only a harmless `logs_failed_in_DLQ = []` global init remains at module level.
- `compliance_reporting` suites: **23 + 10 + 9 = 42 tests green** (unchanged).

Full `import pipeline` + a live single-log run can't run here (needs
torch/sentence-transformers + a populated DB) — that's the server check below.

## ⬜ Server-side verification (run on the Ubuntu box, once DB + models are up)

```bash
cd <engine dir with pipeline.py>

# 1) Prove import has zero side effects (no batch, no crash):
FURIX_DEVICE=cpu python3 -c "import pipeline; print('import OK — no batch ran')"

# 2) Single-log smoke through the real pipeline:
python3 -c "
from pipeline import run_full_pipeline, SAMPLE_LOGS
r = run_full_pipeline(SAMPLE_LOGS['cloudtrail'], log_type='cloudtrail')
print('failure_stage:', r['_failure_stage'])
print('cis_controls :', r['compliance_mapping']['cis_controls'])
print('policy_findings:', len(r['policy_findings']))
"
```
Expected: import prints "no batch ran" (no long pipeline output); the smoke run
returns `failure_stage: None` (or `rag_retrieval` if the DB isn't populated yet)
with a non-empty `cis_controls` list once `furix_det` + `compliance_chunks` are
bootstrapped (Phase 1).

## Next (still local, no server needed)
Refactor `phase1_scf_ingest.py` to read `scf-full-2026.2.json` per
`PHASE1-DATA-FINDINGS.md` (exact keys + PCI `Req N` parser), and add the
`cis_to_pci` table. Then assemble the `furix-compliance/` monorepo (plan §1).
