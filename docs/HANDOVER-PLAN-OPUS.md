# Furix Compliance — End-to-End Product Build
## Handover Plan (authored in Fable 5 → execute in Opus 4.8)

**Goal:** one deployable repo that ingests security logs, runs the **full Furix
compliance pipeline**, and shows the resulting multi-framework compliance report
in the Furix-branded **secureguard** dashboard. Deploys on an Ubuntu server for
testing. Manual log ingestion now; synthetic log generator scaffolded for later.

**Decisions locked with the user (do not re-litigate):**
- **Engine path = FULL heavy Furix pipeline** — real Postgres + pgvector +
  Apache AGE + SecureBERT embeddings + Ollama/Gemma. Not the lite path.
- **Frameworks = 4 (CIS v8, NIST CSF, HIPAA, PCI DSS) from the REAL SCF 2026.1
  workbook**, extendable to more later. No bundled-snapshot shortcut in prod.
- **Single-tenant MVP** — matches the dashboard's localStorage demo auth.
  Multi-tenant (tenant_id + RLS) is explicitly future work (see §9).

> This plan is the single source of truth for the build. Work the phases in
> order; each has an explicit **exit criterion**. Do not start Phase N+1 until
> Phase N's exit criterion is met and its tests are green.

---

## 0. Current state (what already exists)

**`/Users/preetham/compliance/Furix_compliance_1/`** — the cloned Furix repo:
- The heavy pipeline: `pipeline.py` (`run_full_pipeline(raw_log, log_type)` is
  the per-log entry point), `detection_engine.py`, `policy_engine.py`,
  `retrieval_engine.py`, `phase1_scf_ingest.py`, `setup_ingestion.py`,
  `oscal_serialiser.py`, `oscal_plan_builder.py`, `config.py`, `models.py`,
  `db_connections.py`, `log_ingest.py`, `hipaa_data.py`.
- **`compliance_reporting/`** — the NEW zero-dependency reporting engine we
  built (KEEP AND REUSE — this is the reporting/verification/history/diff layer):
  - `report_builder.py` (three-layer rollup + hash seal), `verifier.py`
    (independent recompute, ~220 checks), `render_html.py`, `registry.py`
    (catalogs + crosswalk, `.from_live()` reads furix_det), `history.py`
    (durable ReportStore), `diff.py` (+ alerts), `delivery.py` (console/JSONL/
    webhook sinks), `settings.py`, `__main__.py` (CLI), `pyproject.toml`.
  - **`detection/`** — the ATT&CK/Sigma pivot (log→technique→control), zero-dep.
    In the HEAVY path this is OPTIONAL/secondary (the heavy pipeline's own
    `validate_and_correct_cis_mapping` does control mapping). Keep it available
    as a cross-check and for the future lite mode; do not delete.
  - Tests all green: 23 reporting + 10 detection + 9 delivery.

**`/Users/preetham/compliance/secureguard/`** — the dashboard:
- Next.js 15 (App Router, TypeScript, Tailwind v4, Radix UI, Recharts,
  lucide-react). Furix-branded (`public/furix-logo-new.png`).
- Auth: localStorage demo only, 4 roles (BYOC Admin, SOC Analyst, Compliance
  Auditor, mssp). RBAC context in `src/lib/rbac/`. Role dashboards + tiers.
- **Data seam already exists**: `src/lib/data/*.ts` functions with the literal
  comment *"Replace the body of each function with an API call."*
  `getComplianceFrameworks()` in `src/lib/data/compliance.ts` returns
  `ComplianceFramework[]`.
- Routes present: `/compliance`, `/findings`, `/siem`, `/detection-rules`,
  `/knowledge-graph`, `/risk-scoring`, `/reports`, `/alerts`, `/ai-actions`,
  `/assets`, `/vulnerabilities`, `/settings`, `/login`, etc.
- Two data systems coexist: the `src/lib/data/*` functions (the API seam) and a
  `src/lib/mock/views.ts` "ViewBlock" system + `useCoventraStats` hook used by
  some pages. **Wire the `src/lib/data/*` seam first**; migrate ViewBlock/
  coventra-stats consumers to real data in Phase 3.

**Reference material (read for the Furix-style dashboard roadmap, not to copy):**
`/Users/preetham/compliance research/vanta-teardown-2026.md` and
`vanta-technical-deep-dive-2026.md`. Key lesson: the product is **5 disciplined
filterable-table screens** (Tests, Controls, Frameworks, Framework-detail,
Ingestion/Integrations) — craft is in counts, rollups, status pills, filters,
and readiness rings, not visual novelty.

---

## 1. Target repo layout (Opus creates this)

Create a new monorepo **`/Users/preetham/compliance/furix-compliance/`**:

```
furix-compliance/
├── engine/                       # Python — the compliance brain
│   ├── furix_pipeline/           # ← Furix_compliance_1 moved here (hardened)
│   │   ├── pipeline.py  detection_engine.py  policy_engine.py
│   │   ├── retrieval_engine.py  phase1_scf_ingest.py  setup_ingestion.py
│   │   ├── config.py  models.py  db_connections.py  log_ingest.py ...
│   │   └── compliance_reporting/ # the reporting/verify/history/diff/adapter layer
│   │       └── adapters/dashboard.py   # NEW: report → ComplianceFramework[]
│   └── bootstrap/                # ingestion bootstrap scripts (SCF, PDFs, graph)
├── api/                          # FastAPI backend (the ONLY heavy-dep layer besides ML)
│   ├── main.py  ingestion.py  jobs.py  settings.py  requirements.txt
├── log_generator/                # synthetic log generation (scaffold now, fill later)
│   └── generate.py
├── dashboard/                    # secureguard moved here, wired to the API
├── deploy/                       # docker-compose, Dockerfiles, nginx, systemd, .env.example
├── docs/                         # this plan + runbook + API contract
└── README.md
```

Use `git mv` / `cp -R` to relocate the two existing trees; preserve git history
where reasonable but a fresh repo is acceptable (it's a test deployment).

---

## 2. Phase 0 — Pipeline hardening (MUST come first)

The heavy pipeline is not import-safe or containerizable as-is. Fix these before
anything wraps it. Each fix has a file + line anchor (verified this session).

1. **Import-time batch run** — `pipeline.py` bottom (~lines 945–948):
   ```python
   pipeline_results = complete_log_pipeline_run()   # runs a FULL batch on import!
   logs_failed_in_DLQ = run_dlq_and_malformed()
   ```
   Wrap the entire bottom driver in `if __name__ == "__main__":`. The API imports
   `run_full_pipeline`; it must not trigger a batch. Also guard the smoke test
   near line ~446.
2. **Hardcoded CUDA** — `models.py` lines 21 & 36 (`device="cuda"`). Replace with
   an env-configurable device: `FURIX_DEVICE` env, default auto-detect
   (`"cuda" if torch.cuda.is_available() else "cpu"`). The test Ubuntu box may be
   CPU-only; the server must still boot (slower embeddings, acceptable).
3. **Hardcoded DB credentials** — `config.py` lines 39–44 (`PG_HOST`, `PG_USER`,
   `PG_PASSWORD`, `PG_DBNAME`, `PG_DBNAME_DET`). Move ALL to `os.environ.get(...)`
   with the current values as dev defaults, so docker-compose injects them.
   `LLM_MODEL`/`MY_BASE_URL` already read env — follow that pattern.
4. **detection_engine.py config shadowing** — it re-defines `SEVERITY_ORDER`,
   `SEVERITY_FLOOR`, `BENIGN_SEVERITY_CEILING`, `STRUCTURED_RISK_LOG_TYPES`
   locally, shadowing the `config.py` imports. Remove the local redefinitions so
   config is the single source (documented in the earlier code walkthrough).
5. **Retrieval connection leak** — `retrieve_cis_controls_llm` in
   `retrieval_engine.py` only closes its PG connection on the error path. Wrap in
   try/finally so the API process doesn't leak a connection per ingested log.
6. **Expose a clean single-log entrypoint** — confirm `run_full_pipeline(raw_log,
   log_type="auto")` returns the result dict with `_failure_stage`,
   `policy_findings`, `compliance_mapping`, `findings`, etc. (it does). The API
   will call this per log line. Do NOT use `complete_log_pipeline_run()` (that's
   the file-driven batch driver with stdout teeing).

**Exit criterion:** `python -c "import pipeline"` runs with **zero side effects**
(no batch, no DB writes), and `run_full_pipeline` works on one sample log against
a populated DB. Keep the 42 `compliance_reporting` tests green.

---

## 3. Phase 1 — Infrastructure & data bootstrap

Stand up the stateful services and populate them. This is the heaviest phase.

**3a. Services (docker-compose in `deploy/`):**
- **`db`** — Postgres 15 with **both** `pgvector` and **Apache AGE** extensions.
  Simplest: base off `apache/age` (Postgres-15-based) and add pgvector, or build
  a small custom image installing both. Create two databases: `furix_compliance`
  (pgvector `compliance_chunks` + AGE graph `compliance_graph`) and `furix_det`
  (SCF crosswalk tables). Note the known bootstrap quirk in `phase1_scf_ingest`
  (`PG_ADMIN_DB="furix_det"` — the CREATE DATABASE path assumes it exists; script
  is idempotent on re-run). Handle first-run DB creation in the bootstrap script.
- **`ollama`** — serves Gemma for the DLQ/unknown-format path only. Pull the
  model named by `GEMMA_MODEL` (default `gemma4:e4b`; confirm with user). Point
  `GEMMA_BASE_URL` at the container. This path is rarely hit for the 25 known log
  types, so a CPU Ollama is tolerable for testing.
- **`api`** and **`web`** — added in Phases 2–3.

**3b. One-time data bootstrap (`engine/bootstrap/`), orchestrated by a script:**
1. `phase1_scf_ingest.py` — needs the **real SCF 2026.1 workbook (.xlsx)**
   (USER MUST PROVIDE — see §8). Populates `furix_det` with `cis_to_nist` and
   `hipaa_to_nist`. **ADD PCI:** define `COL_PCI_DSS` (find the real column index
   in the workbook — CIS=37/NIST=102/HIPAA=156-157 are known; PCI is a different
   column), build a `cis_to_pci` table the same way `cis_to_nist` is built.
2. `db_connections.py` — add `CIS_TO_PCI_MAPPINGS` loaded from `furix_det`
   alongside the existing `CIS_TO_NIST_MAPPINGS` / `HIPAA_TO_NIST_MAPPINGS`.
3. `compliance_reporting/registry.py` — `FrameworkRegistry.from_live()` should
   load real `cis_to_pci` from `db_connections` instead of the snapshot (we
   currently stub PCI from snapshot; upgrade to real). Keep snapshot as offline
   fallback only.
4. `setup_ingestion.py` — needs the **CIS Controls PDF**, **NIST CSF PDF**, and
   HIPAA JSON (`hipaa_data.py` is in-repo). Chunks + embeds via SecureBERT into
   `compliance_chunks` (pgvector) and builds the AGE `compliance_graph`. This is
   slow on CPU; run once at deploy time, persist the DB volume.
5. `db_connections.verify_connections()` — must pass (pgvector table exists, AGE
   graph exists, furix_det has crosswalk rows).

**3c. Model warm-load:** the API process imports `models.py` once at startup and
holds `embedder` + `reranker` in memory (SecureBERT bi-encoder + cross-encoder).
Budget **≥16 GB RAM** on the box; note GPU is optional but ~10× faster.

**Exit criterion:** `verify_connections()` all-green; `run_full_pipeline` on the
CloudTrail sample returns a result with non-empty `compliance_mapping`
(cis_controls incl. real NIST + HIPAA + PCI ids) and `policy_findings`.

---

## 4. Phase 2 — API layer (FastAPI, wraps the real pipeline)

`api/` — the seam between the engine and the dashboard. This is where FastAPI +
uvicorn live (the engine core stays zero-dep; the API is allowed heavy deps).

**Adapter first — `compliance_reporting/adapters/dashboard.py`:**
Map our report → the dashboard's `ComplianceFramework[]` contract (from
`secureguard/src/lib/data/types.ts`):
```
ComplianceFramework { id, name, shortName, totalControls, metControls,
  inProgressControls, gapControls, naControls, percentage, controls[] }
ComplianceControl { id, reference, title, description, plainLanguage,
  status: "met"|"gap"|"in-progress"|"na", systems[{name,status,detail}],
  aiRecommendation? }
```
Status mapping (our model → dashboard):
- our framework requirement `compliant` → control `met`
- our `at_risk` → `gap`
- our `not_monitored` → `na` (or `in-progress` if you prefer to signal "no rule yet")
- `percentage` = our `compliance_pct`; counts map to met/gap/na tallies.
- `reference` = the framework requirement id (e.g. `PR.AA-01`, `§164.312`, `Req 8`).
- `title`/`description` = control title + CIS control description.
- `plainLanguage` = short human phrasing (reuse `_CONTROL_SENTENCES` from
  detection_engine, or a small lookup).
- `systems[]` = the evidence rows / log sources that triggered the control
  (from our report's control → tests → evidence chain: log_type + triggered_value).
- `aiRecommendation` = policy finding remediation text (or a templated
  "Investigate {rule}; {control} at risk from {technique}" from the ATT&CK
  provenance). This is where the Vanta "AI remediation" feel comes from — keep
  it deterministic/templated for MVP, real LLM later.

Write a unit test asserting the adapter output validates against the TS shape
(shape-check in Python; a couple of golden fixtures).

**Endpoints (`api/main.py`):**
- `POST /api/ingest` — body: `{ text?: string, log_type?: "auto" }` or multipart
  file upload. Split into log lines (respect the one-event-per-line model in
  `log_ingest.py`; use `detect_log_type` for auto). For each line run
  `run_full_pipeline`. Collect results → `build_report(results)` →
  `verify_report` (reject on failure) → `ReportStore.save(report, batch=results)`
  → return `{ report_id, summary, framework_pct }`. **Long-running:** heavy
  pipeline is seconds-per-log; run ingest as a background job (see `jobs.py`) and
  return a job id the dashboard polls. For MVP a synchronous small-batch path is
  acceptable with a spinner.
- `GET  /api/frameworks?report=latest|<id>` — adapter → `ComplianceFramework[]`.
- `GET  /api/reports` — list (from `ReportStore.entries()`).
- `GET  /api/report/{id}` — full report JSON.
- `GET  /api/report/{id}/html` — `render_html_report`.
- `GET  /api/trend` — `ReportStore.trend()` (posture over time).
- `GET  /api/diff?old=<id>&new=<id>` — `diff_reports` + `alerts_from_diff`.
- `GET  /api/jobs/{job_id}` — ingest job status.
- `POST /api/generate` — (Phase 4) trigger the log generator, then ingest.
- Alerts: on each new report, run diff vs previous and `deliver_alerts` via
  `settings.build_sinks()` (console + JSONL now; webhook if `FURIX_ALERT_WEBHOOK`
  set). Surface alerts at `GET /api/alerts`.

**`jobs.py`:** simplest durable option = a small in-process background task +
status in Postgres (a `jobs` table) or a pg-boss-style queue. Don't over-engineer;
a threadpool + DB status row is fine for a test box. (If scaling later, Temporal/
pg-boss per the Vanta deep-dive.)

**CORS:** allow the dashboard origin. **Config** via `api/settings.py` reading env
(reuse `compliance_reporting/settings.py` patterns: store path, webhook, etc.).

**Exit criterion:** `POST /api/ingest` with pasted CloudTrail sample returns a
report_id; `GET /api/frameworks` returns valid `ComplianceFramework[]` with HIPAA/
PCI/NIST/CIS populated and correct met/gap/na counts; `verify_report` passes.

---

## 5. Phase 3 — Dashboard wiring

Keep the dashboard's look, RBAC, roles, tiers. Swap mock data for the API.

1. **Env:** add `NEXT_PUBLIC_API_URL` (e.g. `http://localhost:8000`). Create a
   tiny `src/lib/data/client.ts` fetch wrapper.
2. **Replace the seam bodies** in `src/lib/data/compliance.ts`
   (`getComplianceFrameworks`) with `fetch(`${API}/api/frameworks`)`. Do the same
   for reports (`src/lib/data/reports.ts`) → `/api/reports`, `/api/report/{id}`.
   Keep the function signatures identical so pages don't change.
3. **Ingestion UI (the new core screen):** add route `src/app/ingest/page.tsx`:
   - a textarea to paste logs + a file upload; a `log_type` select (auto/…);
     an "Ingest" button → `POST /api/ingest` → poll `/api/jobs/{id}` → on done,
     route to `/compliance?report=<id>`.
   - Show per-line progress + the resulting posture summary (the 4 framework
     rings). This is the "manual ingestion" the user asked for.
   - Add a sidebar nav entry for **Ingest** (edit `src/components/layout/sidebar.tsx`).
4. **Compliance page:** it currently renders via the `complianceViews` ViewBlock
   mock. Point it at real data: render `ComplianceFramework` rings + a control
   table (reference, title, status pill, systems, aiRecommendation) reusing the
   existing `Card`/`Progress`/`Badge`/`Tabs` UI primitives. The six framework
   sidebar items (HIPAA/SOC2/ISO/PCI/NIST/GDPR) → drive from `/api/frameworks`;
   show SOC 2 / ISO 27001 / GDPR as **"coming soon"** placeholders (honest: we
   only have 4 live from SCF).
5. **Reports / Trend / Alerts pages:** wire `/api/trend`, `/api/diff`,
   `/api/alerts` into the existing `reports` and `alerts` routes. The trend chart
   uses Recharts (already a dep) over `ReportStore.trend()`.
6. **Detection-rules page:** optionally surface the Sigma ruleset
   (`detection/rules/*.yml`) read-only — a nice Furix-style "these are the rules
   behind your findings" screen. Low priority.

**Exit criterion:** from a browser, paste logs on `/ingest`, watch the job
complete, and see the real compliance posture (rings + control drill-down) on
`/compliance`, with the trend updating on `/reports`.

---

## 6. Phase 4 — Log generator (scaffold now, richen later)

`log_generator/generate.py` — deterministic-by-seed synthetic logs across the
supported types (cloudtrail, windows_evtx, syslog, okta_sso, azure_ad, gcp_audit,
wazuh_siem, microsoft_defender, o365, nmap), modeled on `SAMPLE_LOGS` in
`pipeline.py`. Knobs: `--count`, `--attack-ratio`, `--types`, `--seed`. Emits
newline-delimited logs to stdout or POSTs to `/api/ingest`. Wire a "Generate demo
logs" button in the dashboard (`POST /api/generate`) for future use. MVP: the CLI
+ a handful of attack/benign templates is enough; expand scenarios later.

**Exit criterion:** `python log_generator/generate.py --count 50 --attack-ratio
0.3 | POST /api/ingest` produces a report with a realistic mix of met/gap.

---

## 7. Phase 5 — Ubuntu deployment

`deploy/`:
- **`docker-compose.yml`**: `db` (pg15+pgvector+AGE, named volume), `ollama`
  (model volume), `api` (uvicorn, depends_on db+ollama, mounts report store
  volume), `web` (next build/start), `nginx` (reverse proxy: `/` → web,
  `/api` → api).
- **Dockerfiles**: `Dockerfile.api` (python:3.12-slim + engine + api reqs +
  torch/sentence-transformers — large image; consider CPU torch wheel),
  `Dockerfile.web` (node build → next start).
- **`.env.example`**: `PG_*`, `GEMMA_MODEL`, `GEMMA_BASE_URL`, `FURIX_DEVICE`,
  `FURIX_REPORT_STORE`, `FURIX_ALERT_WEBHOOK`, `NEXT_PUBLIC_API_URL`.
- **First-boot runbook** (`deploy/RUNBOOK.md`): (1) drop the SCF xlsx + CIS/NIST
  PDFs into `engine/bootstrap/data/`; (2) `docker compose up db ollama`;
  (3) run bootstrap (SCF ingest + setup_ingestion + graph) once; (4) `docker
  compose up -d`; (5) smoke test: `POST /api/ingest` sample, verify frameworks.
- **`furix.service`** systemd unit (optional, if not pure-compose) for
  auto-restart on the Ubuntu host.
- Healthchecks: `/api/health` (DB + models loaded), compose `healthcheck` blocks.

**Exit criterion:** on a fresh Ubuntu VM, following RUNBOOK.md end-to-end yields a
working dashboard at `http://<host>/` where a pasted log produces a verified
compliance report.

---

## 8. Prerequisites — STATUS (updated 2026-07-16, Fable session)

1. **SCF crosswalk source** — ✅ RESOLVED. Both the 2026.2 `.xlsx` and the
   machine-readable `scf-full-2026.2.json` are staged. **Use the JSON** (version-
   proof, answers the PCI question). Exact mapping keys, value formats, coverage
   counts, and the PCI `Req N` parser are in **`PHASE1-DATA-FINDINGS.md`** — read
   it before Phase 1. The "PCI column index" question is GONE (PCI is the JSON key
   `PCI DSS 4.0.1`).
2. **NIST CSF 2.0 PDF** — ✅ staged as `NIST.CSWP.29 (1).pdf`.
   **CIS Controls v8.1 PDF** — ❌ still missing; feeds `setup_ingestion` RAG
   evidence only; verdict/mapping unaffected; do NOT block Phase 1 on it.
3. **Gemma / Ollama** — ✅ Ollama is DEPLOYED ON THE SERVER. Point
   `GEMMA_BASE_URL` at that host and confirm the served model name for
   `GEMMA_MODEL`. No in-compose Ollama needed (drop that service or make it
   optional).
4. **Server sizing** — ≥16 GB RAM for model warm-load; GPU optional. Confirm box
   specs; `FURIX_DEVICE=cpu` is the safe default if no GPU.

## 8a. HANDOFF STATUS — read first

- **Build owner: Opus 4.8.** Execute this plan + `PHASE1-DATA-FINDINGS.md`
  starting at **Phase 0**. Keep the 42 `compliance_reporting` tests green
  throughout; add API + adapter tests as you go.
- **File locations (the build spans two dirs):**
  - CODE: `/Users/preetham/compliance/Furix_compliance_1/` (heavy pipeline +
    `compliance_reporting/`) and `/Users/preetham/compliance/secureguard/`
    (dashboard). Assemble the new monorepo (§1) from these.
  - PLAN + DATA: `/Users/preetham/compliance research/` (this plan,
    `PHASE1-DATA-FINDINGS.md`, `SCF-2026-2/` with xlsx+JSON, `NIST.CSWP.29 (1).pdf`,
    the two vanta research docs).
- **Server-side execution model: RUNBOOK.** The assistant CANNOT reach the
  Ubuntu box. For every stateful step (DB bring-up, bootstrap ingestion, model
  load, `docker compose up`), Opus AUTHORS exact copy-paste commands in
  `deploy/RUNBOOK.md`; the USER runs them on the server and pastes back output for
  debugging. Author code + runbook; do not assume live server access.
- **First move for Opus:** Phase 0 hardening (§2) — it's pure local code, needs
  no server, and unblocks everything. Then refactor `phase1_scf_ingest` to the
  SCF JSON (§8/`PHASE1-DATA-FINDINGS.md`) while still local.

---

## 9. Explicit non-goals for MVP (record so scope stays honest)

- **Multi-tenancy** — single-tenant only (dashboard auth is localStorage demo).
  When real customers arrive, add `tenant_id` to every table + Postgres RLS +
  scoped external-id uniqueness `(tenant_id, connection_id, external_id)` — this
  is the #1 lesson from Vanta's May-2025 cross-tenant incident (deep-dive §3).
- **Continuous/scheduled ingestion** — manual + generator only; a cron/scheduler
  wrapper is future (the `/loop` or a systemd timer).
- **Live integrations (AWS/Okta/GitHub connectors)** — Furix ingests logs, not
  cloud-resource state, so the Vanta connector model is a *later* direction, not
  MVP. Log ingestion is the wedge.
- **Trust Center, questionnaires, TPRM, access reviews** — Vanta modules noted in
  research as fast-follows; not in this build.
- **Auth hardening** — keep demo auth; real SSO/RBAC-backend is post-MVP.

---

## 10. Furix-style dashboard roadmap (post-wiring, informed by the Vanta teardown)

Once the spine works, these make it feel best-in-class **in Furix's own style**
(deterministic, evidence-first, self-verifying — Furix's genuine edge over
black-box SaaS):
1. **Frameworks screen** with dual rings (evidence % + control %) per framework —
   the recognizable readiness view.
2. **Controls screen** — Ok / Needs-evidence rollup, control→test→evidence
   drill-down, the ATT&CK provenance chain shown as "why this control".
3. **Tests screen** — the 15 policy rules + Sigma rules as the "tests", with
   pass/fail/no-data, owner assignment, and (later) SLA clocks.
4. **Verify badge** — surface "independently verified: 220 checks passed,
   content hash …" on every report. No competitor can show this; it's Furix's
   trust wedge — make it prominent.
5. **Trend + diff + alerts** — already built in the engine; just needs the UI.
6. **Deterministic "AI remediation"** — templated, provenance-backed remediation
   text now; real LLM remediation-PR generation later.

---

## 11. Task backlog (created in the session for Opus to claim)

Phase-level tasks are seeded in the task list (Phase 0 hardening → Phase 5
deploy). Work them top-down; keep the 42 engine tests green throughout and add
API + adapter tests as you go. Update the deep-dive/guide docs and regenerate the
PDF at the end.

---

*Authored in Fable 5, 2026-07-16. Execute in Opus 4.8. The two research docs in
`/Users/preetham/compliance research/` and the earlier
`COMPLIANCE-DEEP-DIVE.pdf` / `COMPLIANCE-ENGINE-GUIDE.pdf` are the conceptual
companions to this build plan.*
