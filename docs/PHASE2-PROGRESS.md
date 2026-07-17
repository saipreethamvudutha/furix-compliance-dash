# Phase 2 — API Backend + Dashboard Adapter: LOCAL WORK COMPLETE

**Done in Opus 4.8, 2026-07-16.** The adapter and the entire service layer are
built and tested locally (no torch/DB). The FastAPI shell is authored and
compiles; it only needs `pip install -r api/requirements.txt` to run on the server.

## What was built (64 tests green across the whole engine board)

| File | What | Tests |
|---|---|---|
| `compliance_reporting/adapters/dashboard.py` | **The adapter.** Maps a canonical report → the dashboard's exact `ComplianceFramework[]` / `ComplianceControl` shape. Status map: `compliant→met`, `at_risk→gap`, `not_monitored→not_applicable`. Every at-risk row's `systems` + `aiRecommendation` trace to real report evidence (a POL rule that actually fired). | 9/9 |
| `api/service.py` | **The service layer** (logic, no HTTP). `ingest_batch()` runs each log line through an **injectable analyzer** → build → verify → store → diff-vs-prior → deliver alerts. Plus read paths (reports/frameworks/summary/trend/diff) with `latest` + 8-char-prefix id resolution. | 6/6 |
| `api/main.py` | **Thin FastAPI shell** over the service. Heavy pipeline is lazy-imported inside ingest, so the app starts without torch/DB. | compiles |
| `api/requirements.txt` | API deps only (fastapi, uvicorn, python-multipart, pydantic) — the engine core stays stdlib-only. | — |

## Bug found & fixed by local testing
`ReportStore.save()` compared **raw bytes** for idempotency, so re-ingesting the
same logs at a different time (same `report_id`, different `generated_at`) wrongly
raised "different document". Fixed to compare the **content hash** — a matching
`report_id` is now correctly idempotent regardless of generation time. (24/24
reporting tests still green.)

## API contract (for Phase 3 dashboard wiring)

| Method + path | Returns | Needs engine? |
|---|---|---|
| `GET  /api/health` | `{status, engine_version, reports}` | no |
| `POST /api/ingest` `{text, log_type}` | `{report_id, lines_ingested, summary, frameworks, verification, alerts}` | **yes** (pipeline + DB) |
| `POST /api/ingest-file` (multipart) | same as ingest | **yes** |
| `GET  /api/frameworks?report=latest\|<id>` | `ComplianceFramework[]` (the dashboard's type) | no |
| `GET  /api/summary?report=latest\|<id>` | KPI summary | no |
| `GET  /api/reports` | report index (newest first) | no |
| `GET  /api/report/{id}` | full report JSON | no |
| `GET  /api/report/{id}/html` | rendered dashboard HTML | no |
| `GET  /api/trend` | posture time series | no |
| `GET  /api/diff?old=<id>&new=<id>` | `{diff, alerts}` | no |

Only ingest needs the heavy engine; every read endpoint works off the stored
reports, so the dashboard's compliance/reports/trend views light up immediately.

## ⬜ Server-run
```bash
pip install -r api/requirements.txt          # + the engine's own heavy deps
export FURIX_SCF_JSON=/path/scf-full-2026.2.json PG_HOST=... GEMMA_BASE_URL=...
uvicorn api.main:app --host 0.0.0.0 --port 8000
curl localhost:8000/api/health
# ingest a sample:
curl -XPOST localhost:8000/api/ingest -H 'content-type: application/json' \
  -d '{"text":"{\"eventName\":\"CreateUser\",\"requestParameters\":{\"userName\":\"backdoor_admin\"}}","log_type":"cloudtrail"}'
```

## Next — Phase 3 (dashboard wiring, local code)
Replace `secureguard/src/lib/data/compliance.ts` + `reports.ts` bodies with
`fetch(${NEXT_PUBLIC_API_URL}/api/...)`, add the `/ingest` screen (paste/upload →
poll → show posture), and render real framework rings + control drill-down.
The API contract above is the exact shape the dashboard already expects.
