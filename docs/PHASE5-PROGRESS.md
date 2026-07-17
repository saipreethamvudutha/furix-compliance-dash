# Phase 5 — Deployment + Monorepo: COMPLETE

**Done in Opus 4.8, 2026-07-16.** The whole system is assembled into one
deployable monorepo with a validated Docker stack and a step-by-step runbook.

## Monorepo assembled: `furix-compliance/`
```
engine/      the tested Python (pipeline + compliance_reporting + api + log_generator) — 73 tests green here
dashboard/   the Next.js dashboard (secureguard), tsc+build clean
deploy/      docker-compose + Dockerfiles + nginx + .env.example + RUNBOOK.md
docs/        plan + phase records + data findings
README.md    overview + quickstart + local dev
.gitignore
```

## Deployment artifacts (all authored; compose config validated)
| File | What |
|---|---|
| `deploy/docker-compose.yml` | 5 services — **db** (PG16 + AGE + pgvector), **ollama** (Gemma), **api** (FastAPI engine), **web** (Next.js), **nginx** (one-origin reverse proxy). Volumes for DB data, models, report store; healthchecks; dependency ordering. |
| `deploy/db/Dockerfile` + `init.sql` | Apache AGE base + pgvector built from source; creates `furix_compliance` + `furix_det`, enables both extensions in each. |
| `engine/Dockerfile` | Python 3.12 + CPU torch + engine deps; runs `uvicorn api.main:app`; lazy model load so startup + `/api/health` don't need models. |
| `engine/requirements-engine.txt` | Heavy deps (fastapi, torch, sentence-transformers, psycopg2, pgvector, openai, pdfplumber…). The core stays stdlib-only. |
| `dashboard/Dockerfile` | Multi-stage Next.js build; `NEXT_PUBLIC_API_URL=""` so the browser uses the same origin `/api` via nginx. |
| `deploy/nginx.conf` | `/ → web:3000`, `/api → api:8000`; 25m upload cap; 300s ingest timeout. |
| `deploy/.env.example` | PG creds, Gemma host, device, HTTP port, CORS — all defaulted. |
| `deploy/RUNBOOK.md` | Fresh-Ubuntu bring-up: configure → build → **one-time bootstrap** (`ingest_scf_json`, ollama pull, optional `setup_ingestion`) → up → smoke tests (incl. Phase 0 import-safety + generate/ingest over HTTP). |

## Verification (local)
```
docker compose config   → VALID ✓ (db, api, web, nginx, ollama)
engine test board        → 73/73 in the assembled monorepo
                           (scf 6 · reporting 24 · detection 10 · delivery 9 ·
                            adapter 9 · service 7 · generator 8)
dashboard (source)       → tsc --noEmit 0 · next build 0
```
Full container builds + the server bring-up run on the Ubuntu box per RUNBOOK.md
(the DB image compiles AGE/pgvector; the api image pulls CPU torch — minutes, and
they need the server, not this workstation).

## All phases complete
Phase 0 ✅ · Phase 1 ✅ (code; server bootstrap in runbook) · Phase 2 ✅ ·
Phase 3 ✅ · Phase 4 ✅ · **Phase 5 ✅**. The plan is delivered end to end.
