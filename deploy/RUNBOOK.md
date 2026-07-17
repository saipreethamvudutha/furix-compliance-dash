# Furix Compliance — Deployment Runbook (Ubuntu)

End-to-end bring-up of the full stack on a fresh Ubuntu server with Docker.
Everything runs in containers; one one-time bootstrap step loads the SCF
crosswalk and (optionally) the RAG evidence embeddings.

## 0. Prerequisites
- Docker Engine + Compose v2 (`docker --version`, `docker compose version`).
- **≥16 GB RAM** (SecureBERT loads into the api container; CPU is fine, GPU optional).
- Source data files (place in `deploy/source_data/`):
  - `scf-full-2026.2.json` — **required** (SCF crosswalk; from the SCF 2026.2 package).
  - `NIST.CSWP.29.pdf` — NIST CSF 2.0 (RAG evidence).
  - `cis_controls_v8.1.pdf` — optional (CIS RAG evidence; verdict works without it).

## 1. Configure
```bash
cd furix-compliance/deploy
cp .env.example .env
#  - set a real PG_PASSWORD
#  - if Ollama already runs on your server, set GEMMA_BASE_URL to it and delete
#    the `ollama` service from docker-compose.yml; otherwise leave defaults.
cp /path/to/scf-full-2026.2.json  source_data/
cp "/path/to/NIST.CSWP.29 (1).pdf" source_data/NIST.CSWP.29.pdf
```

## 2. Build + start
```bash
docker compose build          # DB image compiles pgvector; api pulls CPU torch — first build is slow
docker compose up -d db ollama
docker compose ps             # wait for db healthy
```

## 3. One-time data bootstrap
```bash
# 3a. SCF crosswalk → furix_det (cis_to_nist / hipaa_to_nist / cis_to_pci)
docker compose run --rm api python ingest_scf_json.py /data/source/scf-full-2026.2.json
#   → "furix_det populated: cis_to_nist=184 hipaa_to_nist=162 cis_to_pci=96 rows"

# 3b. Pull the Gemma model into ollama (skip if using an external Ollama)
docker compose exec ollama ollama pull ${GEMMA_MODEL:-gemma4:e4b}

# 3c. (Optional, slow) RAG evidence: chunk+embed the PDFs into pgvector + build the
#     AGE graph. Downloads SecureBERT on first run. Skip to run without CIS/NIST
#     evidence text — the verdict/mapping are unaffected.
docker compose run --rm api python setup_ingestion.py
```

## 4. Start the app
```bash
docker compose up -d          # brings up api, web, nginx
docker compose ps             # all healthy
```

## 5. Smoke tests
```bash
# API health (no engine needed)
curl -fsS http://localhost/api/health ; echo

# Phase 0 import-safety: importing the pipeline must NOT run a batch
docker compose exec api python -c "import pipeline; print('import OK — no batch ran')"

# Single-log run through the real pipeline (needs bootstrap done)
docker compose exec api python -c "
from pipeline import run_full_pipeline, SAMPLE_LOGS
r = run_full_pipeline(SAMPLE_LOGS['cloudtrail'], log_type='cloudtrail')
print('failure_stage:', r['_failure_stage'])
print('cis_controls :', r['compliance_mapping']['cis_controls'])
print('violations   :', len(r['policy_findings']))
"

# End-to-end via HTTP: generate + ingest 50 synthetic logs → verified report
curl -fsS -XPOST http://localhost/api/generate -H 'content-type: application/json' \
  -d '{"count":50,"attack_ratio":0.35,"seed":7}' | python3 -m json.tool | head -30
```

## 6. Use it
Open **http://<server>/** → log in (demo: `admin@byoc.com` / `admin123`) →
**Ingest** (paste/upload or "Generate demo logs") → watch the verified posture →
**Compliance** for the latest report.

## 7. Troubleshooting
- **DB image build fails on AGE/pgvector** → check the base tag `apache/age:PG16_latest`
  is current; pgvector branch `v0.8.0` builds against PG16.
- **api unhealthy** → `docker compose logs api`. First ingest is slow (SecureBERT
  warm-load); health itself doesn't need models.
- **frameworks empty / snapshot provenance** → bootstrap 3a didn't run or
  `FURIX_SCF_JSON` path is wrong; `docker compose exec api python -c "import db_connections"`
  should print CIS/HIPAA/PCI counts.
- **Gemma errors** → only hit for unknown log formats; confirm the model is pulled
  and `GEMMA_BASE_URL` is reachable from the api container.
- **CORS** in a browser calling the api directly → set `FURIX_CORS_ORIGINS`. Behind
  nginx (default), the browser uses the same origin, so CORS doesn't apply.
