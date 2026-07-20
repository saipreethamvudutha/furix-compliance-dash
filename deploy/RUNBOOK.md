# Furix Compliance — Deployment Runbook (Ubuntu)

End-to-end bring-up of the full stack on a fresh Ubuntu server with Docker.
Everything runs in containers; one one-time bootstrap step loads the SCF
crosswalk and (optionally) the RAG evidence embeddings.

## ⚡ Upgrading an existing (pre-auth) deployment

If the box is running a build from before the auth/BFF hardening, the upgrade
adds mandatory security. On the server:

```bash
cd furix-compliance && git pull
# 1. Update .env (deploy/.env) — the API now REQUIRES these:
#      FURIX_API_KEYS   JSON list of real keys (openssl rand -hex 24)
#      FURIX_API_KEY    the same key, for the dashboard's server-side BFF
#    Internal test box shortcut: set FURIX_ENV=development to boot with the
#    dev key (loud warnings). Production: FURIX_ENV=production +
#    FURIX_TLS_TERMINATED=1 — the API REFUSES to boot with dev/CHANGE-ME keys.
# 2. Rebuild both tiers (dashboard build changed: BFF, no client key):
docker compose -f deploy/docker-compose.yml build api web
docker compose -f deploy/docker-compose.yml up -d
# 3. Verify:
curl -fsS http://localhost:8088/api/health                       # 200
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8088/api/summary  # 401 (no key)
```

Reports stored by the old version still load (schema 1.x fallback); new
ingests produce schema 2.0 with the honest assurance states. The dashboard
will look different by design: coverage-first tiles, no fake compliance %.

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

## 5. Authentication (FUR-CMP-004) — required before any data call
Every endpoint except `/api/health` needs a bearer key. Generate real keys and
put them in `.env` (see `FURIX_API_KEYS` / `NEXT_PUBLIC_API_KEY`):
```bash
openssl rand -hex 24     # make one per key; never ship the CHANGE-ME default
```
`FURIX_ENV=production` (the default in compose) refuses to mint a dev key, so a
missing/blank `FURIX_API_KEYS` means every request is denied — fail closed.

## 6. TLS
The bearer key is a secret in transit — terminate TLS at nginx (or an upstream
load balancer) before exposing the box. Do not serve the API over plain HTTP on
an untrusted network. A self-signed cert is fine for internal testing; use a
real cert (Let's Encrypt / corporate CA) for anything beyond a lab.

## 7. Smoke tests
```bash
KEY=furix-dev-key   # or your real admin key from .env

# API health (open, no key needed)
curl -fsS http://localhost/api/health ; echo

# Data endpoints require the key — this must 401 WITHOUT it:
curl -s -o /dev/null -w '%{http_code}\n' http://localhost/api/reports        # → 401
curl -fsS http://localhost/api/reports -H "Authorization: Bearer $KEY"       # → []

# Phase 0 import-safety: importing the pipeline must NOT run a batch
docker compose exec api python -c "import pipeline; print('import OK — no batch ran')"

# End-to-end via HTTP: generate + ingest 50 synthetic logs → verified report
curl -fsS -XPOST http://localhost/api/generate \
  -H "Authorization: Bearer $KEY" -H 'content-type: application/json' \
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
