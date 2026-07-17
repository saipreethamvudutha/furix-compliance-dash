# Furix Compliance

Deterministic, self-verifying, multi-framework compliance from security logs.
Ingest logs → Furix maps them to **CIS v8.1 · NIST CSF 2.0 · HIPAA · PCI DSS**
(SCF-derived), independently verifies every number, and shows the posture in a
Furix-branded dashboard.

```
  logs ─▶ pipeline (regex + SCF crosswalk + Sigma/ATT&CK) ─▶ report
                                                              │
                          independent verifier ◀──────────────┤ (recomputes ~all numbers)
                                                              ▼
                          dashboard  ◀── FastAPI ── report store (history · diff · alerts)
```

## Layout
```
furix-compliance/
├── engine/       # Python: the pipeline + compliance_reporting + api (FastAPI) + log_generator
├── dashboard/    # Next.js 15 dashboard (secureguard), wired to the API
├── deploy/       # docker-compose, Dockerfiles (db/api/web), nginx, .env.example, RUNBOOK.md
└── docs/         # plan + per-phase build records + data findings
```

## Quick start (Docker, Ubuntu) — see `deploy/RUNBOOK.md` for the full sequence
```bash
cd deploy
cp .env.example .env                         # set PG_PASSWORD, GEMMA_BASE_URL
cp /path/scf-full-2026.2.json source_data/   # + NIST.CSWP.29.pdf
docker compose build && docker compose up -d db ollama
docker compose run --rm api python ingest_scf_json.py /data/source/scf-full-2026.2.json
docker compose up -d
open http://localhost/            # login admin@byoc.com / admin123 → Ingest
```

## Develop locally (no Docker)
```bash
# engine tests (stdlib-only core; 73 tests)
cd engine
python3 -m compliance_reporting.test_reporting
python3 -m compliance_reporting.detection.test_detection
python3 -m compliance_reporting.test_delivery
python3 -m compliance_reporting.adapters.test_adapter
python3 -m api.test_service
python3 -m log_generator.test_generate
python3 test_scf_crosswalk.py
# CLI demo (no DB/models):
python3 -m compliance_reporting demo
python3 -m log_generator --count 50 --seed 7

# dashboard
cd ../dashboard && npm install && npm run dev    # http://localhost:3000
```

## What makes it different
- **Deterministic:** same logs → identical, hash-sealed report. No LLM on the verdict path.
- **Independently verified:** a separate implementation recomputes every status,
  count, and percentage from the raw logs (~220–370 checks per report) — a trust
  wedge no black-box SaaS shows.
- **SCF-derived crosswalks:** real, complete CIS↔NIST↔HIPAA↔PCI edges from the
  Secure Controls Framework, with per-edge provenance.
- **ATT&CK pivot:** log → Sigma rule → technique → control, replacing hand-keyword
  tables (anchored matching, CI-gated rules).
- **History · diff · alerts:** posture over time, regression detection, deliverable alerts.

## Status
Phases 0–5 built and verified locally (73 engine tests green; dashboard `tsc` +
`next build` clean; `docker compose config` valid). Server bring-up per the
runbook. See `docs/` for the full build record.
