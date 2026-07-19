# Enterprise hardening (audit response)

**Status:** shipped. Addresses the trust-and-production-hardening audit's P0/P1/P2
findings. Verified with a **real local deployment** of both tiers (FastAPI +
Next.js) — not the stub.

## P0 — critical

**P0-1 · No credential in the browser.** The dashboard no longer embeds an API
key in client JavaScript. It calls a **same-origin server-side BFF** (`/bff/*`,
`dashboard/src/app/bff/[...path]/route.ts`) that holds the bearer key in a
**server-only** `FURIX_API_KEY` env and attaches it when proxying to the API.
`NEXT_PUBLIC_API_KEY` is removed; the build is verified to contain no key. A
production deployment replaces the static server key with a per-user token from
an OIDC authorization-code/PKCE session — that exchange lives in the BFF and the
client contract (`/bff/*`) does not change when it lands.

**P0-2 · The evaluator hash identifies the evaluator.** Config assertions are
now a **canonical declarative rule language** (`{attr, op, value}` clauses). The
`evaluator_hash` is computed over the FULL normalized rule — applies + predicate
+ parameters + rule-language version — so two opposing predicates (`truthy` vs
`falsy`, or `gte 90` vs `gte 30`) **hash differently** (proven by test). There is
no opaque Python logic the hash can't see.

## P1 — high

**Population honesty.** A collector that did not **declare** `expected_counts`
now yields `UNKNOWN` (`population_unverified`), never PASS — incomplete
collection can no longer masquerade as complete.

**Fail-closed production.** `api/preflight.py` runs at startup; in
`FURIX_ENV=production` the process **refuses to serve** if the default dev key is
present, no durable job DB is set, encryption/OIDC is configured without its
dependency, or TLS is unacknowledged. `cryptography` and `pyjwt[crypto]` are in
`requirements-engine.txt`; evidence encryption **raises** instead of silently
falling back to plaintext when a master key is set.

**Durable findings.** The finding/exception lifecycle store moved off
process-locked JSONL to **transactional SQLite** (WAL, cross-process, one-time
legacy import), durability proven across a store reopen. Jobs and the report
index are already SQLite-durable (Wave 4).

**OSCAL honesty.** OSCAL 1.2.1. The `import-ap`/`import-ssp` placeholders are now
honest external references with remarks (no dangling internal UUIDs). A
`validate_oscal_schema` hook validates against the **official** OSCAL schema when
`jsonschema` + a schema file are configured, and reports `ran=False` when they
are not — it never reports a package "valid" that was only structurally checked.

**CI gates block.** All 10 dashboard lint errors are fixed and `continue-on-error`
is removed, so the CI **lint** (zero-error) and **npm-audit** (high/critical)
steps now fail the build.

## P2

**People/process controls.** Manual/operational **attestation** assertions cover
the 5 controls config can't prove — CIS 9 (email/browser), 14 (training), 15
(vendor review), 17 (incident exercise), 18 (pentest). Each is `MANUAL_PENDING`
until a signed, in-cadence attestation exists, then `compliant` — unless a real
detection finding outranks it (e.g. Control 15). All 18 CIS control families are
now reachable.

## Local deployment proof (both tiers, real backend)

Run offline against the real FastAPI app (not the stub):

```bash
# backend
cd engine
FURIX_ENV=development FURIX_REPORT_STORE=/data FURIX_JOB_DB=/data/jobs.db \
FURIX_API_KEYS='[{"key":"KEY","key_id":"admin","tenant":"default","role":"admin"}]' \
uvicorn api.main:app --port 8000
# frontend (BFF holds the key server-side)
cd dashboard
FURIX_API_URL=http://localhost:8000 FURIX_API_KEY=KEY npm run start -- --port 3011
```

Verified end-to-end on the real stack:
- `/api/health` ok; no-key → **401**; direct API without a key stays 401.
- BFF same-origin call with **no client key** returns real data (key attached
  server-side).
- `/compliance` shows **LIVE · report … · independently verified**, 4 frameworks
  at 100% coverage, 12 met controls, 67% earned compliance.
- Findings from the SQLite store surface on at-risk rows; **Control 5 shows a
  "risk accepted" chip** (approver ciso@acme) through the full backend → BFF →
  browser path.
- OSCAL 1.2.1 POA&M validates (`validation ok: True`); the auditor export bundles
  a valid package + findings workpaper.
- An OIDC HS256 JWT verifies to `tenant=default role=auditor`.

## Test coverage

**189 engine checks green** (`python run_all_tests.py`), including the new
declarative-hash, population-honesty, preflight (9), manual-evidence (7),
finding-durability, and OSCAL schema-hook tests. Dashboard: **zero lint errors**,
clean build.

## Honest remaining scope (the audit's "recommended direction")

These are the deliberately-deferred, genuinely-large items — real infra, not
config switches:

- **Real read-only connectors** (live AWS/Okta/GitHub with pagination,
  permission checks, retries, checkpoints, signed collector manifests). Today
  connectors consume authoritative snapshots in the exact shape a live client
  would emit — the client is the drop-in.
- **Full OIDC authorization-code/PKCE + BFF session** (the BFF and JWT
  verification exist; the interactive login exchange is next).
- **PostgreSQL + durable queue workers + HA** (SQLite is the tested,
  interface-compatible substrate).
- **Official OSCAL schema bundled** into CI (the validation hook is in place).
- **Agentic GRC stays vNext** — agents propose; deterministic code verifies
  every output before it affects posture.
