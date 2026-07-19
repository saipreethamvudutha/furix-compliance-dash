# Security hardening + Evidence Kernel (Waves A & B)

**Status:** shipped. Closes the audit's remaining P0 security blockers plus the
Wave 1 evidence foundation: FUR-CMP-004 (auth/tenancy), FUR-CMP-007
(evidence envelope), FUR-CMP-008 (assertion model), FUR-SEC-001 (dependency),
FUR-SEC-004 (API hardening), and the evaluation-reproduction half of
FUR-CMP-003.

## Wave A — the API is no longer open

**Auth (FUR-CMP-004).** Every endpoint except `/api/health` requires a bearer
API key. Keys carry a `tenant` and a `role`; roles expand to fixed scopes:

| Role | Scopes |
|---|---|
| admin | read, ingest, export, admin, cross-tenant |
| analyst | read, ingest |
| auditor | read, export |
| mssp | read, ingest, cross-tenant |

Keys are compared by constant-time hash (plaintext never held after load).
Every allow/deny is written to an append-only audit log with actor, action,
tenant, decision and wall-clock time. `FURIX_ENV=production` refuses to mint a
dev key — no keys configured means every request is denied (**fail closed**).

**Tenancy.** Data is physically isolated: each tenant gets its own
`ReportStore` and `EvidenceStore` subtree (`.../tenants/<slug>/`). Tenant ids
are slug-validated (no path traversal). Cross-tenant reads need both a
cross-tenant scope AND an explicit `tenant=` argument — never implicit.

**Hardening (FUR-SEC-004).** Per-key fixed-window rate limiting, request-body
and ingest-size caps, tight CORS (GET/POST/OPTIONS, `authorization`+`content-type`
only), safe error bodies (no internal leakage), and security headers on every
response (`nosniff`, `DENY`, `no-referrer`, `no-store`, restrictive CSP).

**Dependency (FUR-SEC-001).** Next.js bumped to 16.2.10, past the high-severity
advisory group.

Config lives in `deploy/.env.example` / `docker-compose.yml`; the dashboard
sends its key via `NEXT_PUBLIC_API_KEY`. **Terminate TLS before exposing the
box** — the bearer key is a secret in transit (see RUNBOOK §6).

Live-verified with FastAPI TestClient: no-key → 401, bad key → 401,
cross-tenant → 403, admin → 200, security headers present. 13 auth tests.

## Wave B — the Evidence Kernel

**Immutable evidence store (FUR-CMP-007).** Every ingested event is stored
**once, content-addressed by the SHA-256 of its raw bytes**, wrapped in a
canonical envelope:

```
EvidenceObject:
  evidence_id (= uuid5(sha256), content-derived)
  source · tenant · boundary · sha256 · raw_uri · size_bytes
  observed_at (event time) · collected_at (ingestion time, VOLATILE)
  collector_version · parser_version · schema_version
```

Layout per tenant: `evidence/objects/<sha256>.raw` (write-once bytes) +
`<sha256>.json` (envelope). Re-ingesting the same event is a no-op on disk.
`verify_object()` re-hashes the stored bytes against their address — tamper
evident. The 300-char excerpt is gone: report evidence rows now carry a
`raw_uri` pointer into this store.

**Population manifest (FUR-CMP-007).** Every report carries a completeness
manifest — `expected / observed / errored / excluded / duplicate / coverage_pct
/ reconciled` — so partial telemetry can never read as healthy. The verifier
fails the report if the manifest doesn't reconcile against the batch.

**Assertion model (FUR-CMP-008).** Each POL rule is an `AssertionSpec` (mode,
predicate_kind, cadence, freshness, control_edges, policy_version) with a
content-derived `evaluator_hash`. Each test in a report carries an
`AssertionRun` — the population it saw, its status + reason codes, the evidence
it references, and the evaluator_hash that pins exactly which logic produced the
verdict. The current pack is honestly `detection_only`/`negative`, so no spec
can positively PASS yet — that limit is encoded, not hidden.

**Evaluation reproduction (FUR-CMP-003 top level).** `verify_report(report,
batch, raw_logs=, reanalyzer=)` re-runs the versioned evaluation from raw
evidence and confirms a byte-identical content hash → `EVALUATION_REPRODUCED`.
Proven end-to-end in `test_evidence.py`.

**Evidence lineage in the dashboard (FUR-CMP-007).** Every at-risk control row
shows its evidence lineage — the finding, the resolvable `furix-evidence://…`
URI, and a copyable `furix verify --evidence <sha> --assertion <POL> --evaluator
<hash>` reproduction command — and the Live Compliance header shows source
completeness (observed/expected + a reconciled indicator). Matches the audit's
Evidence dashboard blueprint.

## Test coverage

120 checks green across 11 suites (reporting 28, **evidence 12**, adapter 13,
detection 10, delivery 9, service 9, jobs 5, **auth 13**, SCF 6, ATT&CK 7,
generator 8), plus a live FastAPI enforcement proof.

## What's still ahead (audit sequence)

Real config/API connectors with **positive** assertions (Wave 2 — what finally
makes PASS/met reachable and earns a compliance %), OIDC/SAML + durable
queue/storage (Wave 4), auditor workspace + OSCAL 1.2.1 (Wave 5), and the
agentic layer (P2/P3). The evidence + assertion + tenancy foundations this wave
laid are the prerequisites for all of them.
