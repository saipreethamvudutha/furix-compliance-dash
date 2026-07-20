# Wave-J — Production Integrity Closure

**Status:** shipped and verified. Closes the production-integrity gaps found in
audit before adding any new frameworks or agents.

**Coverage:** engine **324 checks** green (strict); dashboard builds clean, 42
Node tests green; production overlay + full pipeline verified live.

## P0 — correctness / security (all verified live)

**Approved attestations preserved in every report path.** `ingest_config()` and
`run_posture()` now thread the tenant + approved attestations + tenant key ring
into `build_report`, so a connector/config run can never regress verified
people/process controls (CIS 9/14/15/17/18) back to `manual_pending`.

**Synthetic data generation blocked in production.** `/api/generate` (which
writes demo config + attestations into a tenant's real report history) returns
`403` in production — verified live alongside the existing demo-connector block.

**Continuous compliance is now automatic.** A connector `/run` executes the FULL
posture pipeline (evaluates controls, verifies, opens findings) — not a
manifest-only collection. A real **posture worker** (`api/worker.py`, compose
`worker` service) drives every SCHEDULED connector run through the **durable work
queue → full posture pipeline**, so nothing discards snapshots any more.

## P1 — period-scoped, verified, signed audit sign-off
Sign-off now enforces, before freezing:
1. **every evidence request fulfilled**, and each reference **resolves to a
   retained `furix-evidence://` object** (no arbitrary/dangling refs),
2. a report **within the period's date window** binds the snapshot (not "the
   latest"),
3. the snapshot is **asymmetrically signed** (RSA-PSS / KMS; verifiable by public
   key; **required in production**).

## #0 — secret-file readiness + production smoke test
- `prodReadiness` now honors `*_FILE` **Docker secrets** (was 503 forever when
  secrets were injected as files) — verified live.
- `deploy/smoke-test-prod.sh` drives the **production overlay** with a real
  `aws-org-iam` connector (demo-isolation must not block it). Verified live:
  prod readiness, login via a file-based user directory, `/api/generate` 403,
  `demo-aws` 400, `aws-org-iam` allowed.

## Enhancements
- **Per-assertion / per-evidence freshness.** Control freshness is derived from
  the ACTUAL backing evidence (the oldest contributing observation + each
  assertion's own freshness SLO), not merely the report time — surfaced per
  assertion in the workspace detail.
- **Exact producing run.** A control links to the posture run whose report_id
  produced its current verdict (`PostureRunStore.by_report`), not just the latest.
- **CI expansion:** a **full-pipeline smoke** job (boots API + BFF, runs
  login→collect→posture→OSCAL), a **compose-validate** job (base + prod overlay),
  and a **live two-tenant RLS** job (real Postgres + `rls-schema.sql` +
  `rls-test.sql` asserting cross-tenant reads/writes are blocked). A
  **crash-resume pagination** test proves collection resumes from the durable
  checkpoint with no page re-fetched or item lost.

## Honest remaining scope
- The live AWS collection path needs real read-only creds (or a moto endpoint) to
  complete a run; the smoke test proves the path is wired and not demo-blocked
  and completes fully when AWS is reachable.
- The RLS job runs against Postgres in CI; the app's durable stores still run on
  SQLite by default (Postgres/RLS is the shipped, CI-tested drop-in target).
