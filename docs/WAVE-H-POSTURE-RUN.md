# Wave-H — unified posture-run pipeline (linked-ID traceability)

**Status:** shipped and verified live. Ties every previously-built stage into one
orchestrated, durably-recorded run whose IDs link the whole chain end-to-end.

**Coverage:** engine **263 checks** green (strict); dashboard builds clean, 30
Node tests green; the full chain verified live in a browser.

## The pipeline

One call runs, in order, and records a single **PostureRun**:

```
connector collection → raw snapshot → immutable evidence →
population reconciliation → config assertions → verified report → findings
```

`service.run_posture(...)`:

1. **Immutable evidence** — the raw snapshot is content-addressed and written
   write-once to the evidence store; the linked `snapshot_sha256` is verified to
   have landed (fail-closed if not).
2. **Report** — `ingest_config` persists each resource's evidence, builds, and
   **independently verifies** the report (aborts on verification failure).
3. **Evaluation** — the config-assertion results are summarised (pass/fail) with
   a combined `evaluator_hash`.
4. **Findings** — a finding is opened for every at-risk control; their ids and
   the affected control ids are linked into the run.

## Linked IDs

Every `PostureRun` carries the ids that let an auditor walk the chain both ways —
from a control verdict back to the exact evidence and collection, and forward to
the remediation findings:

| stage | linked id |
|---|---|
| collection | `collection.manifest_sha256` (+ signed / reconciled / basis) |
| snapshot | `snapshot.collected_at`, `resource_count` |
| evidence | `evidence.snapshot_sha256`, `raw_uri` |
| evaluation | `evaluation.evaluator_hash` (+ pass/fail) |
| report | `report_id` (+ `verified`) |
| findings | `findings[]` |
| affected controls | `affected_controls[]` |

The `run_id` is derived deterministically from `(tenant, report_id,
collected_at)`, so the same inputs produce the same run — reproducible like the
report itself. Runs are stored in a durable, tenant-scoped SQLite
`PostureRunStore`.

## API + UI

- `POST /api/connectors/{id}/posture-run` — admin-only; collects, runs the whole
  pipeline, records connector health, returns the linked-ID run (422 on failure,
  with the connector marked failed).
- `GET /api/posture-runs` / `GET /api/posture-runs/{run_id}` — tenant-scoped,
  auditor-readable.
- The **/connectors** page gained a **Run posture** action and a "Latest posture
  run — linked chain" panel showing run → snapshot evidence → assertions →
  verified report → findings → affected controls.

## Also in this wave

- **Fail-closed OSCAL gate** — the auditor package now requires schema
  validation to have `ran` AND passed (`ran && ok`); an unvalidated export
  (e.g. `jsonschema` unavailable) is refused rather than issued.

## Verified live

Browser → BFF → engine: a posture run on the `demo-aws` connector produced a
verified report, a retained snapshot-evidence sha, an assertion summary (2/0),
and a persisted linked-ID run — all surfaced on the connectors page.
