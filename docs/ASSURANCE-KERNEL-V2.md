# Assurance Kernel v2 — Wave 0: truthful status semantics

**Status:** shipped (schema 2.0, engine 2.2.0). This wave implements the P0
semantic corrections from the July 2026 compliance gap audit
(FUR-CMP-001/002/003/005/006/017/018/019) — the "correct the claims" milestone
that must precede evidence connectors, workflow, and any agentic layer.

## The one-sentence change

**Silence never increases posture.** A detection rule that did not fire proves
nothing; the report now says `unknown`, never `pass` — and every rollup above
it (control → requirement → framework) inherits that honesty.

## Status vocabulary (schema 2.0)

| Layer | States | Notes |
|---|---|---|
| Test (assertion) | `fail` · `unknown` · `pass`* | `unknown` carries `status_reason`: `not_observed` / `no_data`. *`pass` requires a positive predicate over an expected population — unreachable from the current detection-only rule pack, enforced by the verifier gate. |
| Control | `at_risk` · `unknown` · `not_monitored` · `compliant`* | `unknown` = monitored, no violations observed — NOT proof the control operates. |
| Framework requirement | same as control | `at_risk` if any contributor at risk; `unknown` if any contributor monitored; `not_monitored` only when NO contributor is monitored. Partial monitoring can never produce `compliant`. |

**Posture is a tuple, not a number:** state counts + `coverage_pct` (share of
requirements monitored) + `at_risk_pct` (share of MONITORED requirements with
observed violations). `compliance_pct` is `null` until positive assertions
exist — never a silent 0 or 100. The dashboard never maps `not_monitored` to
`not_applicable`: N/A requires an approved applicability decision, which does
not exist yet.

## Determinism (FUR-CMP-002)

* `finding_uuid` = UUIDv5(namespace, log_sha256 | rule_id | field | value) —
  derived from WHAT was found in WHICH log, never `uuid4()`.
* Finding `timestamp` = the log's own event time (content-derived), never
  ingestion wall-clock.
* The report content hash covers everything except
  `integrity / report_id / generated_at / run_metadata`; run timestamps live
  only in `run_metadata`. Same logs + same version manifest → byte-identical
  hashed payload → same `report_id`.

## Verification levels (FUR-CMP-003)

The verifier reports exactly what it achieved — the dashboard badge shows the
level, never more:

1. `INTEGRITY_VERIFIED` — hashes and references reconcile (report alone).
2. `ROLLUP_VERIFIED` — statuses/counters independently recomputed from the
   stored batch (the current API level).
3. `EVALUATION_REPRODUCED` — an isolated re-run from raw evidence produced the
   same content hash (available via `verify_report(..., raw_logs=, reanalyzer=)`).

New `GATE-*` checks make forged posture tamper-evident: any `pass` without a
positive predicate, any `compliant` without all-passing tests, any requirement
outranking its contributors → verification fails.

## Deterministic routing (FUR-CMP-005)

API ingestion classifies every line with `detect_log_type()` before analysis —
the analyzer never receives `auto`. Unknown formats stay `generic` and remain
deterministic; Gemma enrichment requires the explicit opt-in
`FURIX_LLM_ENRICH=1` and is advisory only.

## Version manifest (FUR-CMP-017/019)

`compliance_reporting/versions.py` is the single version source (engine,
schema, SCF 2026.2, rule pack, sigma pack, OSCAL), embedded in every report
inside the content hash and imported by policy_engine, OSCAL serialisers,
settings, and the API banner. The 2026.1-vs-2026.2 and 2.0.0-vs-2.1.0 drifts
are gone.

## Golden acceptance gates (in `test_reporting.py`)

* `test_golden_unrelated_log_produces_zero_pass` — one benign log → zero pass,
  zero compliant, all `compliance_pct` null.
* `test_golden_silence_never_increases_posture` — remediated batch moves
  at_risk → unknown, never → compliant.
* `test_golden_verifier_rejects_forged_pass` — a hand-edited `pass` fails
  verification.
* `test_golden_version_manifest_stamped` — one manifest, everywhere.

93 checks green across 9 suites (reporting 28, adapter 11, detection 10,
delivery 9, service 9, jobs 5, SCF 6, ATT&CK enrich 7, generator 8).

## What this wave deliberately does NOT do

Auth/tenancy (FUR-CMP-004), evidence envelope/immutable store (FUR-CMP-007),
connectors, AssertionSpecs with positive predicates, OSCAL 1.2.1 migration,
signed reports, durable jobs — these are Waves 1+ per the audit's sequence.
The current release should be presented as **deterministic security-control
signals with named verification levels**, not as an audit-grade compliance
verdict.
