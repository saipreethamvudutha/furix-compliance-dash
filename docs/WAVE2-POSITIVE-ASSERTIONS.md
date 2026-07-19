# Wave 2 — Positive config-posture assertions

**Status:** shipped (first increment). This is the wave that makes a control
legitimately **`met`** with an **earned compliance %** — not detection silence.
Closes the core of FUR-CMP-009 (config connectors) and completes the positive
half of FUR-CMP-008 (assertion model).

## Why this matters

Everything before Wave 2 was *detection-only* — negative predicates ("a bad
thing was observed"). Silence produced `unknown`, never `pass`; every framework
`compliance_pct` was `null`. That's honest, but it means Furix could only ever
show risk, never assurance. **Positive assertions** evaluate whether a control
is *actually in place* over an expected population of config resources — and a
passing positive assertion is the only thing that can turn a control green.

## What shipped

**Connector framework (`connectors.py`).** A connector normalizes a provider's
config into a uniform `Resource` stream plus an `expected_counts` manifest.
Deterministic, dependency-free, reads a JSON **snapshot** — the exact shape a
live AWS/Okta/GitHub API client would emit, so swapping in a real client is a
drop-in later. Multi-source snapshots merge.

**Positive assertion catalog (`config_assertions.py`).** 9 assertions across
CIS Controls 3 / 5 / 6 / 16, each with applicability, a positive predicate,
control edges, severity, a rationale, and a content-derived `evaluator_hash`:

| Assertion | Control | Checks |
|---|---|---|
| CFG-IDP-MFA-EXTERNAL | 6 | MFA enforced on every internet-facing app |
| CFG-IDP-ADMIN-MFA | 6 | MFA enrolled for every admin |
| CFG-IDP-DORMANT | 5 | no active account dormant >90d |
| CFG-AWS-ROOT-MFA | 6 | root account MFA on |
| CFG-AWS-KEY-ROTATION | 5 | no active access key >90d |
| CFG-AWS-PUBLIC-BUCKET | 3 | object storage blocks public access |
| CFG-GH-BRANCH-PROTECTION | 16 | default branch protected |
| CFG-GH-REVIEW-REQUIRED | 16 | ≥1 review required before merge |
| CFG-GH-SECRET-SCANNING | 16 | secret scanning enabled |

**Population-gated evaluation.** A `PASS` requires the **full expected
population observed** AND every in-scope resource satisfying the predicate. If
the connector saw fewer resources than expected → `UNKNOWN`
(`incomplete_population`), never PASS. Partial config coverage can't masquerade
as compliant.

**Report merge (`report_builder.py`).** A control is `compliant` **only** when
a positive assertion verified it, nothing failed (detection or config), and the
config population is complete. Detection *silence* no longer blocks a positive
pass (no attack observed is the normal good state), but real detection findings
still outrank a clean config — so a control with both a passing config check and
a firing detection rule stays `at_risk`. Framework `compliance_pct` is now
earned and non-null.

**Verification.** The independent verifier recomputes control status from the
combined detection + config outcomes, plus new `CFG-*` gates: every config
assertion's `evaluator_hash` must match the catalog, its population must
reconcile, and a `PASS` is rejected unless the population is complete with zero
failures. A forged config pass fails verification.

**Ingest + dashboard.** `POST /api/ingest-config` (scoped, tenant-isolated)
ingests a snapshot and combines it with the latest detection batch; the demo
generator applies a demo snapshot so "Generate demo logs" shows real `met`
controls. The dashboard drill-down shows each met control's positive evidence —
the passing assertion, its `furix-assertion://` URI, and a reproduction command
with the population (`2/2 resources`).

## Proof (demo_batch + demo_config_snapshot)

- **Control 3 (Data Protection)** → `met` (public-access-blocked verified)
- **Control 16 (Application Software Security)** → `met` (branch protection +
  review + secret scanning, all 2/2) — a control that was *not_monitored*
  before now positively passes
- **Controls 5 & 6** → stay `at_risk` (real detection findings outrank clean
  config)
- **CIS compliance_pct** → earned (was `null`)

133 checks green across 12 suites (config **12**, adapter 14, plus all prior).

## Increment 2 (W2b) — breadth, freshness, lineage

**30 assertions across 13 CIS controls** (was 9 across 4). Added CIS 1 (asset
inventory + ownership), 2 (software support/inventory), 4 (secure-config
benchmark + no default creds), 7 (vuln SLA + authenticated scan), 8 (log
enablement/retention/central), 10 (EDR coverage + current), 11 (backup
enabled/tested/encrypted), 12 (firewall review + segmentation), 13 (IDS), plus
more 3/16 (encryption-at-rest, dependabot). On the demo this takes CIS from 2 →
**8 compliant controls, 53% earned compliance, 83% coverage** (NIST 90%).

**Freshness / STALE (FUR-CMP-010).** `evaluate(snapshot, as_of=)` — an explicit
evaluation time (never wall-clock, so determinism holds). If evidence is older
than an assertion's freshness SLO, a would-be PASS becomes **STALE**: stale
evidence can never make a control compliant, and the verifier rejects a PASS on
stale evidence (`CFG-FRESH-GATE`). `config_as_of` threads through `build_report`.

**Config evidence lineage (FUR-CMP-007 parity).** Every config resource now has
a deterministic `resource_sha256` and a `furix-evidence://` URI; `ingest_config`
writes each raw resource to the tenant's immutable evidence store, so config
evidence is as reproducible as log evidence. Verifier checks the URI matches the
hash (`CFG-EVID`).

139 checks green across 12 suites (config **18**).

## Still ahead in Wave 2

Live API connectors (AWS/Okta/GitHub) behind the same snapshot shape;
per-resource freshness (vs snapshot-level); the remaining CIS 9/14/18 controls
that need people/process evidence, not config (Wave 5 territory).
