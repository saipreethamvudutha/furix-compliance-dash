# Wave-I / Epic 4 — real compliance workspace

**Status:** shipped and verified live.

`/compliance` becomes a real GRC workspace: every control now carries not just
Furix's computed verdict, but the human governance context an auditor expects —
joined into one view.

**Coverage:** engine **284 checks** green (strict); dashboard builds clean, 41
Node tests green; workspace list + editable detail verified live in a browser.

## The workspace model
Furix computes the deterministic verdict (pass / at-risk from events + config).
A new **ControlProfileStore** (durable, per-tenant, SQLite) holds the *editable*
governance metadata separately, and the workspace view joins the two:

| computed (Furix) | governance (editable) | derived / linked |
|---|---|---|
| status / verdict | owner | evidence freshness (vs cadence) |
| worst severity | applicability + rationale | framework mappings (NIST/PCI/HIPAA) |
| config passing/failing | implementation narrative | linked findings |
| evidence mode | verification method + description | exceptions |
| | test cadence (days) | complete evidence lineage |

Every profile edit records `updated_by` / `updated_at` (feeds the Epic-6 admin
audit log). Validation is enforced (applicability, verification method, cadence).

## Evidence lineage
Each control detail traces the full chain back to first evidence: the report id
+ its integrity sha256, the config assertions that passed/failed, and the linked
**posture run** (its `data_mode`, snapshot-evidence sha, and report) — so an
auditor can walk from a control verdict to the exact collection that produced it.

## API + UI
- `GET /api/compliance/controls` — workspace summary rows (verdict + owner +
  applicability + freshness + framework counts + open findings).
- `GET /api/compliance/controls/{id}` — full detail (profile + verdict + mappings
  + findings + exceptions + lineage).
- `PUT /api/compliance/controls/{id}` — edit the governance profile
  (ingest-capable role; validation errors → 400).
- Dashboard: **/compliance/controls** (workspace table) and
  **/compliance/controls/[id]** (editable governance profile + framework mappings
  + findings + evidence-lineage panel); the main `/compliance` page links to it.
- BFF proxy now also forwards **PUT/DELETE** (was GET/POST only).

## Verified live
Browser → BFF → engine: the workspace listed all 18 controls with live verdicts,
owners, freshness and framework coverage; editing Control 6's profile (owner,
narrative, cadence 45) persisted and re-rendered, and the detail showed the full
framework mappings + evidence lineage (report integrity sha + posture-run
snapshot sha).

## Honest remaining scope
- Applicability = `not_applicable` doesn't yet exclude a control from the rollup
  math — it's recorded and displayed, but the coverage %/scoring still counts it
  (a scoring change to wire next).
