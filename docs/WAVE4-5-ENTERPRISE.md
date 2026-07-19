# Waves 4 & 5 — enterprise ops + audit-ready output

**Status:** shipped. Closes FUR-CMP-013/015, FUR-OPS-001/002, FUR-SEC-003,
FUR-QA-001, and advances FUR-CMP-004 (OIDC) and FUR-CMP-017 (OSCAL 1.2.1).

## Wave 5 — audit-ready output

**Exception / remediation lifecycle (FUR-CMP-013).** An at-risk control becomes
a **Finding** with an owner and due date. It moves through a workflow —
`OPEN → IN_PROGRESS → REMEDIATED → RETEST_PENDING → CLOSED` — or is granted a
time-boxed **risk-acceptance exception** (approver + rationale + compensating
control + expiry) that deterministically **EXPIRES** and returns the control to
at-risk. Nothing is deleted: the store is **event-sourced**, and every
transition appends an immutable event with actor, from/to state, reason,
timestamp and a content-derived event id — the audit's "handover rule". Closing
requires a passing retest; risk acceptance requires admin (approver) authority.

Scoped API: `POST /api/findings/derive`, `GET /api/findings`,
`POST /api/findings/{id}/transition`, `GET /api/findings/{id}/history`. The live
`/compliance` frameworks annotate at-risk rows with their remediation/exception
status.

**OSCAL 1.2.1 + POA&M (FUR-CMP-017/015).** Bumped 1.1.2 → 1.2.1. A new zero-dep
`oscal.py` emits **content-deterministic** Assessment Results (a finding per
at-risk control) and a **Plan of Action & Milestones** (a poam-item per open
finding, carrying owner, due date and any risk-acceptance deviation). A
structural `validate_oscal` enforces the invariants that separate a valid
package from an OSCAL-shaped one: known root, `oscal-version` consistency,
well-formed UUIDs, and internally-resolvable references.

**Auditor workspace export (FUR-CMP-015).** `GET /api/audit/export` (auditor
`export` scope) bundles the verified report summary + valid OSCAL AR + POA&M +
the open-findings workpaper — a self-contained package an auditor can inspect
without trusting the live dashboard.

## Wave 4 — enterprise ops

**OIDC / JWT bearer auth (FUR-CMP-004).** The API now accepts IdP-issued JWTs
alongside API keys. **HS256** (shared secret) is verified with the standard
library — fully working and tested. **RS256/JWKS** (public IdPs) is implemented
against `pyjwt[crypto]` when present and raises a clear error when absent —
never silently accepts. Verification enforces signature, `exp`/`nbf`, and the
configured `iss`/`aud`; the tenant and role come from configurable claims, never
trusted without a valid signature. Config via `FURIX_OIDC_*`.

**Durable jobs + report index (FUR-OPS-001/002).** SQLite-backed, transactional,
crash-safe stores replace the in-process job memory and append-only filesystem
index. Jobs a crash leaves mid-flight are **recovered as errored** on restart;
the index upsert is idempotent and ordered. SQLite is the same interface a
Postgres backend implements — the production swap is a connection string.
Opt-in via `FURIX_JOB_DB`.

**Evidence encryption at rest (FUR-SEC-003).** The immutable evidence store
supports transparent envelope encryption: a per-tenant data key (HKDF-derived,
stdlib) seals object bytes with an authenticated cipher (**AES-256-GCM** via
`cryptography` when present). The content address stays the SHA-256 of the
**plaintext**, so dedup and `raw_uri` pointers are unchanged; the envelope
records the key id + algorithm, and unconfigured deployments store plaintext
with `encrypted: false` — never a silent pretence of encryption. Enable with
`FURIX_EVIDENCE_MASTER_KEY`.

**CI + SBOM (FUR-QA-001).** `.github/workflows/ci.yml` runs the full engine
suite (`run_all_tests.py`, 168 checks, stdlib-only), the dashboard build, lint
(advisory — FUR-QA-002 tracked), a production `npm audit`, and generates
CycloneDX SBOMs for engine + dashboard on every push/PR.

## Test coverage

**168 checks green** via `python run_all_tests.py`, one command:
reporting 28 · evidence 12 · config 18 · **exceptions 9** · **oscal 7** ·
adapter 14 · detection 10 · delivery 9 · scf 6 · attack 7 · generator 8 ·
service 10 · jobs 5 · **auth 19** · **durable 6**.

## Honest scope notes (what needs live infra to fully exercise)

- **RS256/JWKS** OIDC is coded and guarded but exercised only when
  `pyjwt[crypto]` is installed against a real IdP; HS256 is fully tested here.
- **AES-256-GCM** evidence encryption is coded and wired; the roundtrip is
  tested with a stub AEAD (so it runs without the dep). Install `cryptography`
  and set the master key to activate the real cipher.
- The **durable stores are SQLite** — genuinely durable/transactional and the
  Postgres swap is interface-compatible, but the Postgres backend itself is a
  follow-on.

These are configuration/dependency switches, not redesigns — the interfaces,
wiring, and tests are all in place.
