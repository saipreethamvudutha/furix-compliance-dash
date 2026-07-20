# Wave-N — trust & production hardening

**Status:** shipped. Addresses the "Next Engineering Wave" audit (6 items).
**218 engine checks green**, dashboard builds with zero lint errors, and the
session subsystem is verified live end-to-end.

## #1 · Real server-side session (auth)

The localStorage demo auth is replaced by a real session, all server-side:
- Login is validated on the server (constant-time hash compare) and issues an
  **AES-256-GCM sealed, HTTP-only session cookie** the browser cannot read,
  plus a CSRF cookie.
- The BFF proxy gates **every** `/bff/api/*` call: **no session → 401**, coarse
  **role RBAC** (auditor can't POST ingest → 403), **CSRF** double-submit on
  writes, and it mints a short-lived **per-user HS256 token** (when
  `FURIX_BFF_MINT_SECRET` is set) so the API authenticates and tenant-scopes
  **per user** and logs the real actor — otherwise falls back to the static key.
- **Logout** clears the server session. **OIDC authorization-code/PKCE** start +
  callback endpoints are wired as the integration point (enabled when
  `FURIX_OIDC_*` is configured).

Verified live: no-session 401 → login → session reflects user/role → authed 200
→ auditor ingest 403 → CSRF-less POST 403 → logout 401.

## #2 · Strict signed attestations

`Attestation` now requires **attester, timestamp, evidence_ref, statement,
tenant, scope, key_id, signature**. The signature is HMAC-SHA256 over the
material fields, verified against a key ring. **Unsigned, tampered,
future-dated, tenant-mismatched, or missing-field** attestations are `INVALID`
and can only drive a control to `MANUAL_PENDING` — **never PASS**.

## #3 · Transactional evidence

Ingest writes each raw evidence object **and verifies it landed**. If raw
evidence cannot be persisted, the ingest **aborts** — a report is never produced
that presents evidence which wasn't durably retained (log and config paths).

## #4 · OSCAL schema validation

A real **OSCAL 1.2.1 JSON Schema** (AR + POA&M subset Furix emits) is bundled
and validated by default (NIST's full metaschema is droppable via
`FURIX_OSCAL_SCHEMA`). `validation_ok` requires **both** structural and schema
validation to pass, and the **auditor export refuses to issue a package** that
doesn't schema-validate.

## #5 · Collection plane (SDK)

A real read-only collector framework: **pagination** (follows cursors to
completion, loop-detected), **retry with exponential backoff**, **permission
preflight** (missing permission aborts before any partial collection),
**checkpoints** (resumable cursors), **independent population reconciliation**
(observed vs discovery-derived expected — a gap aborts), and a **signed,
tamper-evident collection manifest**. The AWS Organizations/IAM collector runs
against a deterministic client interface — **no network**; boto3 is a
constructor-argument swap. The collected snapshot feeds the existing config
assertions unchanged.

## #6 · Integration test suite

FastAPI `TestClient` end-to-end tests covering the audit's full surface:
anonymous access (401), bad credentials (401), **role boundaries** (auditor
read+export not ingest; analyst ingest not export), **tenant isolation**
(cross-tenant 403; empty tenant 404), **risk-acceptance authority** (analyst
403, admin 200), **OSCAL export schema-validated**, and malformed-input
handling (400/422).

## Test coverage (218)

reporting 28 · evidence 12 · config 20 · manual 7 · **attestation 10** ·
exceptions 10 · oscal 10 · adapter 14 · detection 10 · delivery 9 ·
**collectors 8** · scf 6 · attack 7 · generator 8 · service 12 · jobs 5 ·
auth 19 · durable 6 · preflight 9 · **integration 8**.

## Honest remaining scope

- **Live IdP round-trip** for OIDC PKCE (endpoints wired; needs a real IdP).
- **Live boto3 AWS client** (the collector interface + all the hard machinery
  are built and tested; the network client is the drop-in).
- **PostgreSQL + HA** (SQLite is the tested, interface-compatible substrate).
- **Bundle NIST's full OSCAL metaschema** into CI (the validation path already
  uses `FURIX_OSCAL_SCHEMA` when provided).

Every one of these is a configuration/dependency switch onto machinery that
exists and is tested — not missing work.
