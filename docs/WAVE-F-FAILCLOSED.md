# Wave-F — fail-closed web security, mandatory attestations, CI that can't lie

**Status:** shipped. Four hardening fixes: web security fails closed, signed
attestation verification is mandatory end-to-end (with a tenant-scoped
submission/approval API), and CI installs a pinned dependency set so required
test suites run — a skipped required suite now FAILS the build.

**Coverage:** engine **232 checks** green (strict mode); dashboard builds with
zero lint errors and **12 BFF fail-closed / per-user-authorization tests** green.

## #1 · Mandatory signed attestation verification (`build_report`)

Manual/operational controls (CIS 9/14/15/17/18) can only pass on **human
evidence**. That path is now fail-closed at every layer:

- `evaluate_manual` **requires a verification key ring**. Without one an
  attestation is `INVALID` → the control is `MANUAL_PENDING`, never `PASS`.
- With a key ring, the attestation is signature-verified (HMAC-SHA256 over the
  canonical payload). Unsigned, tampered, future-dated, tenant-mismatched or
  missing-field attestations are `INVALID`.
- `build_report` threads `attestation_keyring` + `tenant` through, so a report
  built without a key ring can **never** flip a people/process control to
  compliant — proven by `test_report_without_keyring_keeps_manual_controls_pending`.

## #2 · Tenant-scoped attestation submission / approval API

A real human workflow behind the mandatory verification, durable in SQLite and
**segregated by duty**:

- `POST /api/attestations` — an ingest-capable role **submits** a signed
  attestation. Submission **verifies the signature against the tenant key ring
  first**; an unverifiable or cross-tenant submission is rejected (400) and
  nothing is stored.
- `POST /api/attestations/{id}/approve` / `/reject` — **admin only** (approval is
  an authority act). A SUBMITTED attestation is not usable until approved.
- `GET /api/attestations` — tenant-scoped listing (optionally by status).
- Only **APPROVED** attestations feed a report: the ingest paths pass
  `approved_attestations(tenant)` + the tenant key ring into `build_report`, so a
  pending or rejected attestation can never back a control PASS.

Key rings come from `FURIX_ATTEST_KEYS` (per-tenant or shared JSON). In
production an unconfigured ring is **empty** — every submission is rejected —
never a silent demo secret.

## #3 · Web security fails closed (BFF)

The Backend-for-Frontend refuses to serve on a weak production posture instead
of falling back to dev defaults:

- **Production readiness gate** (`env.ts`): if `FURIX_SESSION_SECRET` (16+ chars),
  `FURIX_BFF_MINT_SECRET`, or an identity source (`FURIX_BFF_USERS` **or** OIDC)
  is missing, the proxy returns **503** — it will not proxy with insecure
  defaults.
- **Session secret**: no dev fallback in production — a missing secret throws
  rather than sealing sessions with a well-known key.
- **No default users in production**: the built-in demo directory is dev-only;
  in production the directory is empty unless configured.
- **No static-key fallback in production**: per-user token minting is mandatory;
  a request that cannot mint a per-user token fails closed (503). The shared
  static key is used only outside production.

Tested (`node --test`) with 12 checks covering the readiness matrix, per-user
token minting, and the coarse per-user API authorization (RBAC) map. Per-user
API authorization is also enforced authoritatively by the API and covered by the
Python integration suite (role boundaries, tenant isolation, approval authority).

## #4 · CI that can't silently skip

- `engine/test-requirements.txt` pins FastAPI, Starlette, HTTPX, anyio,
  jsonschema, python-multipart, cryptography and PyJWT.
- CI installs it and runs the suite with **`FURIX_TEST_STRICT=1`**: a required
  suite whose dependency is missing, that won't import, or that runs zero tests
  is a **FAILURE** — a skipped required suite can no longer masquerade as green.
- The dashboard job runs `npm test` (the BFF fail-closed tests) on Node 24.

## Honest remaining scope

- **Live IdP round-trip** for OIDC PKCE (endpoints wired; needs a real IdP).
- **Key-ring management UI/rotation** for attestation signing keys (the ring
  interface and env wiring exist; rotation tooling is not yet built).
- `session.ts` / `users.ts` are covered end-to-end by the API integration suite
  and a live browser check rather than Node unit tests (their value-import of
  `./env` is not resolvable under Node's type-stripping test loader).
