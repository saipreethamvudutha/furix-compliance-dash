# Wave-I / Epic 3 — trust-boundary hardening

**Status:** shipped and verified live (session revocation exercised end-to-end).

**Coverage:** engine **275 checks** green (strict); dashboard builds clean, **41
Node tests** green (12 BFF + 23 OIDC + 6 revocation). Session revocation verified
live in a browser-equivalent flow.

## #1 · Demo-tenant isolation
Synthetic/demo data can no longer be mistaken for, or mixed into, a real tenant:

- Every posture run records `data_mode` (`"demo"` for the `demo-aws` connector,
  `"live"` otherwise).
- In **production** the demo connector kinds are **refused** at register, run,
  and posture-run (`400 — demo connectors are disabled in production`), so a
  production tenant can only ever hold live evidence.

## #2 · Two-person attestation approval (segregation of duty)
Approving human evidence now requires two distinct people:

- The **submitter can never approve their own** attestation (`400 self-approval
  forbidden`).
- Each distinct approver counts once; a duplicate approval is rejected.
- The attestation only becomes `APPROVED` after `required_approvals` distinct
  non-submitter approvals (default 1 → submitter + one approver = two people;
  raise `FURIX_ATTEST_REQUIRED_APPROVALS` for a stricter quorum). Until then it
  stays pending and cannot back a control PASS.

## #3 · OIDC hardening
- **Bounded timeouts** on every IdP call (discovery, token exchange, JWKS) via
  `AbortController`, so a hung/slow provider can't stall the request.
- **Open-redirect defence**: the post-login `returnTo` is sanitised to a
  same-origin relative path — absolute URLs, `//host`, and `/\host` all fall back
  to `/`.
- **id_token freshness**: an `iat` in the future is rejected (skew/forgery), in
  addition to the existing `exp` check.
- **No takeover via unverified email**: an email claim is only used as the
  subject when the IdP asserts `email_verified` — otherwise the stable `sub` is
  used.

## #4 · Session revocation
Sealed session cookies are stateless, so a stolen cookie would otherwise stay
valid until expiry. A server-side revocation check now kills sessions on demand:

- Every session carries a unique `sid`.
- **Logout** revokes that exact `sid` — a copied cookie is dead immediately.
- **Sign-out-everywhere** (`POST /bff/auth/revoke-all`, CSRF-protected) revokes
  every session for the subject issued before now (suspected compromise /
  password change).
- The BFF proxy rejects any revoked session with `401 session revoked`.

Backed by an atomic file-backed store (`FURIX_BFF_STATE_DIR`) — correct for a
single BFF instance; a shared store (Redis/Postgres) is the multi-instance
upgrade in Epic 6.

**Verified live:** an authenticated call returned 200; after logout the *same
pre-logout cookie* was rejected 401 "session revoked"; and a `revoke-all` from
one device invalidated a session issued to another.

## Also fixed
- Attestation approve/reject API now maps rule violations (self-approval,
  duplicate, bad state) to `400` and only unknown ids to `404`.
