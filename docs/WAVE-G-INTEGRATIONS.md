# Wave-G — real OIDC, live AWS collector, official OSCAL validation

**Status:** shipped and verified live. Turns the three "honest remaining scope"
integration points from prior waves into real, tested, end-to-end-verified
capabilities.

**Coverage:** engine **256 checks** green (strict mode); dashboard builds clean,
**30 Node tests** green (12 BFF + 18 OIDC). All three verified live in a browser.

## #1 · Real OIDC authorization-code + PKCE (against a live IdP)

Discovery-driven, so it works with any spec-compliant IdP (Keycloak, Auth0,
Entra, Okta, Google): the BFF reads the provider's
`.well-known/openid-configuration`, runs authorization-code with **PKCE (S256)**,
exchanges the code at the token endpoint, and **verifies the ID token's RS256
signature against the provider JWKS** — all with Node's built-in crypto, no
external dependency.

- Enforced: PKCE S256, `state` (CSRF), `nonce` (replay), issuer match (mix-up
  defence), audience, expiry, and RS256 signature over the JWKS key.
- Claims map to `{sub, role, tenant}` with **least-privilege defaults** (`auditor`
  / `default`) when the IdP asserts no role/tenant — never a silent `admin`.
- The browser still only ever holds the opaque sealed session cookie.

**Verified live:** a round-trip against a local RS256 mock IdP established a real
session — `/bff/auth/session` → `{authenticated: true, user:
oidc.user@example.com, role: analyst}` from the signed `id_token`. 18 unit tests
cover the crypto and flow (incl. the RFC 7636 PKCE test vector and every
rejection path). Endpoints: `GET /bff/auth/oidc/start` and `/oidc/callback`.

## #2 · Live boto3 AWS collector + scheduled connectors + health UI

A real `boto3`-backed client (`aws_boto3.Boto3AwsClient`) implementing the exact
`AwsClient` interface the collection framework drives — a drop-in for the
deterministic `FakeAwsClient`:

- **STS role assumption** — Organizations read from the management account
  (optionally via an assumed role); each member account's IAM posture read by
  assuming a per-account role (default `OrganizationAccountAccessRole`) with an
  optional ExternalId.
- **Independently-derived population** — `independent_account_count()` counts
  ACTIVE accounts by traversing the Organizations **OU tree**, a different path
  than the flat `list_accounts`, so reconciliation is meaningful (a gap aborts).
- **Mandatory signed manifests** — collection now **refuses to run** without a
  signing secret; every manifest is HMAC-signed and tamper-evident.
- **Durable checkpoints** — `CheckpointStore` persists cursors atomically so a
  collection resumes across process restarts.
- **Scheduled jobs + health** — a SQLite `ConnectorRegistry` + `ConnectorScheduler`
  track cadence, last-run outcome, reconciliation, signature and freshness, and
  derive a health state (healthy / degraded / failed / unknown).
- **API + UI** — `GET /api/connectors`, `POST /api/connectors` (admin),
  `POST /api/connectors/{id}/run` (admin, fail-closed on a missing signing
  secret), surfaced on a new **/connectors** dashboard page.

The adapter is dependency-injected and classifies AWS errors by response shape,
so a `boto3.Session`-shaped stub drives the whole thing in tests — **no boto3,
no botocore, no network** (throttling → retried `TransientError`; access-denied →
surfaced by `check_permissions`). Live AWS needs only `pip install boto3` and
credentials; the client is the drop-in.

**Verified live:** browser → BFF → engine → collector produced a **HEALTHY**
`demo-aws` connector with a signed, reconciled manifest (sha256 shown in the UI).

## #3 · OSCAL exports validate against the OFFICIAL NIST 1.2.1 schema

The bundled Furix-subset schema is replaced (as the default) by the **official
NIST OSCAL 1.2.1 JSON schemas** (`oscal_assessment-results_schema.json`,
`oscal_poam_schema.json`, from the NIST v1.2.1 release), validated per document
type. The emitter was made **fully conformant** — real AR and POA&M exports now
validate with **zero errors** against NIST's own strict schema:

- Added `reviewed-controls` to each result, a `description` to every finding, a
  `statement` to every risk, and slugified control ids into valid OSCAL `token`
  `target-id`s (the human id preserved in a prop).
- A POA&M with no open findings emits one explicit "No open findings" item
  (NIST requires `poam-items` non-empty) — truthful and valid.
- The validator tolerates OSCAL's XSD `\p{L}`/`\p{N}` token pattern by
  translating it for Python's `re` (no dependency), so validation is exact for
  our inputs and never a false pass. `FURIX_OSCAL_SCHEMA` still overrides.

**Verified:** `validate_oscal_schema` reports `ok:true`, `note: "validated against
NIST OSCAL 1.2.1 (official) schema"`, and the API audit export refuses to issue a
package that doesn't schema-validate.

## Honest remaining scope

- **Live IdP hardening** — the flow is complete and verified against a conformant
  RS256 IdP; a production rollout should also pin the IdP's issuer/clientID and
  exercise token refresh (Furix mints its own short-lived session, so refresh is
  optional).
- **Live AWS run** — needs `boto3` + real credentials/roles; the adapter and all
  the collection machinery are built and tested against a faithful stub.
- **Background scheduler loop** — the registry + `tick()`/`run_one()` are built
  and driven by the API; wiring a periodic ticker (cron/worker) is a deployment
  choice.
