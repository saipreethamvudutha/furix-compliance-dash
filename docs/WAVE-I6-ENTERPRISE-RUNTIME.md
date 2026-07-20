# Wave-I / Epic 6 — enterprise runtime

**Status:** shipped. Six enterprise-runtime substrates, each a real, tested
module; the live infra paths (Postgres, KMS, S3, IdP) are guarded drop-ins tested
against stubs/local crypto — the same pattern as the boto3 collector.

**Coverage:** engine **310 checks** green (strict) — incl. **14 enterprise
tests** + 3 new integration tests (admin audit log, queue stats, SCIM).

## #1 · Complete administrative audit log
`admin_audit.py` — an **append-only, hash-chained** log: every entry commits to
the previous entry's hash, so any insert/edit/delete anywhere in the chain is
detectable by re-walking it. Per-tenant chains. Wired into the privileged
actions (attestation approve, connector register/posture-run, control-profile
edit, audit-period sign-off/reopen, SCIM changes).
- `GET /api/admin/audit-log` (admin) · `GET /api/admin/audit-log/verify` (admin,
  returns `{ok, checked, break_at, reason}`).

## #2 · KMS-backed asymmetric signatures
`signing.py` — one `Signer` interface, two impls: `LocalRsaSigner` (RSA-PSS/
SHA-256 in-process) and `KmsSigner` (AWS KMS `Sign`/`GetPublicKey`; the private
key never leaves KMS; boto3 client injected). `verify_signature(data, sig,
public_key_pem)` verifies with the **public key alone** — an external auditor can
verify a Furix artifact with no shared secret. Tested with real local crypto and
a KMS stub.

## #3 · Object storage for immutable evidence
`object_store.py` — pluggable content-addressed backend: `FilesystemObjectStore`
(dev/single-node) and `S3ObjectStore` (S3 put/get/head, injectable client). Keys
are the sha256 → writes are idempotent/write-once; S3 Object Lock gives true WORM
evidence. Tested against a stub S3 client (no network).

## #4 · Real scheduler / worker queue
`work_queue.py` — a durable, lease-based queue: `enqueue`, atomic `claim` (two
workers never get the same job), `complete`/`fail` (bounded exponential backoff →
`dead` past max attempts), and `requeue_expired` (crashed-worker recovery). A
`Worker` runs one job via an injected handler. `GET /api/admin/queue/stats`
(admin). The Postgres `FOR UPDATE SKIP LOCKED` multi-worker claim is in the DDL.

## #5 · SCIM 2.0 user provisioning
`scim.py` + `/scim/v2/Users` (create / get / list with `userName eq` filter /
replace / delete). An enterprise IdP provisions and, crucially, **deprovisions**
users — `DELETE` deactivates so access is revoked immediately while the identity
+ audit trail persist. Tenant-scoped; admin-scoped endpoints.

## #6 · PostgreSQL with tenant RLS
`deploy/db/rls-schema.sql` — the production target: the durable tables in
Postgres with **Row-Level Security** so tenant isolation is enforced by the
DATABASE (`SET app.current_tenant = …` + `USING (tenant = furix_current_tenant())`
policies, `FORCE ROW LEVEL SECURITY`, a least-privilege `furix_app` role). SQLite
remains the tested, interface-compatible substrate; this is the drop-in target.

## Honest remaining scope
- **Live migration** of the stores onto Postgres/RLS, KMS signing of the audit
  snapshot, and S3-backed evidence are configuration/dependency switches onto the
  machinery built and tested here — they need a live Postgres / KMS / S3 to
  exercise end-to-end (like boto3 needs live AWS).
- The admin audit log + SCIM are API/IdP-facing; a bespoke admin **UI** for the
  audit log is a small follow-up (the data is served and integration-tested).
- The async worker is wired as substrate + stats; moving connector posture-runs
  onto it by default (vs. inline) is a deployment switch.
