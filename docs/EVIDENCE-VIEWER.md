# Evidence Viewer & Enterprise Evidence Posture (FUR-CMP-007+)

Makes Furix's tamper-sealed evidence **visible and auditor-usable**: every
`furix-evidence://<sha>` reference in the dashboard becomes a clickable chip that
opens the original event, its provenance, and a live integrity verdict — with
every access recorded server-side.

## Why (industry & regulatory grounding)

Compliance evidence is not optional record-keeping — it is a retention
obligation and the basis of every audit:

| Framework | Retention requirement | Reference |
|---|---|---|
| HIPAA | **6 years** of documentation/audit records; audit controls are a *required* spec | 45 CFR §164.316(b)(2)(i), §164.312(b) |
| PCI DSS 4.0 | **12 months** of audit logs; last **3 months** immediately available | Req 10.5.1 |
| SOC 2 / ISO 27001 | Continuous, timestamped, control-mapped evidence auditors trust | AICPA TSC / ISO 27001 Annex A |
| SEC 17a-4 | **WORM** or a tamper-evident audit-trail with independent verification | 17 CFR 240.17a-4 |

**How the field does it:** leading platforms (Vanta, Drata, AWS Audit Manager)
continuously collect, timestamp, and map evidence to controls, store it in a
read-only repository, and expose an auditor view. The gold standard for
immutability is **S3 Object Lock (Compliance mode)** — objects cannot be deleted
or overwritten even by root for the retention period. NIST **OSCAL** is the
emerging machine-readable exchange format (observations carry evidence, findings
reference observations).

**Where Furix already leads:** evidence is content-addressed (SHA-256 = address =
tamper seal), write-once, per-tenant AES-256-GCM encrypted, carries a full
provenance envelope, and is S3-Object-Lock-ready — a forensic-grade posture most
competitors lack. This change adds the enterprise *surface* on top: retrieval,
a viewer, and an access-audit trail.

## What shipped

### Backend — `GET /api/evidence/{sha256}`
- Resolves a content address to `{ raw, envelope, integrity_verified, size_bytes, raw_uri }`.
- **Live integrity re-verification**: the stored (decrypted) bytes are re-hashed
  and compared to the address, so a caller can *prove* the evidence is untampered.
- Auth + tenant-isolated (`SCOPE_READ`, per-tenant store); 400 on a malformed id,
  404 when nothing is retained, 401 anonymous.
- **Access-audit**: every view writes an `evidence.access` entry to the tenant's
  administrative audit log (actor, integrity result, source) — "who viewed which
  evidence, when", which auditors require.
- Impl: `engine/api/service.py::get_evidence`, `engine/api/main.py`.

### Frontend — clickable evidence viewer
- `furix-evidence://` references in the control table are now buttons that open
  an **evidence modal** showing the original event (pretty-printed), the full
  provenance envelope (source, observed-at vs collected-at, collector/parser/
  schema versions, encryption-at-rest, tenant/boundary), and a green
  **"Integrity verified"** badge (or a red failure state).
- Impl: `dashboard/src/components/compliance/evidence-modal.tsx`,
  `dashboard/src/lib/data/furix-api.ts::getEvidence`, wired in `control-table.tsx`.

### Retention & legal hold (FUR-CMP-008)
- **Retention** is computed at *read* time from the object's `collected_at` plus a
  configurable policy — because evidence is write-once, nothing is stamped onto
  the sealed envelope, so a policy change applies uniformly. Regulatory floors by
  framework (`FRAMEWORK_RETENTION_DAYS`): **HIPAA 6y**, PCI DSS 1y, SOX 7y, SOC 2
  1y, ISO 27001 3y. The effective policy is the strictest applicable; default is
  HIPAA 6y (`FURIX_RETENTION_CLASS` / `FURIX_RETENTION_DAYS` to override). Returns
  `retain_until`, `expired`, `days_remaining`.
- **Legal hold** is a separate mutable per-tenant registry (place/release), since a
  hold is changeable state that cannot live in the write-once object. An active
  hold **overrides retention expiry** — held evidence is never past-retention.
- Endpoints: `POST /api/evidence/{sha}/legal-hold` (place — auditor/admin) and
  `DELETE …/legal-hold` (release — admin only); both audited
  (`evidence.legal_hold.place|release`). The evidence viewer shows retain-until /
  days-remaining / expired and the hold state, with role-gated place/release
  buttons.
- Impl: `engine/compliance_reporting/retention.py`,
  `engine/compliance_reporting/legal_hold.py`, service + endpoints, and the modal.

## RBAC — all roles now tested end-to-end

The role→scope model was only ever exercised for `admin`. Added an HTTP-level
matrix (`engine/api/test_auth.py::test_endpoint_rbac_matrix_all_roles`) covering
every role through the real stack:

| Role | read | ingest (POST /api/ingest) | export (GET /api/oscal) | admin (GET /api/admin/audit-log) | evidence (GET /api/evidence/…) |
|---|---|---|---|---|---|
| admin | ✅ | ✅ | ✅ | ✅ | ✅ |
| analyst | ✅ | ✅ | ⛔ 403 | ⛔ 403 | ✅ |
| auditor | ✅ | ⛔ 403 | ✅ | ⛔ 403 | ✅ |
| mssp | ✅ | ✅ | ⛔ 403 | ⛔ 403 | ✅ |
| readonly | ✅ | ⛔ 403 | ⛔ 403 | ⛔ 403 | ✅ |

Anonymous evidence access is `401`; every authorized access is audited.

## Deploy fixes folded in (bugs hit during bring-up)

1. **Duplicate `FURIX_COOKIE_SECURE` key** in `deploy/docker-compose.yml` (web
   service) — invalid YAML that made `docker compose` refuse to parse. Removed.
2. **Empty issuer → "issuer mismatch" 401 on every per-user call.** The BFF
   minted tokens with `iss` from `FURIX_OIDC_ISSUER ?? "furix-bff"`, but compose
   passes that var as an **empty string**, which `??` does not replace — so
   `iss:""` and the API rejected every token. Fixed at the root in
   `dashboard/src/lib/bff/token.ts` (`||` instead of `??`), with a regression test.
3. **Login directory required.** The dashboard image runs `NODE_ENV=production`,
   which disables the built-in demo users; a `FURIX_BFF_USERS` directory (or
   OIDC) is required to log in. Documented with a ready demo block in
   `deploy/.env.example` (four users, one per role).
4. **File upload 403 (CSRF).** `ingestFile()` used a raw `fetch` that omitted the
   `x-csrf-token` header, so the BFF rejected every log-file upload with
   `403 CSRF token missing or invalid` (text ingest worked because it goes
   through the client helper that adds it). Fixed by exporting `readCsrf` and
   attaching it (plus explicit same-origin credentials) to the upload in
   `dashboard/src/lib/data/furix-api.ts`.

## Verification (all local, pre-push)

- Engine: `python -m api.test_service` (17/17, incl. retention + legal-hold),
  `python -m api.test_auth` (21/21, incl. the all-roles matrix + legal-hold RBAC).
- Dashboard: `npm test` (45/45 BFF tests, incl. the issuer regression + evidence
  & legal-hold RBAC), `npm run build` (clean `tsc` + `next build`).
- File-upload CSRF fix verified live on the server (upload succeeds end-to-end).

## Demo script (for a client)

1. Sign in (e.g. `auditor@byoc.com` — the realistic evidence consumer).
2. **Ingest** → Generate demo logs → open **Compliance** → expand a gap control.
3. Under *Evidence lineage*, click a `furix-evidence://…` chip.
4. The modal shows the exact original event, its provenance, and
   **Integrity verified ✓** — "every finding traces to a tamper-sealed copy of
   the source event, and every look is logged."

## Not yet built (future increments)

- WORM posture indicator (filesystem vs S3 Object Lock) surfaced in the viewer.
- Retention **expiry enforcement / purge job** (today retention is computed and
  displayed, and legal hold blocks expiry — but nothing is auto-deleted yet).
- Evidence viewer wired into the control-detail page and posture-run lineage.
