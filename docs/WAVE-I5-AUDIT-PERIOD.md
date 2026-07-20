# Wave-I / Epic 5 — audit-period workflow

**Status:** shipped and verified live (sign-off → immutable snapshot → ZIP
download exercised end-to-end).

**Coverage:** engine **293 checks** green (strict); dashboard builds clean, 41
Node tests green; the workflow verified live in a browser.

## The workflow
A formal assessment window with a lifecycle and freeze/reopen control:

```
OPEN ──add / fulfil evidence requests──▶ (still OPEN)
OPEN | IN_REVIEW | REOPENED ──sign-off──▶ SIGNED_OFF (FROZEN)
SIGNED_OFF ──reopen (admin)──▶ REOPENED (unfrozen; frozen snapshot retained)
```

- **Assessment boundaries + periods** — each period has a scope boundary
  (e.g. "prod AWS · CIS v8") and a start/end window.
- **Evidence requests** — request evidence for a control (requested → provided);
  refused once the period is frozen.
- **Reviewer sign-off** — an auditor (export scope) signs off, which **freezes**
  the period.
- **Immutable audit snapshots** — sign-off captures the full audit package +
  control workspace, serialises it canonically, and writes it to the **write-once
  evidence store**; only its sha256 is recorded on the period, so a signed
  snapshot can never drift.
- **Downloadable ZIP** — a self-contained evidence package (manifest, OSCAL AR +
  POA&M, findings, report summary, control workspace). For a signed period the
  ZIP is **reconstructed from the immutable snapshot**, not rebuilt live.
- **Auditor-only access** — sign-off and ZIP download require the export scope
  (auditor/admin); analysts get 403.
- **Freeze / reopen** — reopen is **admin-only**; it unfreezes for further work
  while preserving the prior signed snapshot as a historical version.

## API
`POST /api/audit-periods` (admin) · `GET /api/audit-periods` ·
`GET /api/audit-periods/{id}` · `POST …/{id}/evidence-requests` ·
`POST …/{id}/evidence-requests/{req}/fulfill` · `POST …/{id}/signoff` (export) ·
`POST …/{id}/reopen` (admin) · `GET …/{id}/package.zip` (export, auditor-only).

## UI
A new **/audit** page: create periods, request evidence, sign off & freeze,
reopen, and download the ZIP. Added to the nav for admin / auditor / mssp.

## Also fixed
- The BFF proxy now passes response bodies through as **bytes** (arrayBuffer) and
  forwards `content-disposition`, so binary downloads (the audit ZIP) are not
  corrupted by a text round-trip.

## Verified live
Browser → BFF → engine: created a period, signed it off (froze it with a
content-addressed snapshot sha), and downloaded a valid ZIP whose manifest shows
`package_source: signed-snapshot`, `frozen: true`, `oscal_validation_ok: true`.
