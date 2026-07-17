# Phase 3 — Dashboard Wired to the API: COMPLETE (build-verified)

**Done in Opus 4.8, 2026-07-16.** The secureguard Next.js dashboard now consumes
the Furix API, with an ingestion screen and live compliance views. Verified by a
clean `tsc --noEmit` (exit 0) and a full `next build` (exit 0, 0 errors, all 31
routes compiled including the 2 new ones).

## What was built (in `secureguard/`)

| File | What |
|---|---|
| `src/lib/data/client.ts` | Typed API client. Base URL from `NEXT_PUBLIC_API_URL`. `apiGet/apiPost`, `safeGet` (graceful fallback), `apiHealthy`. Fails soft on network/HTTP errors. |
| `src/lib/data/furix-api.ts` | One typed function per backend endpoint (`ingestLogs`, `ingestFile`, `getLiveFrameworks`, `getLiveSummary`, `getReports`, `getTrend`, `getDiff`) with shapes mirroring the API contract exactly. |
| `src/lib/data/compliance.ts` | `getComplianceFrameworks()` is now **API-first**: fetches `/api/frameworks`, falls back to the original seed data when the backend is unreachable (demo mode never breaks). |
| `src/components/compliance/status.tsx` | Status vocabulary + `StatusPill` (met/gap/in_progress/not_applicable) + severity colors. |
| `src/components/compliance/framework-rings.tsx` | Selectable CSS-conic donut cards per framework (met/gap/na counts, no chart lib). |
| `src/components/compliance/control-table.tsx` | Control drill-down: gap-first sort, expandable rows showing **evidence** + **AI recommendation** (traceable to real findings). |
| `src/components/compliance/verification-badge.tsx` | Furix's trust wedge — "independently verified, N checks recomputed" + integrity hash. |
| `src/app/ingest/page.tsx` | **The ingest screen**: paste/upload logs + log-type select + "Load sample" → `POST /api/ingest` → live posture (rings, verification badge, regression alerts, drill-down). Loading + error states. |
| `src/app/compliance/live/page.tsx` | Latest-report posture view (no re-ingest); graceful "no report yet → Ingest logs" empty state. |
| `src/components/layout/sidebar.tsx` | New nav entries **Ingest** + **Compliance** wired into all four role menus. |
| `.env.local.example` | `NEXT_PUBLIC_API_URL=http://localhost:8000` |
| `.claude/launch.json` | `npm run dev` config (port 3000) for the dashboard. |

## Design notes (enterprise-grade)
- **Graceful degradation:** every read fails soft — backend down → dashboard shows
  demo seed data / a "no report yet" empty state, never a crash.
- **Traceability preserved end to end:** each gap row's evidence + AI recommendation
  come straight from the report's control→test→finding chain (a real POL rule that
  fired), surfaced through the adapter. Nothing is invented in the UI.
- **No new heavy deps:** rings are CSS conic-gradients; icons are the existing
  lucide-react; components reuse the app's Tailwind theme + CSS variables.

## Verification done (local)
```
npm install         → 485 packages, ok
npx tsc --noEmit    → exit 0 (clean typecheck of the whole app)
npm run build       → exit 0, "✓ Compiled successfully", 0 errors,
                      routes include ○ /ingest and ○ /compliance/live
```

## ⬜ Live visual check (server / local with API up)
```bash
cd secureguard && npm run dev          # http://localhost:3000
# log in (admin@byoc.com / admin123), open /ingest, "Load sample", Ingest
# with the Furix API running (uvicorn api.main:app) + DB bootstrapped.
```
The build proves the code typechecks and compiles; the end-to-end visual flow
(ingest → verified posture) needs the API + DB up (Phases 1–2 server steps).

## Where we stand
- Phase 0 ✅ · Phase 1 ✅ code · Phase 2 ✅ core · **Phase 3 ✅ build-verified**
- Remaining: Phase 4 (log generator — local), Phase 5 (docker-compose + RUNBOOK +
  monorepo assembly — server), and the server bring-up of Phases 1–2.
