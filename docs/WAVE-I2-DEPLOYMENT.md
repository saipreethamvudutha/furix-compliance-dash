# Wave-I / Epic 2 — production deployment contract

**Status:** shipped and verified live (full-stack smoke test green end-to-end).

Makes the stack deployable to production with real secret handling, the live AWS
collector installed, offline/air-gapped builds, a readiness probe, and an
executable end-to-end smoke test.

## What shipped

### All BFF/API secrets in Compose
The base `docker-compose.yml` now declares every Wave-F/G/H secret (with LOUD dev
defaults so `up` still works out of the box): session key, per-user mint secret
(shared with the API's HS256 verify secret), BFF user directory, full OIDC block,
attestation key ring, and connector manifest signing secret.

### Docker secrets (production overlay)
`docker-compose.prod.yml` layers **Docker secrets** — each sensitive value is a
file mounted at `/run/secrets/<name>` and read via a new `*_FILE` convention, so
no secret ever appears in the environment (`docker inspect`), logs, or child
processes:

- engine: `read_secret()` resolves `X_FILE` over `X` (connector signing secret,
  attestation keys, OIDC HS256 secret; API keys already supported `*_FILE`).
- BFF: `readSecret()` (and a local `fileEnv` in the self-contained modules) does
  the same for the session secret, mint secret, API key, OIDC client secret, and
  user directory.

Run:
```
cp -r deploy/secrets.example deploy/secrets   # fill in real values (gitignored)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### boto3 installed
`boto3>=1.34` added to `requirements-engine.txt` — the live AWS
Organizations/IAM collector runs in the image (drop-in for the tested stub).

### Fonts vendored locally
The dashboard no longer fetches Google Fonts at build time (`next/font/google`
removed). The typeface resolves from a **local system font stack** on
`--font-geist-sans`, so the image builds fully offline / air-gapped and
reproducibly. To pin an exact bundled face, drop woff2 files into
`src/app/fonts/` and switch to `next/font/local` — the CSS variable is unchanged.

### Readiness probe
`GET /readyz` (and `/api/readyz`, and open through the BFF at `/bff/api/readyz`)
returns **200 only when the service can do work** — report store writable, job DB
directory present, and (in production) no outstanding fail-closed preflight
issues — else **503** with the specific reasons. `GET /api/health` stays a cheap
liveness check. Health + readiness are the only unauthenticated endpoints.

### Full-stack smoke test
`deploy/smoke-test.sh` drives the running stack through the browser-facing BFF
exactly as a user would and asserts the whole pipeline:

```
health → readiness → login (session) → register + collect a connector →
unified posture run (verified report) → export + NIST-schema-validate OSCAL
```

`BASE_URL=http://localhost:8088 ./smoke-test.sh` (nginx port), or point it at a
dev server. **Verified live** against the local stack — all six steps pass.

## Also fixed here
- OSCAL: a clean assessment (no at-risk controls) now emits an AR result with the
  `observations`/`findings` arrays omitted (OSCAL forbids empty arrays) rather
  than an invalid empty export — so the smoke test's OSCAL step passes on a clean
  run too.

## Honest remaining scope
- The smoke test is not wired into CI (it needs the full stack running); it's a
  one-command post-deploy gate, documented in the RUNBOOK.
- Exact-Inter typeface requires dropping the licensed woff2 into the repo (kept
  out to avoid bundling a font binary without an explicit decision).
