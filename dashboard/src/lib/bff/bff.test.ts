// BFF fail-closed + per-user authorization tests (Wave-F).
//
// Run with Node's built-in test runner (no extra deps):
//     node --test src/lib/bff/bff.test.ts
//
// Covers env.ts (production readiness — the fail-closed gate) and token.ts
// (per-user token minting + coarse RBAC). session.ts / users.ts are exercised
// end-to-end by the Python API integration tests and a live browser check;
// they are omitted here only because their value-import of ./env is not
// resolvable under Node's type-stripping loader (extensionless specifier).

import { test } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { isProd, prodReadiness, readSecret } from "./env.ts";
import { bffAllows, mintUserToken } from "./token.ts";

// ── env.ts: fail-closed production readiness ──────────────────────────────────
test("development is always ready (dev conveniences allowed)", () => {
  assert.equal(prodReadiness({}).ok, true);
  assert.equal(prodReadiness({ NODE_ENV: "development" }).ok, true);
});

test("isProd detects NODE_ENV and FURIX_ENV", () => {
  assert.equal(isProd({ NODE_ENV: "production" }), true);
  assert.equal(isProd({ FURIX_ENV: "production" }), true);
  assert.equal(isProd({}), false);
});

test("production with nothing configured fails closed with every issue", () => {
  const r = prodReadiness({ FURIX_ENV: "production" });
  assert.equal(r.ok, false);
  const joined = r.issues.join(" | ");
  assert.match(joined, /FURIX_SESSION_SECRET/);
  assert.match(joined, /FURIX_BFF_MINT_SECRET/);
  assert.match(joined, /identity source/);
});

test("production rejects a too-short session secret", () => {
  const r = prodReadiness({
    FURIX_ENV: "production",
    FURIX_SESSION_SECRET: "short",
    FURIX_BFF_MINT_SECRET: "m",
    FURIX_BFF_USERS: "[]",
  });
  assert.equal(r.ok, false);
  assert.match(r.issues.join(" "), /FURIX_SESSION_SECRET/);
});

test("production is ready with secrets + a user directory", () => {
  const r = prodReadiness({
    FURIX_ENV: "production",
    FURIX_SESSION_SECRET: "x".repeat(32),
    FURIX_BFF_MINT_SECRET: "mint-secret",
    FURIX_BFF_USERS: "[]",
  });
  assert.deepEqual(r, { ok: true, issues: [] });
});

test("production is ready when secrets are provided as Docker-secret FILES", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "furix-secretfiles-"));
  const sess = path.join(dir, "session");
  const mint = path.join(dir, "mint");
  const users = path.join(dir, "users");
  fs.writeFileSync(sess, "x".repeat(40) + "\n");
  fs.writeFileSync(mint, "mint-secret\n");
  fs.writeFileSync(users, "[]\n");
  try {
    const r = prodReadiness({
      FURIX_ENV: "production",
      FURIX_SESSION_SECRET_FILE: sess, // only the *_FILE variants set
      FURIX_BFF_MINT_SECRET_FILE: mint,
      FURIX_BFF_USERS_FILE: users,
    });
    assert.deepEqual(r, { ok: true, issues: [] }); // must be READY (was 503 before the fix)
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("production accepts OIDC as the identity source instead of a user list", () => {
  const r = prodReadiness({
    FURIX_ENV: "production",
    FURIX_SESSION_SECRET: "x".repeat(32),
    FURIX_BFF_MINT_SECRET: "mint-secret",
    FURIX_OIDC_ISSUER: "https://idp.example",
  });
  assert.equal(r.ok, true);
});

// ── token.ts: per-user token minting (fail-closed) ────────────────────────────
const SESSION = { sub: "analyst@acme", role: "analyst", tenant: "acme", csrf: "c", iat: 0, exp: 9 };

test("no mint secret → no per-user token (caller must fail closed)", () => {
  delete process.env.FURIX_BFF_MINT_SECRET;
  assert.equal(mintUserToken(SESSION), null);
});

test("mint secret set → a per-user HS256 token carrying the identity", () => {
  process.env.FURIX_BFF_MINT_SECRET = "mint-secret";
  const tok = mintUserToken(SESSION);
  delete process.env.FURIX_BFF_MINT_SECRET;
  assert.ok(tok, "expected a token");
  const parts = tok!.split(".");
  assert.equal(parts.length, 3, "JWT has header.payload.signature");
  const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  assert.equal(claims.sub, "analyst@acme");
  assert.equal(claims.tenant, "acme");
  assert.equal(claims.role, "analyst");
  assert.ok(claims.exp > claims.iat, "token is short-lived");
});

test("minted token has a non-empty issuer even when FURIX_OIDC_ISSUER='' (regression)", () => {
  // docker-compose passes FURIX_OIDC_ISSUER as an empty string; `??` would keep
  // iss:"" and the API rejects it ("issuer mismatch"). Must fall back to the
  // API's expected default so per-user calls (ingest/compliance/audit) work.
  process.env.FURIX_BFF_MINT_SECRET = "mint-secret";
  const prev = process.env.FURIX_OIDC_ISSUER;
  process.env.FURIX_OIDC_ISSUER = "";
  const tok = mintUserToken(SESSION)!;
  if (prev === undefined) delete process.env.FURIX_OIDC_ISSUER;
  else process.env.FURIX_OIDC_ISSUER = prev;
  delete process.env.FURIX_BFF_MINT_SECRET;
  const claims = JSON.parse(Buffer.from(tok.split(".")[1], "base64url").toString("utf8"));
  assert.equal(claims.iss, "furix-bff");
  assert.equal(claims.aud, "furix");
});

// ── token.ts: coarse per-user API authorization (RBAC) ────────────────────────
test("auditor may read and export but not ingest", () => {
  assert.equal(bffAllows("auditor", "GET", "api/summary"), true);
  assert.equal(bffAllows("auditor", "GET", "api/oscal"), true);
  assert.equal(bffAllows("auditor", "GET", "api/audit/export"), true);
  assert.equal(bffAllows("auditor", "POST", "api/ingest"), false);
});

test("analyst may ingest but not export", () => {
  assert.equal(bffAllows("analyst", "POST", "api/ingest"), true);
  assert.equal(bffAllows("analyst", "GET", "api/oscal"), false);
  assert.equal(bffAllows("analyst", "GET", "api/audit/export"), false);
});

test("admin may do everything; health is always open", () => {
  assert.equal(bffAllows("admin", "POST", "api/ingest"), true);
  assert.equal(bffAllows("admin", "GET", "api/oscal"), true);
  assert.equal(bffAllows("anyone", "GET", "api/health"), true);
});

test("attestation submission is a write (ingest-capable roles only)", () => {
  assert.equal(bffAllows("analyst", "POST", "api/attestations"), true);
  assert.equal(bffAllows("auditor", "POST", "api/attestations"), false);
});

test("evidence retrieval is a read — allowed for every authenticated role", () => {
  const sha = "a".repeat(64);
  for (const role of ["admin", "analyst", "auditor", "mssp", "readonly"]) {
    assert.equal(bffAllows(role, "GET", `api/evidence/${sha}`), true);
  }
});

test("legal hold: place is auditor/admin, release is admin-only", () => {
  const p = `api/evidence/${"b".repeat(64)}/legal-hold`;
  assert.equal(bffAllows("auditor", "POST", p), true);
  assert.equal(bffAllows("admin", "POST", p), true);
  assert.equal(bffAllows("analyst", "POST", p), false);
  assert.equal(bffAllows("mssp", "POST", p), false);
  assert.equal(bffAllows("admin", "DELETE", p), true);
  assert.equal(bffAllows("auditor", "DELETE", p), false);
  assert.equal(bffAllows("analyst", "DELETE", p), false);
});

// ── env.ts: Docker-secrets file resolution ────────────────────────────────────
test("readSecret prefers X_FILE over inline X and trims it", () => {
  const f = path.join(os.tmpdir(), `furix-secret-${process.pid}.txt`);
  fs.writeFileSync(f, "  file-value\n");
  try {
    assert.equal(readSecret("MY_SECRET", { MY_SECRET: "inline", MY_SECRET_FILE: f }), "file-value");
    assert.equal(readSecret("MY_SECRET", { MY_SECRET: "inline" }), "inline");
    assert.equal(readSecret("MY_SECRET", {}), "");
  } finally {
    fs.unlinkSync(f);
  }
});
