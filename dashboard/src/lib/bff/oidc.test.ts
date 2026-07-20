// OIDC authorization-code + PKCE tests (Wave-G) against a deterministic mock
// IdP: a real RSA keypair, a real JWKS, a real RS256-signed id_token — verified
// by the same Node-crypto path the BFF uses in production. No network.
//
//     node --test src/lib/bff/oidc.test.ts

import { test } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";

import {
  buildAuthorizeUrl,
  claimsToSession,
  discover,
  exchangeCode,
  fetchJwks,
  oidcConfigFromEnv,
  openTx,
  pkceChallenge,
  randomUrlToken,
  sealTx,
  verifyIdToken,
} from "./oidc.ts";

// ── mock IdP key material ─────────────────────────────────────────────────────
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...(publicKey.export({ format: "jwk" }) as Record<string, unknown>), kid: "test-key", alg: "RS256", use: "sig" };
const JWKS = [jwk];
const ISSUER = "https://idp.example.com";

function b64url(o: unknown): string {
  return Buffer.from(JSON.stringify(o)).toString("base64url");
}
function mintIdToken(claims: Record<string, unknown>, kid = "test-key"): string {
  const h = b64url({ alg: "RS256", typ: "JWT", kid });
  const p = b64url(claims);
  const sig = crypto.sign("RSA-SHA256", Buffer.from(`${h}.${p}`), privateKey).toString("base64url");
  return `${h}.${p}.${sig}`;
}
function baseClaims(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: ISSUER,
    sub: "user-123",
    aud: "furix-client",
    exp: 4102444800, // year 2100
    nonce: "the-nonce",
    email: "alice@example.com",
    ...over,
  };
}

const CFG = {
  issuer: ISSUER,
  clientId: "furix-client",
  redirectUri: "https://app.furix.local/bff/auth/oidc/callback",
  scope: "openid profile email",
  roleClaim: "role",
  tenantClaim: "tenant",
  defaultRole: "auditor",
  defaultTenant: "default",
};

// mock fetch that serves discovery, jwks, and the token endpoint
function mockFetch(opts: { capture?: (body: URLSearchParams) => void; idToken?: string } = {}): typeof fetch {
  return (async (url: string | URL, init?: RequestInit) => {
    const u = url.toString();
    if (u.endsWith("/.well-known/openid-configuration")) {
      return {
        ok: true,
        json: async () => ({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/jwks`,
        }),
      };
    }
    if (u === `${ISSUER}/jwks`) {
      return { ok: true, json: async () => ({ keys: JWKS }) };
    }
    if (u === `${ISSUER}/token`) {
      const body = new URLSearchParams(String(init?.body ?? ""));
      opts.capture?.(body);
      return { ok: true, json: async () => ({ id_token: opts.idToken ?? mintIdToken(baseClaims()), token_type: "Bearer" }) };
    }
    return { ok: false, status: 404, text: async () => "not found", json: async () => ({}) };
  }) as unknown as typeof fetch;
}

// ── PKCE (RFC 7636 Appendix B test vector) ────────────────────────────────────
test("pkce S256 challenge matches the RFC 7636 test vector", () => {
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  assert.equal(pkceChallenge(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
});

test("randomUrlToken is url-safe and unique", () => {
  const a = randomUrlToken();
  const b = randomUrlToken();
  assert.notEqual(a, b);
  assert.match(a, /^[A-Za-z0-9_-]+$/);
});

// ── discovery ─────────────────────────────────────────────────────────────────
test("discover reads the well-known document and validates the issuer", async () => {
  const disc = await discover(ISSUER, mockFetch(), 1);
  assert.equal(disc.token_endpoint, `${ISSUER}/token`);
  assert.equal(disc.jwks_uri, `${ISSUER}/jwks`);
});

test("discover rejects an issuer mismatch (mix-up defence)", async () => {
  const bad = (async () => ({
    ok: true,
    json: async () => ({
      issuer: "https://evil.example",
      authorization_endpoint: "x",
      token_endpoint: "y",
      jwks_uri: "z",
    }),
  })) as unknown as typeof fetch;
  await assert.rejects(() => discover(ISSUER, bad, 999999), /issuer mismatch/);
});

// ── authorize URL ─────────────────────────────────────────────────────────────
test("buildAuthorizeUrl carries PKCE S256, state and nonce", () => {
  const url = new URL(
    buildAuthorizeUrl(
      { issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: "", jwks_uri: "" },
      CFG,
      { state: "st", nonce: "no", codeChallenge: "cc" },
    ),
  );
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.get("code_challenge"), "cc");
  assert.equal(url.searchParams.get("state"), "st");
  assert.equal(url.searchParams.get("nonce"), "no");
  assert.equal(url.searchParams.get("client_id"), "furix-client");
});

// ── token exchange sends the PKCE verifier ────────────────────────────────────
test("exchangeCode posts the authorization code and PKCE verifier", async () => {
  let captured: URLSearchParams | null = null;
  const disc = await discover(ISSUER, mockFetch(), 2);
  const tokens = await exchangeCode(disc, CFG, "auth-code", "verifier-xyz", mockFetch({ capture: (b) => (captured = b) }));
  assert.ok(tokens.id_token);
  assert.equal(captured!.get("grant_type"), "authorization_code");
  assert.equal(captured!.get("code"), "auth-code");
  assert.equal(captured!.get("code_verifier"), "verifier-xyz");
});

// ── id_token verification ─────────────────────────────────────────────────────
test("verifyIdToken accepts a correctly signed token", () => {
  const claims = verifyIdToken(mintIdToken(baseClaims()), {
    jwks: JWKS,
    issuer: ISSUER,
    audience: "furix-client",
    nonce: "the-nonce",
  });
  assert.equal(claims.sub, "user-123");
  assert.equal(claims.email, "alice@example.com");
});

test("verifyIdToken rejects a bad nonce (replay defence)", () => {
  assert.throws(
    () => verifyIdToken(mintIdToken(baseClaims({ nonce: "wrong" })), { jwks: JWKS, issuer: ISSUER, audience: "furix-client", nonce: "the-nonce" }),
    /nonce mismatch/,
  );
});

test("verifyIdToken rejects a wrong audience", () => {
  assert.throws(
    () => verifyIdToken(mintIdToken(baseClaims({ aud: "someone-else" })), { jwks: JWKS, issuer: ISSUER, audience: "furix-client", nonce: "the-nonce" }),
    /audience mismatch/,
  );
});

test("verifyIdToken rejects an expired token", () => {
  assert.throws(
    () => verifyIdToken(mintIdToken(baseClaims({ exp: 1000 })), { jwks: JWKS, issuer: ISSUER, audience: "furix-client", nonce: "the-nonce", now: 5000 }),
    /expired/,
  );
});

test("verifyIdToken rejects a tampered signature", () => {
  const tok = mintIdToken(baseClaims());
  const parts = tok.split(".");
  const forged = `${parts[0]}.${b64url(baseClaims({ role: "admin" }))}.${parts[2]}`; // swap payload, keep sig
  assert.throws(
    () => verifyIdToken(forged, { jwks: JWKS, issuer: ISSUER, audience: "furix-client", nonce: "the-nonce" }),
    /signature invalid/,
  );
});

test("verifyIdToken rejects a token whose kid has no JWKS key", () => {
  assert.throws(
    () => verifyIdToken(mintIdToken(baseClaims(), "unknown-kid"), { jwks: JWKS, issuer: ISSUER, audience: "furix-client", nonce: "the-nonce" }),
    /no matching JWKS key/,
  );
});

// ── claim mapping (fail-closed to least privilege) ────────────────────────────
test("claimsToSession maps role/tenant claims and prefers email as subject", () => {
  const s = claimsToSession(baseClaims({ role: "analyst", tenant: "acme" }) as never, CFG);
  assert.deepEqual(s, { sub: "alice@example.com", role: "analyst", tenant: "acme" });
});

test("claimsToSession falls back to least-privilege defaults when claims are absent", () => {
  const s = claimsToSession({ iss: ISSUER, sub: "u", aud: "furix-client", exp: 4102444800 } as never, CFG);
  assert.equal(s.role, "auditor"); // NOT admin
  assert.equal(s.tenant, "default");
  assert.equal(s.sub, "u");
});

// ── full flow: exchange → verify → session claims ─────────────────────────────
test("end-to-end: discover, exchange, verify, map to a session identity", async () => {
  const f = mockFetch();
  const disc = await discover(ISSUER, f, 3);
  const tokens = await exchangeCode(disc, CFG, "code", "verifier", f);
  const jwks = await fetchJwks(disc.jwks_uri, f);
  const claims = verifyIdToken(tokens.id_token, { jwks, issuer: ISSUER, audience: "furix-client", nonce: "the-nonce" });
  const session = claimsToSession(claims, CFG);
  assert.equal(session.sub, "alice@example.com");
  assert.equal(session.role, "auditor"); // no role claim → least privilege
});

// ── transaction cookie roundtrip ──────────────────────────────────────────────
test("sealTx / openTx roundtrip the PKCE transaction", () => {
  const tx = { state: "s", nonce: "n", codeVerifier: "v", returnTo: "/reports" };
  const opened = openTx(sealTx(tx));
  assert.deepEqual(opened, tx);
});

test("openTx returns null on a tampered cookie", () => {
  assert.equal(openTx("garbage.value.here"), null);
});

// ── config gating ─────────────────────────────────────────────────────────────
test("oidcConfigFromEnv requires issuer, client id and redirect uri", () => {
  assert.equal(oidcConfigFromEnv({} as never), null);
  const cfg = oidcConfigFromEnv({
    FURIX_OIDC_ISSUER: "https://idp/",
    FURIX_OIDC_CLIENT_ID: "cid",
    FURIX_OIDC_REDIRECT_URI: "https://app/cb",
  } as never);
  assert.ok(cfg);
  assert.equal(cfg!.issuer, "https://idp"); // trailing slash stripped
  assert.equal(cfg!.defaultRole, "auditor");
});
