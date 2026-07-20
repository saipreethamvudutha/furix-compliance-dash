// Real OIDC authorization-code + PKCE (Wave-G). Discovery-driven, so it works
// against any spec-compliant IdP (Keycloak, Auth0, Entra, Okta, Google): we read
// the provider's `.well-known/openid-configuration`, run the authorization-code
// flow with PKCE (S256), exchange the code at the token endpoint, and verify the
// ID token's RS256 signature against the provider's JWKS — all with Node's
// built-in crypto, no external dependency.
//
// The browser only ever holds the same opaque sealed session cookie as dev
// login; this module just produces the {sub, role, tenant} the session needs.

import crypto from "node:crypto";
import fs from "node:fs";

export type Fetch = typeof fetch;

// All IdP calls get a bounded timeout so a hung/slow provider can't stall the
// request indefinitely (deployment/trust hardening).
const DEFAULT_TIMEOUT_MS = 5000;

async function fetchWithTimeout(
  fetchImpl: Fetch,
  url: string,
  init: RequestInit = {},
  ms = DEFAULT_TIMEOUT_MS,
): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetchImpl(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// Open-redirect defence: only same-origin relative paths are allowed as the
// post-login destination. Rejects absolute URLs and protocol-relative "//host".
export function safeReturnTo(returnTo: string | undefined | null): string {
  if (!returnTo) return "/";
  if (!returnTo.startsWith("/") || returnTo.startsWith("//") || returnTo.startsWith("/\\")) {
    return "/";
  }
  return returnTo;
}

// Docker-secrets-friendly resolution (kept local so this module stays free of
// relative imports and runs under Node's type-stripping test loader).
function fileEnv(env: NodeJS.ProcessEnv, name: string): string {
  const p = env[`${name}_FILE`];
  if (p) {
    try {
      return fs.readFileSync(p, "utf8").trim();
    } catch {
      return "";
    }
  }
  return env[name] ?? "";
}

// Self-contained AES-256-GCM seal/open over the server session key. Kept local
// (not imported from ./session) so this security-critical module has zero
// relative imports and can run under Node's type-stripping test runner. The key
// derivation matches session.ts exactly (same secret → interchangeable).
function secretKey(): Buffer {
  const s = fileEnv(process.env, "FURIX_SESSION_SECRET");
  if (!s) {
    if (process.env.NODE_ENV === "production" || process.env.FURIX_ENV === "production") {
      throw new Error("FURIX_SESSION_SECRET is required in production (fail-closed)");
    }
    return crypto.createHash("sha256").update("dev-session-secret-change-me-in-prod").digest();
  }
  return crypto.createHash("sha256").update(s).digest();
}

function sealPayload(obj: unknown): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", secretKey(), iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(obj), "utf8")), cipher.final()]);
  return [iv, ct, cipher.getAuthTag()].map((b) => b.toString("base64url")).join(".");
}

function openPayload<T>(token: string | undefined): T | null {
  if (!token) return null;
  try {
    const [ivB, ctB, tagB] = token.split(".");
    if (!ivB || !ctB || !tagB) return null;
    const d = crypto.createDecipheriv("aes-256-gcm", secretKey(), Buffer.from(ivB, "base64url"));
    d.setAuthTag(Buffer.from(tagB, "base64url"));
    const pt = Buffer.concat([d.update(Buffer.from(ctB, "base64url")), d.final()]);
    return JSON.parse(pt.toString("utf8")) as T;
  } catch {
    return null;
  }
}

export type OidcConfig = {
  issuer: string;
  clientId: string;
  clientSecret?: string; // omit for public clients (PKCE only)
  redirectUri: string;
  scope: string;
  roleClaim: string;
  tenantClaim: string;
  defaultRole: string;
  defaultTenant: string;
};

export type Discovery = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
};

export type OidcTx = { state: string; nonce: string; codeVerifier: string; returnTo: string };

export function oidcConfigFromEnv(env: NodeJS.ProcessEnv = process.env): OidcConfig | null {
  const issuer = env.FURIX_OIDC_ISSUER;
  const clientId = env.FURIX_OIDC_CLIENT_ID;
  const redirectUri = env.FURIX_OIDC_REDIRECT_URI;
  if (!issuer || !clientId || !redirectUri) return null;
  return {
    issuer: issuer.replace(/\/$/, ""),
    clientId,
    clientSecret: fileEnv(env, "FURIX_OIDC_CLIENT_SECRET") || undefined,
    redirectUri,
    scope: env.FURIX_OIDC_SCOPE || "openid profile email",
    roleClaim: env.FURIX_OIDC_ROLE_CLAIM || "role",
    tenantClaim: env.FURIX_OIDC_TENANT_CLAIM || "tenant",
    // Least-privilege defaults when the IdP does not assert a role/tenant.
    defaultRole: env.FURIX_OIDC_DEFAULT_ROLE || "auditor",
    defaultTenant: env.FURIX_OIDC_DEFAULT_TENANT || "default",
  };
}

// ── PKCE ──────────────────────────────────────────────────────────────────────
export function randomUrlToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function pkceChallenge(verifier: string): string {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

// ── discovery (cached) ────────────────────────────────────────────────────────
const _discoveryCache = new Map<string, { at: number; doc: Discovery }>();
const DISCOVERY_TTL_MS = 5 * 60 * 1000;

export async function discover(
  issuer: string,
  fetchImpl: Fetch = fetch,
  now: number = Date.now(),
): Promise<Discovery> {
  const base = issuer.replace(/\/$/, "");
  const cached = _discoveryCache.get(base);
  if (cached && now - cached.at < DISCOVERY_TTL_MS) return cached.doc;
  const url = `${base}/.well-known/openid-configuration`;
  const res = await fetchWithTimeout(fetchImpl, url);
  if (!res.ok) throw new Error(`OIDC discovery failed (${res.status}) at ${url}`);
  const doc = (await res.json()) as Discovery;
  for (const k of ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"] as const) {
    if (!doc[k]) throw new Error(`OIDC discovery document missing ${k}`);
  }
  // The discovered issuer MUST match what we asked for (mix-up defence).
  if (doc.issuer.replace(/\/$/, "") !== base) {
    throw new Error(`OIDC issuer mismatch: expected ${base}, got ${doc.issuer}`);
  }
  _discoveryCache.set(base, { at: now, doc });
  return doc;
}

// ── authorize URL ─────────────────────────────────────────────────────────────
export function buildAuthorizeUrl(
  disc: Discovery,
  cfg: OidcConfig,
  tx: { state: string; nonce: string; codeChallenge: string },
): string {
  const u = new URL(disc.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", cfg.clientId);
  u.searchParams.set("redirect_uri", cfg.redirectUri);
  u.searchParams.set("scope", cfg.scope);
  u.searchParams.set("state", tx.state);
  u.searchParams.set("nonce", tx.nonce);
  u.searchParams.set("code_challenge", tx.codeChallenge);
  u.searchParams.set("code_challenge_method", "S256");
  return u.toString();
}

// ── token exchange ────────────────────────────────────────────────────────────
export type TokenResponse = { id_token: string; access_token?: string; token_type?: string };

export async function exchangeCode(
  disc: Discovery,
  cfg: OidcConfig,
  code: string,
  codeVerifier: string,
  fetchImpl: Fetch = fetch,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: cfg.redirectUri,
    client_id: cfg.clientId,
    code_verifier: codeVerifier,
  });
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  // Confidential client: HTTP Basic auth per RFC 6749.
  if (cfg.clientSecret) {
    headers.authorization =
      "Basic " + Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString("base64");
  }
  const res = await fetchWithTimeout(fetchImpl, disc.token_endpoint,
    { method: "POST", headers, body: body.toString() });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`OIDC token exchange failed (${res.status}): ${text.slice(0, 200)}`);
  }
  const json = (await res.json()) as TokenResponse;
  if (!json.id_token) throw new Error("OIDC token response had no id_token");
  return json;
}

// ── JWKS + ID token verification (RS256) ──────────────────────────────────────
type Jwk = { kty: string; kid?: string; alg?: string; use?: string; n?: string; e?: string };

export async function fetchJwks(jwksUri: string, fetchImpl: Fetch = fetch): Promise<Jwk[]> {
  const res = await fetchWithTimeout(fetchImpl, jwksUri);
  if (!res.ok) throw new Error(`JWKS fetch failed (${res.status})`);
  const doc = (await res.json()) as { keys?: Jwk[] };
  return doc.keys ?? [];
}

function b64urlJson(seg: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(seg, "base64url").toString("utf8"));
}

export type IdClaims = {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat?: number;
  nonce?: string;
  [k: string]: unknown;
};

export function verifyIdToken(
  idToken: string,
  opts: { jwks: Jwk[]; issuer: string; audience: string; nonce: string; now?: number; leeway?: number },
): IdClaims {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("id_token is not a JWT");
  const [h, p, s] = parts;
  const header = b64urlJson(h) as { alg?: string; kid?: string };
  const claims = b64urlJson(p) as IdClaims;

  if (header.alg !== "RS256") throw new Error(`unsupported id_token alg: ${header.alg}`);
  // pick the signing key by kid (or the only RSA key)
  const rsaKeys = opts.jwks.filter((k) => k.kty === "RSA");
  const jwk = header.kid ? rsaKeys.find((k) => k.kid === header.kid) : rsaKeys[0];
  if (!jwk) throw new Error("no matching JWKS key for id_token");

  const key = crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: "jwk" });
  const ok = crypto.verify(
    "RSA-SHA256",
    Buffer.from(`${h}.${p}`),
    key,
    Buffer.from(s, "base64url"),
  );
  if (!ok) throw new Error("id_token signature invalid");

  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const leeway = opts.leeway ?? 60;
  if (claims.iss.replace(/\/$/, "") !== opts.issuer.replace(/\/$/, "")) {
    throw new Error("id_token issuer mismatch");
  }
  const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!auds.includes(opts.audience)) throw new Error("id_token audience mismatch");
  if (typeof claims.exp !== "number" || now > claims.exp + leeway) throw new Error("id_token expired");
  if (typeof claims.iat === "number" && claims.iat > now + leeway) {
    throw new Error("id_token issued in the future (clock skew or forgery)");
  }
  if (claims.nonce !== opts.nonce) throw new Error("id_token nonce mismatch (possible replay)");
  return claims;
}

// ── claim mapping (fail-closed to least privilege) ────────────────────────────
export function claimsToSession(
  claims: IdClaims,
  cfg: OidcConfig,
): { sub: string; role: string; tenant: string } {
  const roleRaw = claims[cfg.roleClaim];
  const role = typeof roleRaw === "string" && roleRaw ? roleRaw : cfg.defaultRole;
  const tenantRaw = claims[cfg.tenantClaim];
  const tenant = typeof tenantRaw === "string" && tenantRaw ? tenantRaw : cfg.defaultTenant;
  // Use email as the subject only when the IdP asserts it is verified — an
  // unverified email must not become an identity (account-takeover defence).
  const emailOk = typeof claims.email === "string" && claims.email && claims.email_verified !== false;
  const sub = emailOk ? (claims.email as string) : claims.sub;
  return { sub, role, tenant };
}

// ── transaction cookie (PKCE verifier + state + nonce), sealed + short-lived ────
const TX_COOKIE = "furix_oidc_tx";
const TX_TTL = 600; // 10 minutes

export function sealTx(tx: OidcTx): string {
  return sealPayload(tx);
}
export function openTx(token: string | undefined): OidcTx | null {
  return openPayload<OidcTx>(token);
}
export function txCookie(sealed: string, secure: boolean): string {
  return `${TX_COOKIE}=${sealed}; Path=/bff/auth; HttpOnly; SameSite=Lax; Max-Age=${TX_TTL}${
    secure ? "; Secure" : ""
  }`;
}
export function clearTxCookie(): string {
  return `${TX_COOKIE}=; Path=/bff/auth; HttpOnly; SameSite=Lax; Max-Age=0`;
}
export function readTxCookie(cookieHeader: string | null): string | undefined {
  if (!cookieHeader) return undefined;
  for (const part of cookieHeader.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === TX_COOKIE) return v.join("=");
  }
  return undefined;
}

export const OIDC = { TX_COOKIE, TX_TTL };
