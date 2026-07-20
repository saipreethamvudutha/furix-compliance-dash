// Per-user API token minting (Wave-N #1). When FURIX_BFF_MINT_SECRET is set to
// the API's FURIX_OIDC_HS256_SECRET, the BFF mints a short-lived HS256 JWT
// carrying the SESSION user's identity, so the API authenticates and tenant-
// scopes per user (and logs the real actor) instead of a shared admin key.
// Without the secret it falls back to the static FURIX_API_KEY.

import crypto from "node:crypto";
import type { SessionData } from "./session";

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString("base64url");
}

export function mintUserToken(session: SessionData): string | null {
  const secret = process.env.FURIX_BFF_MINT_SECRET;
  if (!secret) return null;
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(
    JSON.stringify({
      iss: process.env.FURIX_OIDC_ISSUER ?? "furix-bff",
      aud: process.env.FURIX_OIDC_AUDIENCE ?? "furix",
      sub: session.sub,
      tenant: session.tenant,
      role: session.role,
      iat: now,
      exp: now + 120, // short-lived; minted per request
    }),
  );
  const signingInput = `${header}.${payload}`;
  const sig = crypto.createHmac("sha256", secret).update(signingInput).digest("base64url");
  return `${signingInput}.${sig}`;
}

// Coarse server-side RBAC at the BFF (defense in depth; the API enforces the
// fine-grained scopes). Maps an HTTP method + API path to the minimum role.
export function bffAllows(role: string, method: string, apiPath: string): boolean {
  const isWrite = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
  const p = apiPath.replace(/^\/?api\//, "");
  if (p.startsWith("health")) return true;
  // export-only surfaces require the auditor's export scope OR admin
  if (p.startsWith("oscal") || p.startsWith("audit/")) {
    return ["admin", "auditor"].includes(role);
  }
  if (isWrite) {
    // ingest / findings mutations require an ingest-capable role
    return ["admin", "analyst", "mssp", "service"].includes(role);
  }
  // any authenticated role may read
  return true;
}
