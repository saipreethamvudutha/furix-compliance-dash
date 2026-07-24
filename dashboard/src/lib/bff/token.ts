// Per-user API token minting (Wave-N #1). When FURIX_BFF_MINT_SECRET is set to
// the API's FURIX_OIDC_HS256_SECRET, the BFF mints a short-lived HS256 JWT
// carrying the SESSION user's identity, so the API authenticates and tenant-
// scopes per user (and logs the real actor) instead of a shared admin key.
// Without the secret it falls back to the static FURIX_API_KEY.

import crypto from "node:crypto";
import fs from "node:fs";
import type { SessionData } from "./session";

// Docker-secrets-friendly resolution (kept local so this module stays free of
// relative value imports and runs under Node's type-stripping test loader).
function fileEnv(name: string): string {
  const p = process.env[`${name}_FILE`];
  if (p) {
    try {
      return fs.readFileSync(p, "utf8").trim();
    } catch {
      return "";
    }
  }
  return process.env[name] ?? "";
}

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString("base64url");
}

export function mintUserToken(session: SessionData): string | null {
  const secret = fileEnv("FURIX_BFF_MINT_SECRET");
  if (!secret) return null;
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(
    JSON.stringify({
      // `||` not `??`: docker-compose passes FURIX_OIDC_ISSUER as an EMPTY
      // string (`${FURIX_OIDC_ISSUER:-}`), which `??` would NOT replace — the
      // token would carry iss:"" and the API would reject it ("issuer
      // mismatch"). Fall back to the API's expected default for empty too.
      iss: process.env.FURIX_OIDC_ISSUER || "furix-bff",
      aud: process.env.FURIX_OIDC_AUDIENCE || "furix",
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
  // legal hold: placing (POST) is an auditor/admin authority act; releasing
  // (DELETE) is admin-only — it re-enables retention expiry/purge.
  if (p.includes("/legal-hold")) {
    if (method === "DELETE") return role === "admin";
    return ["admin", "auditor"].includes(role);
  }
  // export-only surfaces require the auditor's export scope OR admin
  if (p.startsWith("oscal") || p.startsWith("audit/") || p.startsWith("evidence-access")) {
    return ["admin", "auditor"].includes(role);
  }
  if (isWrite) {
    // ingest / findings mutations require an ingest-capable role
    return ["admin", "analyst", "mssp", "service"].includes(role);
  }
  // any authenticated role may read
  return true;
}
