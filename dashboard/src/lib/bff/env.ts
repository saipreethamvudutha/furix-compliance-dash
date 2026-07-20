// Fail-closed production readiness for the BFF (Wave-F).
//
// The BFF holds the only server-side credentials the browser must never see.
// In production a WEAK configuration must refuse to serve rather than silently
// falling back to dev secrets, default users, or a shared static key. This
// module centralises "are we production?" and "is the BFF safely configured?"
// so the proxy can return 503 instead of proxying with insecure defaults.

import fs from "node:fs";

export type Env = Record<string, string | undefined>;

export function isProd(env: Env = process.env): boolean {
  return env.NODE_ENV === "production" || env.FURIX_ENV === "production";
}

// Docker-secrets-friendly resolution: `X_FILE` (a mounted secret file) wins over
// the inline `X`, so production injects secrets as files, not env vars that leak
// into `docker inspect` / logs / child processes.
export function readSecret(name: string, env: Env = process.env): string {
  const file = env[`${name}_FILE`];
  if (file) {
    try {
      return fs.readFileSync(file, "utf8").trim();
    } catch {
      return ""; // unreadable configured secret → fail-closed at the caller
    }
  }
  return env[name] ?? "";
}

// Returns the list of production misconfigurations. In development it is always
// ready (empty issues) — the dev conveniences (default users, dev session
// secret, static key) are allowed ONLY outside production.
export function prodReadiness(env: Env = process.env): { ok: boolean; issues: string[] } {
  const issues: string[] = [];
  if (!isProd(env)) return { ok: true, issues };

  // Resolve via readSecret so Docker-secret files (X_FILE) count — otherwise a
  // production stack that injects secrets as files would report everything
  // missing and 503 forever (Wave-J).
  const secret = readSecret("FURIX_SESSION_SECRET", env);
  if (secret.length < 16) {
    issues.push("FURIX_SESSION_SECRET missing or too short (need a 16+ char random value)");
  }
  if (!readSecret("FURIX_BFF_MINT_SECRET", env)) {
    issues.push(
      "FURIX_BFF_MINT_SECRET missing — per-user API token minting is mandatory in production " +
        "(the shared static API key is not used as a fallback)",
    );
  }
  const hasUsers = !!readSecret("FURIX_BFF_USERS", env);
  const hasOidc = !!(env.FURIX_OIDC_ISSUER || env.FURIX_OIDC_CLIENT_ID);
  if (!hasUsers && !hasOidc) {
    issues.push(
      "no identity source: set FURIX_BFF_USERS or FURIX_OIDC_* — built-in default users are " +
        "disabled in production",
    );
  }
  return { ok: issues.length === 0, issues };
}
