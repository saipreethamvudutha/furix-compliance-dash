// Server-side user directory for dev credential login (Wave-N #1).
//
// This replaces the old localStorage demo auth: credentials are validated on
// the SERVER and never shipped to the client. In production this is replaced by
// the OIDC authorization-code/PKCE flow (see auth routes) — the session shape
// is identical, so the rest of the app doesn't change.
//
// Passwords are compared against SHA-256 hashes; configure real users via
// FURIX_BFF_USERS (JSON: [{email, passHash, role, tenant}]).

import crypto from "node:crypto";
import { isProd } from "./env";

export type BffUser = { email: string; passHash: string; role: string; tenant: string };

function sha256(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex");
}

// Default dev users (dev only — override with FURIX_BFF_USERS in prod). The
// hashes below are sha256 of the demo passwords.
const DEFAULT_USERS: BffUser[] = [
  { email: "admin@byoc.com", passHash: sha256("admin123"), role: "admin", tenant: "default" },
  { email: "analyst@byoc.com", passHash: sha256("analyst123"), role: "analyst", tenant: "default" },
  { email: "auditor@byoc.com", passHash: sha256("auditor123"), role: "auditor", tenant: "default" },
  { email: "mssp@byoc.com", passHash: sha256("mssp123"), role: "mssp", tenant: "default" },
];

function users(): BffUser[] {
  const raw = process.env.FURIX_BFF_USERS;
  if (raw) {
    try {
      return JSON.parse(raw) as BffUser[];
    } catch {
      // In production a malformed directory must NOT silently fall back to the
      // built-in demo users — it fails closed (no users → no logins).
      if (isProd()) return [];
    }
  }
  // Default demo users are dev-only. In production the directory is empty unless
  // FURIX_BFF_USERS (or OIDC) is configured — no well-known credentials ship.
  return isProd() ? [] : DEFAULT_USERS;
}

export function authenticateUser(email: string, password: string): BffUser | null {
  const want = sha256(password);
  const user = users().find((u) => u.email.toLowerCase() === email.trim().toLowerCase());
  if (!user) return null;
  // constant-time compare
  const a = Buffer.from(user.passHash);
  const b = Buffer.from(want);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return user;
}
