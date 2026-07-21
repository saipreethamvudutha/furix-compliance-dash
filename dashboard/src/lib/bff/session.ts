// Server-side session (Wave-N #1). Encrypted, authenticated, HTTP-only session
// cookies — the browser never sees a bearer credential OR a readable identity;
// it holds an opaque AES-256-GCM sealed token that only the server can open.
//
// Runs only on the server (imported by BFF route handlers). Uses Node crypto;
// no external dependency.

import crypto from "node:crypto";
import { isProd, readSecret } from "./env";

const COOKIE_NAME = "furix_session";
const CSRF_COOKIE = "furix_csrf";
const TTL_SECONDS = 60 * 60 * 8; // 8h

export type SessionData = {
  sub: string; // user id / email
  role: string; // admin | analyst | auditor | mssp
  tenant: string;
  csrf: string;
  sid: string; // unique session id (for server-side revocation)
  iat: number;
  exp: number;
};

// Server-only secret. In production this MUST be set — no dev fallback. A
// missing secret in production throws (fail-closed) rather than sealing sessions
// with a well-known key anyone could forge.
function secretKey(): Buffer {
  const s = readSecret("FURIX_SESSION_SECRET");
  if (!s) {
    if (isProd()) {
      throw new Error("FURIX_SESSION_SECRET is required in production (fail-closed)");
    }
    return crypto.createHash("sha256").update("dev-session-secret-change-me-in-prod").digest();
  }
  return crypto.createHash("sha256").update(s).digest(); // 32 bytes for AES-256
}

export function newCsrfToken(): string {
  return crypto.randomBytes(24).toString("base64url");
}

// Generic AES-256-GCM seal/open over the server session key. Used for the
// session cookie AND the short-lived OIDC transaction cookie (PKCE verifier +
// state + nonce), so there is a single audited crypto implementation.
export function sealPayload(obj: unknown): string {
  const plaintext = Buffer.from(JSON.stringify(obj), "utf8");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", secretKey(), iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, ct, tag].map((b) => b.toString("base64url")).join(".");
}

export function openPayload<T>(token: string | undefined): T | null {
  if (!token) return null;
  try {
    const [ivB, ctB, tagB] = token.split(".");
    if (!ivB || !ctB || !tagB) return null;
    const decipher = crypto.createDecipheriv("aes-256-gcm", secretKey(), Buffer.from(ivB, "base64url"));
    decipher.setAuthTag(Buffer.from(tagB, "base64url"));
    const pt = Buffer.concat([decipher.update(Buffer.from(ctB, "base64url")), decipher.final()]);
    return JSON.parse(pt.toString("utf8")) as T;
  } catch {
    return null; // tampered / bad key / malformed
  }
}

export function newSessionId(): string {
  return crypto.randomBytes(18).toString("base64url");
}

export function sealSession(
  data: Omit<SessionData, "iat" | "exp" | "csrf" | "sid"> & { csrf: string; sid?: string },
): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: SessionData = {
    ...data,
    sid: data.sid ?? newSessionId(),
    iat: now,
    exp: now + TTL_SECONDS,
  };
  return sealPayload(payload);
}

export function openSession(token: string | undefined): SessionData | null {
  const data = openPayload<SessionData>(token);
  if (!data) return null;
  if (data.exp < Math.floor(Date.now() / 1000)) return null; // expired
  return data;
}

// ── cookie helpers ────────────────────────────────────────────────────────────
export function sessionCookie(token: string): string {
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${TTL_SECONDS}${
    isSecure() ? "; Secure" : ""
  }`;
}

// CSRF cookie is readable by JS (double-submit pattern): the client echoes it
// back in the X-CSRF-Token header on state-changing requests.
export function csrfCookie(csrf: string): string {
  return `${CSRF_COOKIE}=${csrf}; Path=/; SameSite=Lax; Max-Age=${TTL_SECONDS}${
    isSecure() ? "; Secure" : ""
  }`;
}

export function clearCookies(): string[] {
  const expired = `Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
  return [`${COOKIE_NAME}=; ${expired}`, `${CSRF_COOKIE}=; Path=/; SameSite=Lax; Max-Age=0`];
}

export function readSessionCookie(cookieHeader: string | null): string | undefined {
  return readCookie(cookieHeader, COOKIE_NAME);
}
export function readCsrfCookie(cookieHeader: string | null): string | undefined {
  return readCookie(cookieHeader, CSRF_COOKIE);
}

function readCookie(cookieHeader: string | null, name: string): string | undefined {
  if (!cookieHeader) return undefined;
  for (const part of cookieHeader.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return undefined;
}

function isSecure(): boolean {
  // Explicit FURIX_COOKIE_SECURE wins (so an http deployment behind a plain
  // reverse proxy can force non-Secure with FURIX_COOKIE_SECURE=0 even though
  // `next start` sets NODE_ENV=production); otherwise default from NODE_ENV.
  const explicit = process.env.FURIX_COOKIE_SECURE;
  if (explicit === "0" || explicit === "false") return false;
  if (explicit === "1" || explicit === "true") return true;
  return process.env.NODE_ENV === "production";
}

export const SESSION = { COOKIE_NAME, CSRF_COOKIE, TTL_SECONDS };
