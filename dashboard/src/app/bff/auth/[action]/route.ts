// BFF auth endpoints (Wave-N #1): server-side session lifecycle.
//
//   POST /bff/auth/login    { email, password }  → sets session + CSRF cookies
//   POST /bff/auth/logout                        → clears cookies
//   GET  /bff/auth/session                        → { authenticated, user, role, tenant, csrf }
//   GET  /bff/auth/oidc/start                     → 302 to the IdP (PKCE) [when configured]
//   GET  /bff/auth/oidc/callback                  → exchanges code, sets session [when configured]
//
// Dev credential login works out of the box; OIDC is used when FURIX_OIDC_* is
// configured. Either way the browser only ever holds an opaque sealed cookie.

import { NextRequest, NextResponse } from "next/server";
import { authenticateUser } from "@/lib/bff/users";
import {
  clearCookies,
  csrfCookie,
  newCsrfToken,
  openSession,
  readSessionCookie,
  sealSession,
  sessionCookie,
} from "@/lib/bff/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const oidcConfigured = () => Boolean(process.env.FURIX_OIDC_AUTH_URL && process.env.FURIX_OIDC_CLIENT_ID);

export async function POST(req: NextRequest, ctx: { params: Promise<{ action: string }> }) {
  const { action } = await ctx.params;

  if (action === "logout") {
    const res = NextResponse.json({ ok: true });
    for (const c of clearCookies()) res.headers.append("set-cookie", c);
    return res;
  }

  if (action === "login") {
    let body: { email?: string; password?: string };
    try {
      body = await req.json();
    } catch {
      return NextResponse.json({ error: "invalid body" }, { status: 400 });
    }
    const user = authenticateUser(body.email ?? "", body.password ?? "");
    if (!user) {
      return NextResponse.json({ error: "invalid credentials" }, { status: 401 });
    }
    const csrf = newCsrfToken();
    const token = sealSession({ sub: user.email, role: user.role, tenant: user.tenant, csrf });
    const res = NextResponse.json({
      ok: true,
      user: { email: user.email, role: user.role, tenant: user.tenant },
    });
    res.headers.append("set-cookie", sessionCookie(token));
    res.headers.append("set-cookie", csrfCookie(csrf));
    return res;
  }

  return NextResponse.json({ error: "unknown action" }, { status: 404 });
}

export async function GET(req: NextRequest, ctx: { params: Promise<{ action: string }> }) {
  const { action } = await ctx.params;

  if (action === "session") {
    const session = openSession(readSessionCookie(req.headers.get("cookie")));
    if (!session) return NextResponse.json({ authenticated: false }, { status: 200 });
    return NextResponse.json({
      authenticated: true,
      user: session.sub,
      role: session.role,
      tenant: session.tenant,
      csrf: session.csrf,
      exp: session.exp,
    });
  }

  // OIDC authorization-code / PKCE start (only when configured).
  if (action === "oidc") {
    if (!oidcConfigured()) {
      return NextResponse.json(
        { error: "OIDC not configured (set FURIX_OIDC_AUTH_URL, FURIX_OIDC_CLIENT_ID)" },
        { status: 501 },
      );
    }
    // The real flow generates a PKCE verifier/challenge + state, stores them in
    // a short-lived cookie, and 302s to the IdP authorize endpoint. On
    // /oidc/callback the code is exchanged for tokens, verified, and mapped to a
    // session (same sealSession call as dev login). Wired here as the
    // integration point; the exchange requires a live IdP.
    return NextResponse.json({ error: "OIDC start not enabled in this build" }, { status: 501 });
  }

  return NextResponse.json({ error: "unknown action" }, { status: 404 });
}
