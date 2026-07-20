// BFF auth endpoints (Wave-N #1 + Wave-G OIDC): server-side session lifecycle.
//
//   POST /bff/auth/login    { email, password }  → sets session + CSRF cookies
//   POST /bff/auth/logout                        → clears cookies
//   GET  /bff/auth/session                        → { authenticated, user, role, tenant, csrf }
//   GET  /bff/auth/oidc/start                     → 302 to the IdP (authorization-code + PKCE)
//   GET  /bff/auth/oidc/callback                  → exchanges code, verifies id_token, sets session
//
// Dev credential login works out of the box; OIDC is used when FURIX_OIDC_* is
// configured. Either way the browser only ever holds an opaque sealed cookie.

import { NextRequest, NextResponse } from "next/server";
import { authenticateUser } from "@/lib/bff/users";
import {
  claimsToSession,
  buildAuthorizeUrl,
  clearTxCookie,
  discover,
  exchangeCode,
  fetchJwks,
  oidcConfigFromEnv,
  openTx,
  pkceChallenge,
  randomUrlToken,
  readTxCookie,
  sealTx,
  txCookie,
  verifyIdToken,
} from "@/lib/bff/oidc";
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

function isSecure(): boolean {
  return process.env.FURIX_COOKIE_SECURE === "1" || process.env.NODE_ENV === "production";
}

export async function POST(req: NextRequest, ctx: { params: Promise<{ action: string[] }> }) {
  const { action } = await ctx.params;
  const head = action[0];

  if (head === "logout") {
    const res = NextResponse.json({ ok: true });
    for (const c of clearCookies()) res.headers.append("set-cookie", c);
    return res;
  }

  if (head === "login") {
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

export async function GET(req: NextRequest, ctx: { params: Promise<{ action: string[] }> }) {
  const { action } = await ctx.params;
  const head = action[0];

  if (head === "session") {
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

  if (head === "oidc") {
    const step = action[1];
    if (step === "start") return oidcStart(req);
    if (step === "callback") return oidcCallback(req);
    return NextResponse.json({ error: "unknown oidc step" }, { status: 404 });
  }

  return NextResponse.json({ error: "unknown action" }, { status: 404 });
}

// ── OIDC authorization-code + PKCE ────────────────────────────────────────────
async function oidcStart(req: NextRequest): Promise<NextResponse> {
  const cfg = oidcConfigFromEnv();
  if (!cfg) {
    return NextResponse.json(
      { error: "OIDC not configured (set FURIX_OIDC_ISSUER, FURIX_OIDC_CLIENT_ID, FURIX_OIDC_REDIRECT_URI)" },
      { status: 501 },
    );
  }
  try {
    const disc = await discover(cfg.issuer);
    const state = randomUrlToken();
    const nonce = randomUrlToken();
    const codeVerifier = randomUrlToken(32);
    const codeChallenge = pkceChallenge(codeVerifier);
    const returnTo = req.nextUrl.searchParams.get("returnTo") || "/";
    const url = buildAuthorizeUrl(disc, cfg, { state, nonce, codeChallenge });
    const res = NextResponse.redirect(url, 302);
    res.headers.append("set-cookie", txCookie(sealTx({ state, nonce, codeVerifier, returnTo }), isSecure()));
    return res;
  } catch (e) {
    return NextResponse.json({ error: `oidc start failed: ${String(e)}` }, { status: 502 });
  }
}

async function oidcCallback(req: NextRequest): Promise<NextResponse> {
  const cfg = oidcConfigFromEnv();
  if (!cfg) return NextResponse.json({ error: "OIDC not configured" }, { status: 501 });

  const q = req.nextUrl.searchParams;
  if (q.get("error")) {
    return NextResponse.json(
      { error: `idp returned error: ${q.get("error")}`, description: q.get("error_description") },
      { status: 401 },
    );
  }
  const code = q.get("code");
  const state = q.get("state");
  const tx = openTx(readTxCookie(req.headers.get("cookie")));
  if (!tx) return NextResponse.json({ error: "oidc transaction missing or expired" }, { status: 400 });
  if (!code || !state || state !== tx.state) {
    return NextResponse.json({ error: "oidc state mismatch (possible CSRF)" }, { status: 400 });
  }

  try {
    const disc = await discover(cfg.issuer);
    const tokens = await exchangeCode(disc, cfg, code, tx.codeVerifier);
    const jwks = await fetchJwks(disc.jwks_uri);
    const claims = verifyIdToken(tokens.id_token, {
      jwks,
      issuer: cfg.issuer,
      audience: cfg.clientId,
      nonce: tx.nonce,
    });
    const { sub, role, tenant } = claimsToSession(claims, cfg);
    const csrf = newCsrfToken();
    const token = sealSession({ sub, role, tenant, csrf });
    const dest = new URL(tx.returnTo.startsWith("/") ? tx.returnTo : "/", req.nextUrl.origin);
    const res = NextResponse.redirect(dest, 302);
    res.headers.append("set-cookie", sessionCookie(token));
    res.headers.append("set-cookie", csrfCookie(csrf));
    res.headers.append("set-cookie", clearTxCookie());
    return res;
  } catch (e) {
    const res = NextResponse.json({ error: `oidc callback failed: ${String(e)}` }, { status: 401 });
    res.headers.append("set-cookie", clearTxCookie());
    return res;
  }
}
