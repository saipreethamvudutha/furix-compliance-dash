// Server-side Backend-for-Frontend proxy (P0-1 fix).
//
// The Furix API requires a bearer key. Embedding that key in client JavaScript
// (NEXT_PUBLIC_API_KEY) exposed it to every browser — the audit's P0. This
// route handler runs ONLY on the server: it holds the key in a server-only env
// var (FURIX_API_KEY, never NEXT_PUBLIC_*) and forwards same-origin /bff/*
// requests to the real API with the Authorization header attached server-side.
// The browser never sees the credential.
//
// A real deployment replaces the static server key with a per-user token minted
// from an OIDC authorization-code/PKCE session; this handler is where that
// session→token exchange lives. The client contract (same-origin /bff/*) does
// not change when that lands.

import { NextRequest, NextResponse } from "next/server";
import { isProd, prodReadiness, readSecret } from "@/lib/bff/env";
import { openSession, readCsrfCookie, readSessionCookie } from "@/lib/bff/session";
import { bffAllows, mintUserToken } from "@/lib/bff/token";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Server-only configuration — NOT prefixed NEXT_PUBLIC, so it is never bundled
// into client JavaScript. The static key is a DEV convenience only; in
// production per-user token minting is mandatory (see the bearer resolution
// below) and this fallback is never used.
const API_URL = (process.env.FURIX_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
const DEV_API_KEY = readSecret("FURIX_API_KEY") || "furix-dev-key";

function unauth(detail: string, status = 401): NextResponse {
  return NextResponse.json({ detail }, { status });
}

async function proxy(req: NextRequest, path: string[]): Promise<NextResponse> {
  const apiPath = path.join("/");
  // health + readiness probes are open (no session) — an orchestrator/LB must be
  // able to probe them before any user is authenticated.
  const probe = apiPath.replace(/^api\//, "");
  const isHealth = probe.startsWith("health") || probe.startsWith("readyz");

  // ── fail-closed production readiness (Wave-F) ─────────────────────────────
  // If production is misconfigured (missing session/mint secret, no identity
  // source), refuse to proxy rather than serving with insecure defaults.
  const readiness = prodReadiness();
  if (!readiness.ok) {
    return NextResponse.json(
      { detail: "BFF is not configured for production", issues: readiness.issues },
      { status: 503 },
    );
  }

  // ── server-side session gate (Wave-N #1) ──────────────────────────────────
  const cookieHeader = req.headers.get("cookie");
  const session = openSession(readSessionCookie(cookieHeader));
  if (!isHealth) {
    if (!session) return unauth("not authenticated — sign in");
    // server-side RBAC (defense in depth; the API enforces fine-grained scopes)
    if (!bffAllows(session.role, req.method, apiPath)) {
      return unauth(`role '${session.role}' may not ${req.method} ${apiPath}`, 403);
    }
    // CSRF double-submit on state-changing requests
    if (req.method !== "GET" && req.method !== "HEAD") {
      const header = req.headers.get("x-csrf-token");
      const cookie = readCsrfCookie(cookieHeader);
      if (!header || !cookie || header !== cookie || header !== session.csrf) {
        return unauth("CSRF token missing or invalid", 403);
      }
    }
  }

  // Bearer resolution. Prefer a short-lived per-user minted token so the API
  // authenticates and tenant-scopes per user. In production minting is
  // mandatory: there is NO static-key fallback — a request that cannot mint
  // fails closed (503). The static dev key is used ONLY outside production.
  const minted = session ? mintUserToken(session) : null;
  let bearer: string | null = minted;
  if (!bearer && !isProd()) {
    bearer = DEV_API_KEY; // dev convenience only
  }
  if (!isHealth && !bearer) {
    return unauth("server misconfigured: per-user token minting unavailable", 503);
  }

  const target = `${API_URL}/${apiPath}${req.nextUrl.search}`;
  const init: RequestInit = {
    method: req.method,
    headers: {
      ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
      // forward the authenticated identity for the API's audit log
      ...(session ? { "x-furix-actor": session.sub, "x-furix-role": session.role } : {}),
      ...(req.headers.get("content-type")
        ? { "content-type": req.headers.get("content-type") as string }
        : {}),
    },
    // pass the body through for POST/PUT
    body: req.method === "GET" || req.method === "HEAD" ? undefined : await req.text(),
    cache: "no-store",
  };

  let res: Response;
  try {
    res = await fetch(target, init);
  } catch (e) {
    return NextResponse.json(
      { detail: `bff: cannot reach the Furix API at ${API_URL}: ${String(e)}` },
      { status: 502 },
    );
  }

  const contentType = res.headers.get("content-type") ?? "application/json";
  const bodyText = await res.text();
  return new NextResponse(bodyText, {
    status: res.status,
    headers: { "content-type": contentType, "cache-control": "no-store" },
  });
}

export async function GET(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  return proxy(req, path);
}

export async function POST(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  return proxy(req, path);
}
