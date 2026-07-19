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

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Server-only configuration — NOT prefixed NEXT_PUBLIC, so it is never bundled
// into client JavaScript.
const API_URL = (process.env.FURIX_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
const API_KEY = process.env.FURIX_API_KEY ?? "furix-dev-key";

async function proxy(req: NextRequest, path: string[]): Promise<NextResponse> {
  const target = `${API_URL}/${path.join("/")}${req.nextUrl.search}`;
  const init: RequestInit = {
    method: req.method,
    headers: {
      authorization: `Bearer ${API_KEY}`,
      // forward only content-type; the key is injected server-side
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
