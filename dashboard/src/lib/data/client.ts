// ============================================================
// Furix Compliance API client.
// Base URL from NEXT_PUBLIC_API_URL (default http://localhost:8000).
// All helpers fail soft: on network/HTTP error they throw ApiError, and the
// `safe*` variants return a fallback so the dashboard degrades gracefully to
// seed data when the backend is unreachable.
// ============================================================

// All API calls go through the same-origin server-side BFF (/bff/*), which
// attaches the bearer key on the server (P0-1). The browser never holds a
// credential — there is deliberately no NEXT_PUBLIC_API_KEY here.
export const API_BASE = "/bff";

export class ApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "ApiError";
  }
}

function readCsrf(): string {
  if (typeof document === "undefined") return "";
  for (const part of document.cookie.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === "furix_csrf") return v.join("=");
  }
  return "";
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const isWrite = init?.method && init.method !== "GET" && init.method !== "HEAD";
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        "content-type": "application/json",
        // CSRF double-submit: echo the readable CSRF cookie on state changes
        ...(isWrite ? { "x-csrf-token": readCsrf() } : {}),
        ...(init?.headers ?? {}),
      },
      credentials: "same-origin", // send the session cookie
      cache: "no-store",
    });
  } catch (e) {
    throw new ApiError(`network error contacting ${API_BASE}${path}: ${String(e)}`);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body?.detail ?? detail;
    } catch {
      /* ignore parse errors */
    }
    throw new ApiError(`${path} → ${res.status}: ${detail}`, res.status);
  }
  return (await res.json()) as T;
}

export function apiGet<T>(path: string): Promise<T> {
  return request<T>(path);
}

export function apiPost<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, { method: "POST", body: JSON.stringify(body) });
}

export function apiPut<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, { method: "PUT", body: JSON.stringify(body) });
}

/** GET that returns `fallback` on any error (for graceful degradation). */
export async function safeGet<T>(path: string, fallback: T): Promise<T> {
  try {
    return await apiGet<T>(path);
  } catch {
    return fallback;
  }
}

/** Is the backend reachable? Used to show a "live vs. demo data" indicator. */
export async function apiHealthy(): Promise<boolean> {
  try {
    await apiGet<{ status: string }>("/api/health");
    return true;
  } catch {
    return false;
  }
}
