// ============================================================
// Furix Compliance API client.
// Base URL from NEXT_PUBLIC_API_URL (default http://localhost:8000).
// All helpers fail soft: on network/HTTP error they throw ApiError, and the
// `safe*` variants return a fallback so the dashboard degrades gracefully to
// seed data when the backend is unreachable.
// ============================================================

export const API_BASE =
  (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
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
