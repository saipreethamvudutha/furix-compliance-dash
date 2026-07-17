// ============================================================
// Typed Furix Compliance API functions — one per backend endpoint.
// Shapes mirror api/service.py + the dashboard adapter exactly.
// ============================================================

import type { ComplianceFramework } from "./types";
import { apiGet, apiPost, safeGet, API_BASE } from "./client";

export type FrameworkKpi = {
  id: string;
  name: string;
  shortName: string;
  percentage: number;
  gapControls: number;
  totalControls: number;
};

export type ReportSummary = {
  report_id: string;
  generated_at: string;
  total_logs: number;
  successful_logs: number;
  failed_logs: number;
  total_violations: number;
  frameworks: FrameworkKpi[];
  integrity_sha256: string;
};

export type Alert = {
  type: string;
  severity: string;
  message: string;
  control_id?: string;
  framework_id?: string;
};

export type IngestResult = {
  report_id: string;
  lines_ingested: number;
  summary: ReportSummary;
  frameworks: ComplianceFramework[];
  verification: { ok: boolean; checks_run: number };
  alerts: Alert[];
};

export type ReportIndexEntry = {
  report_id: string;
  generated_at: string;
  window_end: string;
  total_logs: number;
  successful_logs: number;
  total_violations: number;
  framework_pct: Record<string, number | null>;
};

// ── ingest ────────────────────────────────────────────────────────────────
export function ingestLogs(text: string, logType = "auto"): Promise<IngestResult> {
  return apiPost<IngestResult>("/api/ingest", { text, log_type: logType });
}

export async function ingestFile(file: File, logType = "auto"): Promise<IngestResult> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_BASE}/api/ingest-file?log_type=${encodeURIComponent(logType)}`, {
    method: "POST",
    body: form,
    cache: "no-store",
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json())?.detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new Error(`ingest-file → ${res.status}: ${detail}`);
  }
  return (await res.json()) as IngestResult;
}

export function generateAndIngest(
  count = 50,
  attackRatio = 0.35,
  seed = 0,
): Promise<IngestResult> {
  return apiPost<IngestResult>("/api/generate", {
    count,
    attack_ratio: attackRatio,
    seed,
  });
}

// ── reads ─────────────────────────────────────────────────────────────────
export function getLiveFrameworks(report = "latest"): Promise<ComplianceFramework[]> {
  return apiGet<ComplianceFramework[]>(`/api/frameworks?report=${encodeURIComponent(report)}`);
}

export function getLiveSummary(report = "latest"): Promise<ReportSummary> {
  return apiGet<ReportSummary>(`/api/summary?report=${encodeURIComponent(report)}`);
}

export function getReports(): Promise<ReportIndexEntry[]> {
  return safeGet<ReportIndexEntry[]>("/api/reports", []);
}

export function getTrend(): Promise<ReportIndexEntry[]> {
  return safeGet<ReportIndexEntry[]>("/api/trend", []);
}

export function getDiff(oldId: string, newId: string): Promise<{ diff: unknown; alerts: Alert[] }> {
  return apiGet(`/api/diff?old=${encodeURIComponent(oldId)}&new=${encodeURIComponent(newId)}`);
}
