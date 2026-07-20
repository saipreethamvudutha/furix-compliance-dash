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
  percentage: number | null;
  coveragePct: number;
  atRiskPct: number | null;
  gapControls: number;
  unknownControls: number;
  notMonitoredControls: number;
  totalControls: number;
};

export type PopulationManifest = {
  expected: number;
  observed: number;
  errored: number;
  excluded: number;
  duplicate: number;
  coverage_pct: number;
  reconciled: boolean;
};

export type ReportSummary = {
  report_id: string;
  generated_at: string;
  total_logs: number;
  successful_logs: number;
  failed_logs: number;
  total_violations: number;
  population?: PopulationManifest;
  frameworks: FrameworkKpi[];
  versions?: Record<string, string>;
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
  verification: {
    ok: boolean;
    /** the exact verification level achieved — the UI must show this, never more */
    level?:
      | "NOT_VERIFIED"
      | "INTEGRITY_VERIFIED"
      | "ROLLUP_VERIFIED"
      | "EVALUATION_REPRODUCED";
    checks_run: number;
  };
  alerts: Alert[];
};

export type ReportIndexEntry = {
  report_id: string;
  generated_at: string;
  window_end: string;
  total_logs: number;
  successful_logs: number;
  total_violations: number;
  /** framework_id → share of monitored requirements at risk (schema 2.0) */
  framework_at_risk_pct: Record<string, number | null>;
};

// ── async ingest (background jobs) ──────────────────────────────────────────
// Ingest endpoints return a job ref; poll getJob() until done, then read result.
export type JobRef = { job_id: string };

export type JobStatus = {
  job_id: string;
  status: "queued" | "running" | "done" | "error";
  phase: string;
  processed: number;
  total: number;
  percent: number;
  error: string | null;
  result: IngestResult | null;
};

export function ingestLogs(text: string, logType = "auto"): Promise<JobRef> {
  return apiPost<JobRef>("/api/ingest", { text, log_type: logType });
}

export async function ingestFile(file: File, logType = "auto"): Promise<JobRef> {
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
  return (await res.json()) as JobRef;
}

export function generateAndIngest(count = 50, attackRatio = 0.35, seed = 0): Promise<JobRef> {
  return apiPost<JobRef>("/api/generate", { count, attack_ratio: attackRatio, seed });
}

export function getJob(jobId: string): Promise<JobStatus> {
  return apiGet<JobStatus>(`/api/jobs/${encodeURIComponent(jobId)}`);
}

/** Poll a job until it finishes, calling onProgress each tick. Resolves with the final status. */
export async function pollJob(
  jobId: string,
  onProgress?: (job: JobStatus) => void,
  intervalMs = 800,
): Promise<JobStatus> {
  for (;;) {
    const job = await getJob(jobId);
    onProgress?.(job);
    if (job.status === "done" || job.status === "error") return job;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
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

// ── findings / remediation lifecycle (Wave 5) ────────────────────────────────
export type Finding = {
  finding_id: string;
  state: string;
  control_id?: string;
  framework_id?: string;
  severity?: string;
  owner?: string;
  due_date?: string;
  expired?: boolean;
  updated_at?: string;
  last_actor?: string;
  last_reason?: string;
  exception?: {
    approver?: string;
    rationale?: string;
    compensating_control?: string;
    expiry?: string;
  };
};

export function getFindings(openOnly = true): Promise<Finding[]> {
  return apiGet<Finding[]>(`/api/findings?open_only=${openOnly}`);
}

// ── connectors: scheduled collection + health (Wave-G) ───────────────────────
export type Connector = {
  connector_id: string;
  tenant: string;
  kind: string;
  schedule_seconds: number;
  enabled: boolean;
  health: "healthy" | "degraded" | "failed" | "unknown" | string;
  last_status?: string | null;
  last_error?: string | null;
  last_run_at_iso?: string | null;
  next_run_at_iso?: string | null;
  last_manifest_sha?: string | null;
  last_signed: boolean;
  last_reconciled: boolean;
};

export function getConnectors(): Promise<Connector[]> {
  return apiGet<Connector[]>("/api/connectors");
}

export function registerConnector(
  connectorId: string,
  kind = "demo-aws",
  scheduleSeconds = 86400,
): Promise<Connector> {
  return apiPost<Connector>("/api/connectors", {
    connector_id: connectorId,
    kind,
    schedule_seconds: scheduleSeconds,
  });
}

export function runConnector(connectorId: string): Promise<Connector> {
  return apiPost<Connector>(`/api/connectors/${encodeURIComponent(connectorId)}/run`, {});
}
