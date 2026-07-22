// ============================================================
// Typed Furix Compliance API functions — one per backend endpoint.
// Shapes mirror api/service.py + the dashboard adapter exactly.
// ============================================================

import type { ComplianceFramework } from "./types";
import { apiGet, apiPost, apiPut, apiDelete, safeGet, API_BASE, readCsrf } from "./client";

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
    // CSRF double-submit: the BFF requires this header on every write. Do NOT
    // set content-type — the browser must set the multipart boundary itself.
    headers: { "x-csrf-token": readCsrf() },
    credentials: "same-origin", // send the session cookie
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

// ── unified posture-run pipeline (Wave-H) ────────────────────────────────────
export type PostureRun = {
  run_id: string;
  tenant: string;
  connector_id?: string | null;
  completed_at?: string;
  status: string;
  collection: {
    manifest_sha256?: string | null;
    signed: boolean;
    reconciled: boolean;
    reconciliation_basis?: string | null;
    expected_accounts?: number | null;
    observed_accounts?: number | null;
  };
  snapshot: { source?: string; collected_at?: string; resource_count: number };
  evidence: { snapshot_sha256: string; raw_uri: string };
  evaluation: { assertion_total: number; pass: number; fail: number; evaluator_hash: string };
  report_id: string;
  verified: boolean;
  verifier_level?: string;
  findings: string[];
  affected_controls: string[];
};

export function runPosture(connectorId: string): Promise<PostureRun> {
  return apiPost<PostureRun>(`/api/connectors/${encodeURIComponent(connectorId)}/posture-run`, {});
}

export function getPostureRuns(): Promise<PostureRun[]> {
  return apiGet<PostureRun[]>("/api/posture-runs");
}

// ── compliance workspace (Wave-I / Epic 4) ───────────────────────────────────
export type ControlSummary = {
  control_id: string;
  title: string;
  status: string;
  owner: string;
  applicability: string;
  verification_method: string;
  test_cadence_days: number;
  evidence_freshness: "fresh" | "stale" | "unknown" | string;
  last_assessed: string | null;
  open_findings: number;
  framework_counts: { nist_csf: number; pci_dss: number; hipaa: number };
};

export type ControlProfile = {
  owner: string;
  applicability: string;
  applicability_rationale: string;
  implementation_narrative: string;
  verification_method: string;
  verification_description: string;
  test_cadence_days: number;
  updated_at: string | null;
  updated_by: string | null;
  configured: boolean;
};

export type ControlDetail = {
  control_id: string;
  title: string;
  status: string;
  worst_severity?: string | null;
  profile: ControlProfile;
  evidence_freshness: string;
  oldest_evidence_at?: string | null;
  last_assessed: string | null;
  assertion_freshness?: Array<{
    spec_id: string;
    status: string;
    freshness: { as_of?: string; collected_at?: string; age_seconds?: number; slo_seconds?: number; stale?: boolean } | null;
    evidence: Array<{ resource_id?: string; observed_at?: string; raw_uri?: string }>;
  }>;
  framework_mappings: { nist_csf: string[]; pci_dss: string[]; hipaa: string[] };
  linked_findings: Finding[];
  exceptions: Array<Record<string, unknown>>;
  evidence_lineage: {
    report_id: string | null;
    report_integrity_sha256: string | null;
    evidence_mode?: string;
    config_passing: string[];
    config_failing: string[];
    passing_tests: string[];
    failing_tests: string[];
    posture_run: {
      run_id: string;
      data_mode?: string;
      snapshot_sha256: string;
      snapshot_uri: string;
      report_id: string;
    } | null;
  };
};

export type ControlProfilePatch = Partial<{
  owner: string;
  applicability: string;
  applicability_rationale: string;
  implementation_narrative: string;
  verification_method: string;
  verification_description: string;
  test_cadence_days: number;
}>;

export function listControlWorkspace(): Promise<ControlSummary[]> {
  return apiGet<ControlSummary[]>("/api/compliance/controls");
}

export function getControlWorkspace(controlId: string): Promise<ControlDetail> {
  return apiGet<ControlDetail>(`/api/compliance/controls/${encodeURIComponent(controlId)}`);
}

export function updateControlProfile(
  controlId: string,
  patch: ControlProfilePatch,
): Promise<ControlProfile> {
  return apiPut<ControlProfile>(`/api/compliance/controls/${encodeURIComponent(controlId)}`, patch);
}

// ── audit-period workflow (Wave-I / Epic 5) ──────────────────────────────────
export type EvidenceRequest = {
  req_id: string;
  control_id: string;
  note: string;
  status: string;
  requested_by: string;
  requested_at: string;
  evidence_ref: string | null;
  fulfilled_by: string | null;
  fulfilled_at: string | null;
};

export type AuditPeriod = {
  period_id: string;
  tenant: string;
  name: string;
  boundary: string;
  start_date: string;
  end_date: string;
  status: "open" | "in_review" | "signed_off" | "reopened" | string;
  frozen: boolean;
  created_by: string;
  created_at: string;
  evidence_requests: EvidenceRequest[];
  signoffs: Array<{ reviewer: string; at: string; snapshot_sha256: string; snapshot_uri: string }>;
  reopenings: Array<{ by: string; at: string; reason: string }>;
};

export function listAuditPeriods(): Promise<AuditPeriod[]> {
  return apiGet<AuditPeriod[]>("/api/audit-periods");
}

export function createAuditPeriod(body: {
  name: string;
  boundary: string;
  start_date: string;
  end_date: string;
}): Promise<AuditPeriod> {
  return apiPost<AuditPeriod>("/api/audit-periods", body);
}

export function addEvidenceRequest(
  periodId: string,
  controlId: string,
  note: string,
): Promise<AuditPeriod> {
  return apiPost<AuditPeriod>(`/api/audit-periods/${encodeURIComponent(periodId)}/evidence-requests`, {
    control_id: controlId,
    note,
  });
}

export function signoffAuditPeriod(periodId: string): Promise<AuditPeriod> {
  return apiPost<AuditPeriod>(`/api/audit-periods/${encodeURIComponent(periodId)}/signoff`, {});
}

export function reopenAuditPeriod(periodId: string, reason: string): Promise<AuditPeriod> {
  return apiPost<AuditPeriod>(`/api/audit-periods/${encodeURIComponent(periodId)}/reopen`, { reason });
}

/** Same-origin download URL for the auditor evidence ZIP (session cookie is sent). */
export function auditPackageUrl(periodId: string): string {
  return `${API_BASE}/api/audit-periods/${encodeURIComponent(periodId)}/package.zip`;
}

// ── evidence retrieval (FUR-CMP-007): resolve a furix-evidence:// URI ─────────
export type EvidenceEnvelope = {
  evidence_id: string;
  source: string;
  tenant: string;
  boundary: string;
  sha256: string;
  raw_uri: string;
  size_bytes: number;
  observed_at: string | null;
  collected_at: string;
  collector_version: string;
  parser_version: string;
  schema_version: string;
  encryption?: { encrypted: boolean } & Record<string, unknown>;
};

export type LegalHold = {
  sha256: string;
  active: boolean;
  reason?: string;
  placed_by?: string;
  placed_at?: string;
  released_by?: string;
  released_at?: string;
  release_reason?: string;
};

export type RetentionPosture = {
  /** governing framework key, e.g. "hipaa" */
  class: string;
  retention_days: number;
  retain_until: string | null;
  /** true once past retention AND not under an active legal hold */
  expired: boolean;
  days_remaining: number | null;
  on_legal_hold: boolean;
  legal_hold: LegalHold | null;
};

export type EvidenceObject = {
  sha256: string;
  raw_uri: string;
  /** live re-verification: the stored bytes re-hash to this address (untampered) */
  integrity_verified: boolean;
  size_bytes: number;
  raw: string;
  envelope: EvidenceEnvelope;
  retention: RetentionPosture;
};

/** Extract the sha256 from a furix-evidence://<sha> URI (or accept a raw sha). */
export function evidenceSha(uriOrSha: string): string {
  const prefix = "furix-evidence://";
  return uriOrSha.startsWith(prefix) ? uriOrSha.slice(prefix.length) : uriOrSha;
}

/** Resolve a furix-evidence:// URI (or raw sha) to its sealed event + envelope. */
export function getEvidence(uriOrSha: string): Promise<EvidenceObject> {
  return apiGet<EvidenceObject>(`/api/evidence/${encodeURIComponent(evidenceSha(uriOrSha))}`);
}

/** Place a legal hold on an evidence object (auditor/admin). Freezes retention. */
export function placeLegalHold(uriOrSha: string, reason: string): Promise<LegalHold> {
  return apiPost<LegalHold>(
    `/api/evidence/${encodeURIComponent(evidenceSha(uriOrSha))}/legal-hold`,
    { reason },
  );
}

/** Release a legal hold (admin). Re-enables retention expiry. */
export function releaseLegalHold(uriOrSha: string, reason = ""): Promise<LegalHold> {
  return apiDelete<LegalHold>(
    `/api/evidence/${encodeURIComponent(evidenceSha(uriOrSha))}/legal-hold?reason=${encodeURIComponent(reason)}`,
  );
}
