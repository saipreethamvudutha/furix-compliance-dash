// ============================================================
// Type definitions for the BYOC platform
// ============================================================

export type SeverityLevel = "critical" | "high" | "medium" | "low";
export type AssetStatus = "healthy" | "warning" | "critical" | "unknown";
export type AssetType = "server" | "workstation" | "network" | "iot" | "cloud" | "unknown";
export type DeploymentType = "on-prem" | "cloud" | "hybrid";
export type DataSensitivity = "public" | "internal" | "confidential" | "restricted";
// Honest assurance vocabulary (Assurance Kernel v2):
//   met           — all mapped assertions positively passed (requires positive
//                   predicates; unreachable from detection-only evidence)
//   gap           — violations observed
//   unknown       — monitored, nothing observed. NOT proof of compliance.
//   not_monitored — no detection covers it (never disguised as N/A)
//   not_applicable— an APPROVED applicability decision excludes it
export type ControlStatus =
  | "met"
  | "in_progress"
  | "gap"
  | "unknown"
  | "not_monitored"
  | "not_applicable";
export type ActionPriority = "high" | "medium" | "low";
export type ActionStatus = "pending" | "approved" | "in_progress" | "completed" | "rolled_back";
export type ScanStatus = "idle" | "running" | "completed" | "failed";

// Dashboard metrics
export interface DashboardMetrics {
  totalAssets: number;
  assetsChange: number;
  activeScans: number;
  scansChange: number;
  riskScore: number;
  riskChange: number;
  criticalFindings: number;
  findingsChange: number;
}

// Scans
export interface Scan {
  id: string;
  name: string;
  target: string;
  type: "port" | "vulnerability" | "compliance" | "full";
  status: ScanStatus;
  progress: number;
  startedAt: string;
  completedAt?: string;
  findings: number;
  credentialRequired: boolean;
}

// Asset with classification
export interface Asset {
  id: string;
  name: string;
  businessLabel: string;
  type: AssetType;
  status: AssetStatus;
  businessRole: string;
  ip: string;
  os: string;
  lastScanned: string;
  healthScore: number;
  deployment: DeploymentType;
  dataSensitivity: DataSensitivity;
  vulnerabilities: { critical: number; high: number; medium: number; low: number };
  complianceFrameworks: string[];
  contextBadges: string[];
}

// Risk scoring
export interface RiskScore {
  id: string;
  assetId: string;
  assetName: string;
  cvssScore: number;
  assetCriticality: number;
  dataSensitivityScore: number;
  compositeScore: number;
  trend: "up" | "down" | "stable";
}

// Reports
export interface Report {
  id: string;
  title: string;
  type: "executive" | "technical" | "compliance" | "risk";
  generatedAt: string;
  period: string;
  exportable: boolean;
}

// AI Actions
export interface AIAction {
  id: string;
  title: string;
  priority: ActionPriority;
  system: string;
  description: string;
  fixes: string;
  confidence: number;
  confidenceLabel: string;
  risk: string;
  downtime: string;
  reversible: boolean;
  status: ActionStatus;
  isAgentic: boolean;
  manualSteps?: string[];
  reasoning: {
    finding: string;
    businessContext: string;
    riskAssessment: string;
    confidenceExplanation: string;
  };
  steps: string[];
}

// SIEM
export interface SIEMQuery {
  id: string;
  name: string;
  query: string;
  description: string;
  lastRun: string;
  resultCount: number;
}

export interface LogSource {
  id: string;
  name: string;
  type: string;
  status: "active" | "paused" | "error";
  eventsPerSecond: number;
  storageUsed: string;
  retentionDays: number;
}

// Reused types
export interface SecurityScore {
  overall: number;
  status: string;
  message: string;
  factors: {
    vulnerability: number;
    configuration: number;
    compliance: number;
    patchCurrency: number;
  };
  trend: { month: string; score: number }[];
}

export interface QuickStats {
  assetsMonitored: number;
  openVulnerabilities: number;
  complianceScore: number;
  aiActionsPending: number;
}

export interface ActionItem {
  id: string;
  type: "vulnerability" | "ai_recommendation" | "compliance_gap";
  title: string;
  description: string;
  severity: SeverityLevel;
  link: string;
}

export interface ActivityEntry {
  id: string;
  actor: "ai" | "user" | "system";
  action: string;
  target?: string;
  timestamp: string;
  status: "completed" | "in_progress" | "pending";
}

export interface Vulnerability {
  id: string;
  cve: string;
  title: string;
  severity: SeverityLevel;
  severityLabel: string;
  affectedAsset: string;
  affectedAssetLabel: string;
  discoveredAt: string;
  publicExploit: boolean;
  activelyExploited: boolean;
  businessImpact: string;
  aiRecommendation: string;
  remediationRisk: string;
  remediationDowntime: string;
  reversible: boolean;
  contextTags: string[];
}

export interface ComplianceFramework {
  id: string;
  name: string;
  shortName: string;
  totalControls: number;
  metControls: number;
  inProgressControls: number;
  gapControls: number;
  unknownControls: number;
  notMonitoredControls: number;
  naControls: number;
  /** share of requirements covered by ≥1 monitored control (0–100) */
  coveragePct: number;
  /** share of MONITORED requirements with observed violations; null if none monitored */
  atRiskPct: number | null;
  /** compliance % — null until positive assertions exist (never a silent 0/100) */
  percentage: number | null;
  controls: ComplianceControl[];
}

export interface AttackRef {
  techniqueId: string;
  techniqueName: string;
  ruleId: string;
  ruleTitle: string;
  level: string;
}

export interface ComplianceControl {
  id: string;
  reference: string;
  title: string;
  description: string;
  plainLanguage: string;
  status: ControlStatus;
  /** contributing CIS controls actually monitored / total mapped (coverage) */
  monitoredControls?: number;
  totalMappedControls?: number;
  systems: { name: string; status: ControlStatus; detail: string }[];
  aiRecommendation?: string;
  attack?: AttackRef[];
}

export interface AIPerformance {
  recommendationsMade: number;
  approvedByUsers: number;
  completedSuccessfully: number;
  rolledBack: number;
}

export interface VulnerabilityTrend {
  month: string;
  newVulns: number;
  resolvedVulns: number;
}

export interface ExecutiveReport {
  period: string;
  companyName: string;
  securityScore: number;
  scoreChange: number;
  status: string;
  metrics: {
    assetsMonitored: { value: number; change: number };
    criticalVulns: number;
    openVulns: { value: number; change: number };
    vulnsResolved: number;
    complianceScore: number;
    aiActions: number;
  };
  highlights: string[];
  attentionNeeded: string[];
  vulnTrends: VulnerabilityTrend[];
}
