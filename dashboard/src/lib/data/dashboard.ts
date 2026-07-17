// ============================================================
// Dashboard seed data for BYOC platform
// ============================================================

import type { SecurityScore, QuickStats, ActionItem, ActivityEntry, DashboardMetrics } from "./types";
import { getCoventraStats } from "./coventra-stats";

export async function getDashboardMetrics(): Promise<DashboardMetrics> {
  const s = await getCoventraStats();
  return {
    totalAssets: s.total,
    assetsChange: 12,
    activeScans: s.activeScans,
    scansChange: -2,
    riskScore: s.riskScore,
    riskChange: -5,
    criticalFindings: s.vulns.critical,
    findingsChange: 7,
  };
}

export async function getSecurityScore(): Promise<SecurityScore> {
  return {
    overall: 87,
    status: "Strong",
    message: "Your security posture is excellent",
    factors: {
      vulnerability: 82,
      configuration: 90,
      compliance: 85,
      patchCurrency: 91,
    },
    trend: [
      { month: "Aug", score: 68 },
      { month: "Sep", score: 72 },
      { month: "Oct", score: 75 },
      { month: "Nov", score: 79 },
      { month: "Dec", score: 83 },
      { month: "Jan", score: 87 },
    ],
  };
}

export async function getQuickStats(): Promise<QuickStats> {
  const s = await getCoventraStats();
  return {
    assetsMonitored: s.total,
    openVulnerabilities: s.vulns.critical + s.vulns.high,
    complianceScore: s.complianceScore,
    aiActionsPending: Math.max(5, Math.round(s.vulns.critical / 4)),
  };
}

export async function getActionItems(): Promise<ActionItem[]> {
  return [
    {
      id: "act-1",
      type: "vulnerability",
      title: "5 Critical Vulnerabilities",
      description: "Bulk PHI query risk on phi-db-01 and member portal exposure",
      severity: "critical",
      link: "/risk-scoring",
    },
    {
      id: "act-2",
      type: "ai_recommendation",
      title: "5 AI Recommendations Ready",
      description: "Patch and configuration improvements available",
      severity: "medium",
      link: "/ai-actions",
    },
    {
      id: "act-3",
      type: "compliance_gap",
      title: "Compliance gap identified",
      description: "HIPAA §164.312(e)(1) transmission security needs attention on edi-srv-01",
      severity: "high",
      link: "/reports",
    },
  ];
}

export async function getRecentActivity(): Promise<ActivityEntry[]> {
  return [
    {
      id: "evt-1",
      actor: "ai",
      action: "Completed port scan on 12 Coventra assets",
      timestamp: "2 hours ago",
      status: "completed",
    },
    {
      id: "evt-2",
      actor: "ai",
      action: "Applied approved patch to claims-proc-01",
      target: "claims-proc-01",
      timestamp: "5 hours ago",
      status: "completed",
    },
    {
      id: "evt-3",
      actor: "system",
      action: "SIEM (Splunk) detected unusual login pattern for cfo_williams",
      timestamp: "Yesterday",
      status: "pending",
    },
    {
      id: "evt-4",
      actor: "ai",
      action: "New cloud asset discovered: ec2-etl-worker",
      target: "ec2-etl-worker",
      timestamp: "Yesterday",
      status: "completed",
    },
    {
      id: "evt-5",
      actor: "user",
      action: "Exported HIPAA risk assessment report (CSV)",
      target: "HIPAA Risk Report Q1",
      timestamp: "2 days ago",
      status: "completed",
    },
  ];
}
