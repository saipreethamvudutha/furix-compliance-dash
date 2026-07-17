// ============================================================
// Reports seed data
// Replace the body of each function with an API call.
// ============================================================

import type { ExecutiveReport } from "./types";

export async function getExecutiveReport(): Promise<ExecutiveReport> {
  return {
    period: "January 2026",
    companyName: "Coventra Health Insurance",
    securityScore: 87,
    scoreChange: 5,
    status: "STRONG",
    metrics: {
      assetsMonitored: { value: 24, change: 2 },
      criticalVulns: 0,
      openVulns: { value: 7, change: -3 },
      vulnsResolved: 12,
      complianceScore: 92,
      aiActions: 15,
    },
    highlights: [
      "Zero critical vulnerabilities on PHI databases for 45 consecutive days",
      "HIPAA compliance improved from 72% to 78%",
      "Automated remediation resolved 12 issues across claims-proc fleet",
      "2 new AWS assets (ec2-etl-worker, ec2-claims-api) discovered and secured",
    ],
    attentionNeeded: [
      "2 medium vulnerabilities on member-portal-01 (internet-facing)",
      "3 HIPAA Security Rule gaps require documentation",
      "edi-srv-01 (CMS clearinghouse link) needs TLS 1.2+ upgrade",
    ],
    vulnTrends: [
      { month: "Aug", newVulns: 10, resolvedVulns: 6 },
      { month: "Sep", newVulns: 12, resolvedVulns: 8 },
      { month: "Oct", newVulns: 8, resolvedVulns: 10 },
      { month: "Nov", newVulns: 5, resolvedVulns: 9 },
      { month: "Dec", newVulns: 4, resolvedVulns: 8 },
      { month: "Jan", newVulns: 3, resolvedVulns: 7 },
    ],
  };
}
