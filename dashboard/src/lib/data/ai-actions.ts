// ============================================================
// AI Actions seed data for BYOC platform
// ============================================================

import type { AIAction, AIPerformance, ActivityEntry } from "./types";

export async function getAIActions(): Promise<AIAction[]> {
  return [
    {
      id: "ai-1",
      title: "Apply Critical Security Patch",
      priority: "high",
      system: "member-portal-01",
      description: "Apply Nginx security patch to fix SQL injection vulnerability against member portal",
      fixes: "CVE-2024-1234 (SQL Injection)",
      confidence: 98,
      confidenceLabel: "Very High",
      risk: "Low",
      downtime: "~5 minutes",
      reversible: true,
      status: "pending",
      isAgentic: true,
      manualSteps: [
        "Stage Nginx 1.26.x security build",
        "Drain member-portal-01 behind waf-01",
        "Apply patch as root",
        "Restart Nginx and re-enable upstream",
        "Verify vulnerability is resolved",
      ],
      reasoning: {
        finding: "member-portal-01 is running Nginx 1.18 with a known critical vulnerability (CVE-2024-1234).",
        businessContext: "This server hosts member.coventra.com and handles PHI for ~1.2M Coventra plan members.",
        riskAssessment: "Public exploit exists and lookalike-domain attackers are probing the member portal.",
        confidenceExplanation: "High confidence — vulnerability confirmed and patch is from the official vendor.",
      },
      steps: [
        "Stage Nginx security build (automatic)",
        "Drain member-portal-01 behind waf-01 (~2 minutes)",
        "Install patch",
        "Restart Nginx",
        "Verify vulnerability is resolved",
      ],
    },
    {
      id: "ai-2",
      title: "Close Unused RDP Port",
      priority: "medium",
      system: "phi-db-01",
      description: "Close port 3389 (RDP) on phi-db-01 — not used in 90+ days",
      fixes: "Open RDP Port (CVE-2024-9012)",
      confidence: 95,
      confidenceLabel: "Very High",
      risk: "Low",
      downtime: "None",
      reversible: true,
      status: "pending",
      isAgentic: true,
      manualSteps: [
        "Open Palo Alto policy on fw-internal-01",
        "Create deny rule for tcp/3389 to 10.30.1.10",
        "Verify no active RDP sessions via CyberArk",
        "Commit and save firewall rule",
      ],
      reasoning: {
        finding: "Port 3389 (RDP) is open on phi-db-01 with no connections in 90 days (Imperva + Splunk confirmed).",
        businessContext: "phi-db-01 hosts member_health_records, mental_health_records and rx_history. An open RDP port is a common attack vector.",
        riskAssessment: "Closing this unused port removes a potential attack path with zero operational impact — DBAs use CyberArk PAM.",
        confidenceExplanation: "High confidence based on 90 days of traffic analysis showing zero usage.",
      },
      steps: [
        "Update fw-internal-01 policy to block inbound tcp/3389",
        "Verify no active RDP sessions",
        "Commit firewall rule",
        "Confirm port is closed via Nessus scan",
      ],
    },
    {
      id: "ai-3",
      title: "Update TLS Certificate on Email Gateway",
      priority: "low",
      system: "email-gw-01",
      description: "Renew TLS certificate with SHA-256 on email-gw-01 (Proofpoint)",
      fixes: "CVE-2024-7890 (Outdated SSL)",
      confidence: 92,
      confidenceLabel: "Very High",
      risk: "Low",
      downtime: "~2 minutes",
      reversible: true,
      status: "pending",
      isAgentic: true,
      manualSteps: [
        "Generate new CSR with SHA-256 using openssl",
        "Submit CSR to Certificate Authority",
        "Download and install the new certificate on email-gw-01",
        "Restart Proofpoint service",
        "Verify certificate is active via mail.coventra.com",
      ],
      reasoning: {
        finding: "The TLS certificate on email-gw-01 uses SHA-1, which is considered weak.",
        businessContext: "email-gw-01 fronts mail.coventra.com and is the primary control against BEC targeting cfo_williams and ciso_patel.",
        riskAssessment: "Certificate renewal is a routine operation with minimal risk.",
        confidenceExplanation: "High confidence — TLS certificate renewal is a well-understood, low-risk operation.",
      },
      steps: [
        "Generate new CSR with SHA-256",
        "Obtain new certificate from CA",
        "Install new certificate",
        "Restart Proofpoint service",
        "Verify certificate is active",
      ],
    },
  ];
}

export async function getAIPerformance(): Promise<AIPerformance> {
  return {
    recommendationsMade: 156,
    approvedByUsers: 148,
    completedSuccessfully: 147,
    rolledBack: 1,
  };
}

export async function getActivityLog(): Promise<ActivityEntry[]> {
  return [
    { id: "log-1", actor: "ai", action: "Applied Nginx patch to member-portal-01", target: "member-portal-01", timestamp: "Today, 14:32", status: "completed" },
    { id: "log-2", actor: "user", action: "ciso_patel approved AI recommendation: patch member-portal-01", timestamp: "Today, 14:30", status: "completed" },
    { id: "log-3", actor: "ai", action: "Completed vulnerability scan - Found 2 new vulnerabilities on edi-srv-01", timestamp: "Today, 10:15", status: "completed" },
    { id: "log-4", actor: "ai", action: "Scanning 3 newly discovered AWS assets", timestamp: "Today, 09:00", status: "in_progress" },
    { id: "log-5", actor: "ai", action: "Applied approved patch to claims-proc-02", target: "claims-proc-02", timestamp: "Yesterday, 22:15", status: "completed" },
    { id: "log-6", actor: "system", action: "New asset discovered: iot-badge-fl2", target: "iot-badge-fl2", timestamp: "Yesterday, 14:00", status: "completed" },
    { id: "log-7", actor: "ai", action: "Identified 2 HIPAA compliance gaps for review", timestamp: "Yesterday, 12:30", status: "completed" },
  ];
}
