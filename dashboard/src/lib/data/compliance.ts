// ============================================================
// Compliance data.
// API-first: fetches live SCF-derived compliance from the Furix backend
// (/api/frameworks). Falls back to the seed data below when the backend is
// unreachable, so the dashboard still renders in demo mode.
// ============================================================

import type { ComplianceFramework } from "./types";
import { getLiveFrameworks } from "./furix-api";

export async function getComplianceFrameworks(): Promise<ComplianceFramework[]> {
  try {
    const live = await getLiveFrameworks("latest");
    if (Array.isArray(live) && live.length > 0) return live;
  } catch {
    /* backend unreachable or no reports yet — fall through to seed data */
  }
  return getComplianceSeed();
}

async function getComplianceSeed(): Promise<ComplianceFramework[]> {
  return [
    {
      id: "hipaa",
      name: "Health Insurance Portability and Accountability Act",
      shortName: "HIPAA",
      totalControls: 60,
      metControls: 47,
      inProgressControls: 5,
      gapControls: 8,
      unknownControls: 0,
      notMonitoredControls: 0,
      naControls: 0,
      coveragePct: 100,
      atRiskPct: 13,
      percentage: 78,
      controls: [
        {
          id: "hipaa-1",
          reference: "§164.312(a)(1)",
          title: "Access Control",
          description: "Implement technical policies and procedures for electronic information systems that maintain ePHI",
          plainLanguage: "Only authorized people can access PHI systems",
          status: "met",
          systems: [
            { name: "member-portal-01", status: "met", detail: "Okta SSO + RBAC configured" },
            { name: "phi-db-01", status: "met", detail: "CyberArk PAM checkout enforced" },
            { name: "claims-proc-01", status: "met", detail: "Okta SSO integrated" },
          ],
        },
        {
          id: "hipaa-2",
          reference: "§164.312(a)(2)(i)",
          title: "Unique User Identification",
          description: "Assign a unique name/number for identifying and tracking user identity",
          plainLanguage: "Every user has their own unique login",
          status: "met",
          systems: [
            { name: "All Systems", status: "met", detail: "ad-dc-01 / ad-dc-02 + Okta integrated" },
          ],
        },
        {
          id: "hipaa-3",
          reference: "§164.312(e)(1)",
          title: "Transmission Security",
          description: "Implement technical security measures to guard against unauthorized access to ePHI transmitted over networks",
          plainLanguage: "All PHI sent over the network must be encrypted",
          status: "gap",
          systems: [
            { name: "member-portal-01", status: "met", detail: "TLS 1.3 enabled" },
            { name: "claims-proc-01", status: "met", detail: "TLS 1.3 enabled" },
            { name: "edi-srv-01", status: "gap", detail: "TLS 1.0 only (needs upgrade)" },
          ],
          aiRecommendation: "Update edi-srv-01 to support TLS 1.2+. Estimated effort: 2-4 hours.",
        },
        {
          id: "hipaa-4",
          reference: "§164.312(c)(1)",
          title: "Integrity Controls",
          description: "Implement policies to protect ePHI from improper alteration or destruction",
          plainLanguage: "PHI cannot be changed or deleted without authorization",
          status: "met",
          systems: [
            { name: "phi-db-01", status: "met", detail: "Imperva DAM + Oracle audit enabled" },
            { name: "coventra-phi-backup", status: "met", detail: "S3 Object Lock + versioning enabled" },
          ],
        },
        {
          id: "hipaa-5",
          reference: "§164.312(d)",
          title: "Person or Entity Authentication",
          description: "Implement procedures to verify a person seeking access is who they claim to be",
          plainLanguage: "Verify that people are who they say they are before granting access",
          status: "in_progress",
          systems: [
            { name: "member-portal-01", status: "met", detail: "MFA enabled via Okta" },
            { name: "phi-db-01", status: "met", detail: "MFA via CyberArk PAM" },
            { name: "edi-srv-01", status: "gap", detail: "Vendor service account, password-only" },
          ],
          aiRecommendation: "Migrate vendor_edi_cms to CyberArk-vaulted credentials with MFA.",
        },
        {
          id: "hipaa-6",
          reference: "§164.308(a)(5)",
          title: "Security Awareness Training",
          description: "Implement a security awareness and training program for all workforce members",
          plainLanguage: "All 64 employees must receive HIPAA security training",
          status: "gap",
          systems: [],
          aiRecommendation: "Roll out hipaa_officer-led annual training program. We can help track completion across all 64 users.",
        },
        {
          id: "hipaa-7",
          reference: "§164.310(d)(1)",
          title: "Device and Media Controls",
          description: "Implement policies for the receipt and removal of hardware and electronic media",
          plainLanguage: "Track and control all devices that can access PHI",
          status: "in_progress",
          systems: [
            { name: "All Workstations", status: "met", detail: "CrowdStrike Falcon installed" },
            { name: "iot-badge-fl2", status: "gap", detail: "Newly discovered - not yet assessed" },
          ],
        },
        {
          id: "hipaa-8",
          reference: "§164.312(b)",
          title: "Audit Controls",
          description: "Implement hardware, software, and/or procedural mechanisms that record and examine activity",
          plainLanguage: "Keep records of who accessed what and when",
          status: "met",
          systems: [
            { name: "All Servers", status: "met", detail: "Splunk centralized logging (splunk-idx-01/02)" },
          ],
        },
      ],
    },
    {
      id: "pci-dss",
      name: "Payment Card Industry Data Security Standard",
      shortName: "PCI-DSS",
      totalControls: 24,
      metControls: 22,
      inProgressControls: 1,
      gapControls: 1,
      unknownControls: 0,
      notMonitoredControls: 0,
      naControls: 0,
      coveragePct: 100,
      atRiskPct: 4,
      percentage: 92,
      controls: [
        {
          id: "pci-1",
          reference: "Req 1",
          title: "Install and maintain network security controls",
          description: "Install and maintain a firewall configuration to protect cardholder data",
          plainLanguage: "Keep firewalls properly set up to protect premium-payment data",
          status: "met",
          systems: [
            { name: "fw-perimeter-01", status: "met", detail: "Palo Alto rules reviewed quarterly" },
          ],
        },
        {
          id: "pci-2",
          reference: "Req 4",
          title: "Protect cardholder data with strong cryptography during transmission",
          description: "Use strong cryptography to protect cardholder data during transmission over open, public networks",
          plainLanguage: "Encrypt premium-payment data when sent over the internet",
          status: "gap",
          systems: [
            { name: "billing-srv-01", status: "met", detail: "TLS 1.3 enabled" },
            { name: "edi-srv-01", status: "gap", detail: "TLS 1.0 only" },
          ],
          aiRecommendation: "Same fix as HIPAA §164.312(e)(1) - Update edi-srv-01 TLS version.",
        },
        {
          id: "pci-3",
          reference: "Req 6",
          title: "Develop and maintain secure systems and software",
          description: "Develop and maintain secure systems and applications",
          plainLanguage: "Keep all software up to date and secure",
          status: "in_progress",
          systems: [
            { name: "member-portal-01", status: "gap", detail: "Pending patch for CVE-2024-1234" },
            { name: "claims-proc-01", status: "met", detail: "All patches current" },
          ],
        },
        {
          id: "pci-4",
          reference: "Req 8",
          title: "Identify users and authenticate access",
          description: "Identify and authenticate access to system components",
          plainLanguage: "All users must have unique logins with strong authentication",
          status: "met",
          systems: [
            { name: "All Systems", status: "met", detail: "AD + Okta MFA for premium-billing systems" },
          ],
        },
      ],
    },
  ];
}
