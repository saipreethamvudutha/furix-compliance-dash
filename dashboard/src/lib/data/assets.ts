// ============================================================
// Assets seed data for BYOC platform
// ============================================================

import type { Asset } from "./types";

const CURATED_ASSETS: Asset[] = [
    {
      id: "asset-1",
      name: "member-portal-01",
      businessLabel: "Member Portal (member.coventra.com)",
      type: "server",
      status: "warning",
      businessRole: "Member Portal",
      ip: "172.16.1.10",
      os: "Ubuntu 22.04 / Nginx",
      lastScanned: "2 hours ago",
      healthScore: 72,
      deployment: "on-prem",
      dataSensitivity: "confidential",
      vulnerabilities: { critical: 1, high: 1, medium: 2, low: 0 },
      complianceFrameworks: ["HIPAA", "PCI-DSS"],
      contextBadges: ["Handles Member Data", "Internet-Facing", "Contains PHI"],
    },
    {
      id: "asset-2",
      name: "phi-db-01",
      businessLabel: "PHI Database (Oracle)",
      type: "server",
      status: "warning",
      businessRole: "PHI Database",
      ip: "10.30.1.10",
      os: "Oracle Linux 8 / Oracle DB 19c",
      lastScanned: "2 hours ago",
      healthScore: 78,
      deployment: "on-prem",
      dataSensitivity: "restricted",
      vulnerabilities: { critical: 0, high: 1, medium: 1, low: 2 },
      complianceFrameworks: ["HIPAA"],
      contextBadges: ["Contains PHI", "Business Critical", "42 CFR Part 2"],
    },
    {
      id: "asset-3",
      name: "claims-proc-01",
      businessLabel: "Claims Processing Server",
      type: "server",
      status: "healthy",
      businessRole: "Claims Processing",
      ip: "10.20.1.10",
      os: "Ubuntu 22.04 LTS",
      lastScanned: "2 hours ago",
      healthScore: 94,
      deployment: "on-prem",
      dataSensitivity: "confidential",
      vulnerabilities: { critical: 0, high: 0, medium: 1, low: 0 },
      complianceFrameworks: ["HIPAA", "PCI-DSS"],
      contextBadges: ["Handles Member Data", "Business Critical"],
    },
    {
      id: "asset-4",
      name: "ec2-claims-api",
      businessLabel: "Claims API (AWS)",
      type: "cloud",
      status: "healthy",
      businessRole: "Cloud Claims API",
      ip: "172.31.1.20",
      os: "Amazon Linux 2023",
      lastScanned: "1 hour ago",
      healthScore: 91,
      deployment: "cloud",
      dataSensitivity: "confidential",
      vulnerabilities: { critical: 0, high: 0, medium: 0, low: 1 },
      complianceFrameworks: ["HIPAA", "SOC2"],
      contextBadges: ["Cloud Service", "Business Critical"],
    },
    {
      id: "asset-5",
      name: "member-db-01",
      businessLabel: "Member Database (MSSQL)",
      type: "cloud",
      status: "healthy",
      businessRole: "Member Database",
      ip: "10.30.2.10",
      os: "MSSQL 2022",
      lastScanned: "1 hour ago",
      healthScore: 88,
      deployment: "cloud",
      dataSensitivity: "restricted",
      vulnerabilities: { critical: 0, high: 0, medium: 1, low: 1 },
      complianceFrameworks: ["HIPAA", "SOC2"],
      contextBadges: ["Contains PHI", "Cloud Service"],
    },
    {
      id: "asset-6",
      name: "fw-perimeter-01",
      businessLabel: "Perimeter Firewall (Palo Alto)",
      type: "network",
      status: "healthy",
      businessRole: "Network Security",
      ip: "10.0.1.1",
      os: "PAN-OS 11.1",
      lastScanned: "1 hour ago",
      healthScore: 96,
      deployment: "on-prem",
      dataSensitivity: "internal",
      vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
      complianceFrameworks: ["HIPAA", "PCI-DSS"],
      contextBadges: ["Business Critical"],
    },
    {
      id: "asset-7",
      name: "WS-CS-005",
      businessLabel: "Customer Service Workstation (cs_rep_02)",
      type: "workstation",
      status: "healthy",
      businessRole: "Customer Service",
      ip: "10.10.4.5",
      os: "Windows 11 Pro",
      lastScanned: "3 hours ago",
      healthScore: 85,
      deployment: "on-prem",
      dataSensitivity: "internal",
      vulnerabilities: { critical: 0, high: 0, medium: 1, low: 0 },
      complianceFrameworks: ["HIPAA"],
      contextBadges: [],
    },
    {
      id: "asset-8",
      name: "coventra-phi-backup",
      businessLabel: "PHI Backup S3 Bucket",
      type: "cloud",
      status: "healthy",
      businessRole: "Encrypted Backup",
      ip: "N/A (Cloud)",
      os: "AWS S3 (us-east-1)",
      lastScanned: "1 hour ago",
      healthScore: 92,
      deployment: "cloud",
      dataSensitivity: "restricted",
      vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
      complianceFrameworks: ["HIPAA"],
      contextBadges: ["Contains PHI", "Cloud Service"],
    },
    {
      id: "asset-9",
      name: "ec2-etl-worker",
      businessLabel: "ETL Worker (AWS)",
      type: "cloud",
      status: "healthy",
      businessRole: "Data Pipeline",
      ip: "172.31.1.30",
      os: "Amazon Linux 2023",
      lastScanned: "2 hours ago",
      healthScore: 90,
      deployment: "cloud",
      dataSensitivity: "internal",
      vulnerabilities: { critical: 0, high: 0, medium: 0, low: 1 },
      complianceFrameworks: [],
      contextBadges: ["Cloud Service"],
    },
    {
      id: "asset-10",
      name: "edi-srv-01",
      businessLabel: "EDI Server (legacy X12)",
      type: "server",
      status: "critical",
      businessRole: "EDI / CMS Exchange",
      ip: "10.40.1.10",
      os: "Windows Server 2012 R2",
      lastScanned: "2 hours ago",
      healthScore: 45,
      deployment: "on-prem",
      dataSensitivity: "restricted",
      vulnerabilities: { critical: 1, high: 2, medium: 3, low: 1 },
      complianceFrameworks: ["HIPAA"],
      contextBadges: ["Contains PHI", "Business Critical", "End of Life OS"],
    },
];

export async function getAssets(): Promise<Asset[]> {
  return [...CURATED_ASSETS, ...SYNTHETIC_ASSETS];
}

export async function getAssetById(id: string): Promise<Asset | undefined> {
  const assets = await getAssets();
  return assets.find((a) => a.id === id);
}

/* ────────────────────────────────────────────────────────────
 * Synthetic asset generator — Coventra Health Insurance
 * ~800 assets across the zones described in the architecture:
 *   User LAN · Server VLAN · DMZ · Vendor Access · Cloud (AWS/Azure)
 * Deterministic (seeded) so the list is stable across renders.
 * ──────────────────────────────────────────────────────────── */

// Deterministic PRNG
function mulberry32(seed: number) {
  return function () {
    let t = (seed += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

type ZoneSpec = {
  zone: string;
  prefix: string;
  type: Asset["type"];
  deployment: Asset["deployment"];
  ipBase: string;
  count: number;
  osPool: string[];
  rolePool: string[];
  framePool: string[];
  badgePool: string[];
  sens: Asset["dataSensitivity"];
};

const ZONES: ZoneSpec[] = [
  {
    zone: "User LAN",
    prefix: "wks-coventra",
    type: "workstation",
    deployment: "on-prem",
    ipBase: "10.10.",
    count: 380,
    osPool: ["Windows 11 Pro 23H2", "Windows 11 Enterprise", "Windows 10 22H2", "macOS 14 Sonoma"],
    rolePool: ["Claims Adjuster", "Customer Service", "Underwriter", "Member Services", "Billing", "Provider Relations", "HR", "Finance", "Legal", "Compliance Analyst"],
    framePool: ["HIPAA"],
    badgePool: ["Handles Member Data"],
    sens: "internal",
  },
  {
    zone: "Server VLAN",
    prefix: "srv-coventra",
    type: "server",
    deployment: "on-prem",
    ipBase: "10.20.",
    count: 140,
    osPool: ["Ubuntu 22.04 LTS", "RHEL 9.4", "Windows Server 2022", "Oracle Linux 8", "RHEL 8.10"],
    rolePool: ["Claims Processing", "Provider Database", "Eligibility Service", "Authorization Service", "Billing Engine", "Document Repository", "Reporting Server", "Member Database"],
    framePool: ["HIPAA", "SOC2"],
    badgePool: ["Contains PHI", "Business Critical"],
    sens: "confidential",
  },
  {
    zone: "Server VLAN · DB",
    prefix: "db-coventra",
    type: "server",
    deployment: "on-prem",
    ipBase: "10.30.",
    count: 50,
    osPool: ["Oracle Linux 8 / Oracle DB 19c", "Ubuntu 22.04 / PostgreSQL 16", "Windows Server 2022 / MSSQL 2022", "RHEL 9 / MariaDB 10.11"],
    rolePool: ["PHI Database", "Member Database", "Claims Database", "Audit Database", "Analytics Warehouse"],
    framePool: ["HIPAA", "SOC2", "PCI-DSS"],
    badgePool: ["Contains PHI", "Business Critical", "42 CFR Part 2"],
    sens: "restricted",
  },
  {
    zone: "DMZ",
    prefix: "dmz-coventra",
    type: "server",
    deployment: "on-prem",
    ipBase: "172.16.",
    count: 45,
    osPool: ["Ubuntu 22.04 / Nginx", "RHEL 9 / Apache 2.4", "Windows Server 2022 / IIS 10", "Ubuntu 22.04 / HAProxy"],
    rolePool: ["Member Portal", "Provider Portal", "Broker Portal", "Public Website", "API Gateway", "Reverse Proxy", "Email Gateway", "WAF"],
    framePool: ["HIPAA", "PCI-DSS"],
    badgePool: ["Internet-Facing", "Handles Member Data"],
    sens: "confidential",
  },
  {
    zone: "Vendor Access",
    prefix: "ven-coventra",
    type: "server",
    deployment: "on-prem",
    ipBase: "10.40.",
    count: 25,
    osPool: ["Windows Server 2019", "Windows Server 2022", "Ubuntu 20.04 LTS"],
    rolePool: ["EDI / CMS Exchange", "Vendor SFTP", "Vendor VPN Concentrator", "Vendor Relay", "Pharmacy Bridge"],
    framePool: ["HIPAA"],
    badgePool: ["Contains PHI", "Restricted Access"],
    sens: "restricted",
  },
  {
    zone: "Cloud · AWS",
    prefix: "aws-coventra",
    type: "cloud",
    deployment: "cloud",
    ipBase: "172.31.",
    count: 90,
    osPool: ["Amazon Linux 2023", "Ubuntu 22.04 (AMI)", "Windows Server 2022 (AMI)", "AWS RDS · PostgreSQL 16", "AWS S3", "AWS Lambda"],
    rolePool: ["Cloud Claims API", "Data Pipeline", "Encrypted Backup", "Member API", "Analytics Cluster", "Provider API", "Notification Service"],
    framePool: ["HIPAA", "SOC2"],
    badgePool: ["Cloud Service", "Handles Member Data"],
    sens: "confidential",
  },
  {
    zone: "Cloud · Azure",
    prefix: "az-coventra",
    type: "cloud",
    deployment: "cloud",
    ipBase: "10.50.",
    count: 60,
    osPool: ["Windows Server 2022 (Azure)", "Ubuntu 22.04 (Azure)", "Azure SQL Database", "Azure Blob Storage", "Azure App Service"],
    rolePool: ["Power BI Reporting", "Document Storage", "M365 Connector", "Identity Sync", "Backup Vault"],
    framePool: ["HIPAA", "SOC2"],
    badgePool: ["Cloud Service"],
    sens: "confidential",
  },
  {
    zone: "Network",
    prefix: "net-coventra",
    type: "network",
    deployment: "on-prem",
    ipBase: "10.0.",
    count: 30,
    osPool: ["PAN-OS 11.1", "Cisco IOS-XE 17.12", "FortiOS 7.4", "Juniper Junos 23.2", "Aruba ArubaOS 8.11"],
    rolePool: ["Perimeter Firewall", "Core Switch", "Distribution Switch", "Wireless Controller", "VPN Concentrator", "Internal Firewall"],
    framePool: ["HIPAA", "PCI-DSS"],
    badgePool: ["Business Critical"],
    sens: "internal",
  },
];

function pick<T>(rnd: () => number, arr: T[]): T {
  return arr[Math.floor(rnd() * arr.length)];
}

function makeAsset(rnd: () => number, spec: ZoneSpec, idx: number): Asset {
  const seq = String(idx).padStart(4, "0");
  const name = `${spec.prefix}-${seq}`;
  const role = pick(rnd, spec.rolePool);
  const os = pick(rnd, spec.osPool);

  const oct3 = 1 + Math.floor(rnd() * 254);
  const oct4 = 1 + Math.floor(rnd() * 254);
  const ip = spec.deployment === "cloud" && /S3|Blob|Lambda|App Service/.test(os)
    ? "N/A (Cloud)"
    : `${spec.ipBase}${oct3}.${oct4}`;

  // Realistic vuln distribution — most healthy, a tail of warn/crit
  const r = rnd();
  let status: Asset["status"];
  let vulns: Asset["vulnerabilities"];
  let healthScore: number;
  if (r < 0.78) {
    status = "healthy";
    vulns = { critical: 0, high: 0, medium: Math.floor(rnd() * 2), low: Math.floor(rnd() * 3) };
    healthScore = 86 + Math.floor(rnd() * 14);
  } else if (r < 0.95) {
    status = "warning";
    vulns = { critical: 0, high: 1 + Math.floor(rnd() * 2), medium: 1 + Math.floor(rnd() * 3), low: Math.floor(rnd() * 4) };
    healthScore = 65 + Math.floor(rnd() * 18);
  } else {
    status = "critical";
    vulns = { critical: 1 + Math.floor(rnd() * 2), high: 1 + Math.floor(rnd() * 3), medium: 1 + Math.floor(rnd() * 4), low: Math.floor(rnd() * 3) };
    healthScore = 30 + Math.floor(rnd() * 28);
  }

  const lastScannedPool = ["1 hour ago", "2 hours ago", "3 hours ago", "5 hours ago", "yesterday", "1 day ago", "2 days ago"];
  return {
    id: `asset-syn-${idx}`,
    name,
    businessLabel: `${role} (${spec.zone})`,
    type: spec.type,
    status,
    businessRole: role,
    ip,
    os,
    lastScanned: pick(rnd, lastScannedPool),
    healthScore,
    deployment: spec.deployment,
    dataSensitivity: spec.sens,
    vulnerabilities: vulns,
    complianceFrameworks: [...spec.framePool],
    contextBadges: [...spec.badgePool],
  };
}

const SYNTHETIC_ASSETS: Asset[] = (() => {
  const rnd = mulberry32(2026_06_10);
  const out: Asset[] = [];
  let idx = 1;
  for (const spec of ZONES) {
    for (let i = 0; i < spec.count; i++) {
      out.push(makeAsset(rnd, spec, idx++));
    }
  }
  return out;
})();

