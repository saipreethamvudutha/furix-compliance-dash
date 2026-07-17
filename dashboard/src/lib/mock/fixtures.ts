// ============================================================
// Enterprise-grade mock data for the BYOC security dashboard.
// All values are deterministic strings so SSR + CSR match.
// ============================================================

export type Severity = "Critical" | "High" | "Medium" | "Low";

export type DatabaseAsset = {
  id: string;
  name: string;
  engine: "PostgreSQL" | "MySQL" | "MongoDB" | "Redis" | "MSSQL" | "DynamoDB" | "Aurora";
  version: string;
  cloud: "AWS" | "Azure" | "GCP" | "On-Prem";
  region: string;
  ip: string;
  env: "prod" | "staging" | "dev";
  cvssMax: number;
  openFindings: number;
  encryption: "AES-256" | "TLS-only" | "None";
  lastScan: string;
  owner: string;
  tags: string[];
};

export const databaseAssets: DatabaseAsset[] = [
  { id: "DB-0001", name: "phi-db-01",            engine: "PostgreSQL", version: "15.4", cloud: "On-Prem", region: "secure-data-zone", ip: "10.30.1.10",  env: "prod",    cvssMax: 9.1, openFindings: 12, encryption: "AES-256", lastScan: "2026-06-09 04:21", owner: "dba_oracle_01", tags: ["phi", "tier-1"] },
  { id: "DB-0002", name: "member-db-01",         engine: "MSSQL",      version: "2022", cloud: "On-Prem", region: "secure-data-zone", ip: "10.30.2.10",  env: "prod",    cvssMax: 7.4, openFindings: 6,  encryption: "AES-256", lastScan: "2026-06-09 03:55", owner: "dba_mssql_01",  tags: ["pii", "tier-1"] },
  { id: "DB-0003", name: "claims-dw-01",         engine: "MSSQL",      version: "2022", cloud: "On-Prem", region: "secure-data-zone", ip: "10.30.3.10",  env: "prod",    cvssMax: 5.8, openFindings: 3,  encryption: "AES-256", lastScan: "2026-06-09 02:11", owner: "dba_mssql_01",  tags: ["analytics"] },
  { id: "DB-0004", name: "mongo-events-stg",     engine: "MongoDB",    version: "7.0.4", cloud: "AWS",    region: "us-east-2",        ip: "172.31.2.4",  env: "staging", cvssMax: 4.1, openFindings: 1,  encryption: "TLS-only", lastScan: "2026-06-08 22:40", owner: "cloud_ops_aws", tags: [] },
  { id: "DB-0005", name: "redis-rl-cache",       engine: "Redis",      version: "7.2.5", cloud: "AWS",    region: "us-east-1",        ip: "172.31.3.7",  env: "prod",    cvssMax: 6.6, openFindings: 4,  encryption: "TLS-only", lastScan: "2026-06-09 05:02", owner: "devops_jenkins",tags: ["api-gw"] },
  { id: "DB-0006", name: "phi-db-02",            engine: "PostgreSQL", version: "15.4", cloud: "On-Prem", region: "secure-data-zone", ip: "10.30.1.11",  env: "prod",    cvssMax: 8.6, openFindings: 9,  encryption: "AES-256", lastScan: "2026-06-08 18:14", owner: "dba_oracle_01", tags: ["phi", "replica"] },
  { id: "DB-0007", name: "dynamo-sessions",      engine: "DynamoDB",   version: "—",    cloud: "AWS",     region: "us-east-1",        ip: "—",            env: "prod",    cvssMax: 3.2, openFindings: 0,  encryption: "AES-256", lastScan: "2026-06-09 04:48", owner: "cloud_ops_aws", tags: ["serverless"] },
  { id: "DB-0008", name: "audit-log-db",         engine: "PostgreSQL", version: "16.2", cloud: "AWS",    region: "us-east-1",        ip: "172.31.4.3",  env: "prod",    cvssMax: 5.2, openFindings: 2,  encryption: "AES-256", lastScan: "2026-06-09 01:30", owner: "infosec_lead",  tags: ["soc2", "hipaa"] },
  { id: "DB-0009", name: "mongo-dev-sandbox",    engine: "MongoDB",    version: "6.0.9", cloud: "AWS",    region: "us-east-2",        ip: "172.31.99.1", env: "dev",     cvssMax: 2.9, openFindings: 0,  encryption: "TLS-only", lastScan: "2026-06-08 16:00", owner: "devops_jenkins",tags: [] },
  { id: "DB-0010", name: "billing-db-01",        engine: "PostgreSQL", version: "15.4", cloud: "On-Prem", region: "server-vlan",      ip: "10.20.1.21",  env: "prod",    cvssMax: 7.1, openFindings: 5,  encryption: "AES-256", lastScan: "2026-06-09 03:02", owner: "dba_mssql_01",  tags: ["pci", "tier-2"] },
  { id: "DB-0011", name: "provider-db-01",       engine: "MSSQL",      version: "2019", cloud: "On-Prem", region: "server-vlan",      ip: "10.20.1.31",  env: "prod",    cvssMax: 6.0, openFindings: 3,  encryption: "AES-256", lastScan: "2026-06-08 21:18", owner: "dba_mssql_01",  tags: ["provider"] },
  { id: "DB-0012", name: "redis-api-cache",      engine: "Redis",      version: "7.0.11",cloud: "AWS",    region: "us-east-2",        ip: "172.31.3.8",  env: "prod",    cvssMax: 4.7, openFindings: 1,  encryption: "TLS-only", lastScan: "2026-06-09 05:11", owner: "cloud_ops_aws", tags: [] },
];

export type ThreatEvent = {
  ts: string;
  src: string;
  srcIp: string;
  geo: string;
  detection: string;
  mitre: string;
  severity: Severity;
  asset: string;
  confidence: number;
  state: "Open" | "Suppressed" | "Auto-mitigated";
};

export const liveThreats: ThreatEvent[] = [
  { ts: "12:42:18", src: "EDR-Falcon",        srcIp: "203.0.113.42",  geo: "RU",  detection: "Suspicious LSASS access on ad-dc-01",      mitre: "T1003.001", severity: "Critical", asset: "ad-dc-01",          confidence: 96, state: "Open" },
  { ts: "12:41:52", src: "AWS-CloudTrail",    srcIp: "198.51.100.7",  geo: "CN",  detection: "Brute-force on AWS IAM principal",          mitre: "T1110.001", severity: "High",     asset: "iam::coventra-root",  confidence: 88, state: "Open" },
  { ts: "12:40:39", src: "WAF-01",            srcIp: "45.155.205.18", geo: "KP",  detection: "SQLi payload against member portal",        mitre: "T1190",     severity: "Critical", asset: "member-portal-01",   confidence: 99, state: "Auto-mitigated" },
  { ts: "12:38:11", src: "Imperva-DAM",       srcIp: "10.10.1.3",     geo: "—",   detection: "Bulk PHI query from WS-CLM-003",             mitre: "T1213",     severity: "Critical", asset: "phi-db-01",          confidence: 94, state: "Open" },
  { ts: "12:35:02", src: "EDR-CrowdStrike",   srcIp: "10.10.5.2",     geo: "—",   detection: "Process injection (DLL) on WS-IT-002",       mitre: "T1055.001", severity: "High",     asset: "claims-proc-01",     confidence: 91, state: "Open" },
  { ts: "12:32:47", src: "AWS-GuardDuty",     srcIp: "172.31.1.30",   geo: "US",  detection: "Egress to known C2 (Operation Silent Claim)",mitre: "T1071.001", severity: "High",     asset: "ec2-etl-worker",     confidence: 85, state: "Open" },
  { ts: "12:30:14", src: "Palo-Alto-NGFW",    srcIp: "104.244.74.211",geo: "IR",  detection: "DNS tunneling beacon to lookalike domain",   mitre: "T1572",     severity: "Medium",   asset: "fw-perimeter-01",    confidence: 67, state: "Open" },
  { ts: "12:27:00", src: "AWS-CloudTrail",    srcIp: "10.20.1.40",    geo: "—",   detection: "S3 exfil to coventra-phi-backup (200k objects)",mitre: "T1567.002",severity: "Critical", asset: "coventra-phi-backup",confidence: 93, state: "Open" },
  { ts: "12:25:33", src: "Okta-Logs",         srcIp: "82.221.139.4",  geo: "BY",  detection: "Impossible travel (Columbus→Minsk) — cfo_williams", mitre: "T1078.004",severity:"High",  asset: "okta::cfo_williams", confidence: 89, state: "Open" },
  { ts: "12:22:08", src: "AWS-GuardDuty",     srcIp: "10.40.1.10",    geo: "—",   detection: "Crypto-mining XMR traffic on edi-srv-01",     mitre: "T1496",     severity: "High",     asset: "edi-srv-01",         confidence: 82, state: "Suppressed" },
  { ts: "12:18:51", src: "CrowdStrike-Cloud", srcIp: "172.31.1.20",   geo: "—",   detection: "Privileged pod spawn",                       mitre: "T1611",     severity: "Medium",   asset: "ec2-claims-api",     confidence: 71, state: "Open" },
  { ts: "12:15:29", src: "EDR-Falcon",        srcIp: "10.30.6.10",    geo: "—",   detection: "Mimikatz signature near PAM vault",          mitre: "T1003",     severity: "Critical", asset: "pam-vault-01",       confidence: 95, state: "Open" },
];

export type TriageItem = {
  id: string;
  cve: string;
  asset: string;
  proposal: string;
  riskBefore: number;
  riskAfter: number;
  confidence: number;
  blastRadius: "Low" | "Medium" | "High";
  state: "Pending" | "Approved" | "Awaiting Eval" | "Auto-applied";
  eta: string;
  owner: string;
};

export const triageItems: TriageItem[] = [
  { id: "AI-TQ-3201", cve: "CVE-2026-1102", asset: "edi-srv-01",        proposal: "Patch X12 parser + restart EDI service",       riskBefore: 9.2, riskAfter: 2.1, confidence: 96, blastRadius: "Medium", state: "Pending",       eta: "12m", owner: "sysadmin_ops" },
  { id: "AI-TQ-3200", cve: "CVE-2026-0938", asset: "member-portal-01",  proposal: "Rotate JWT signing key + invalidate sessions", riskBefore: 8.1, riskAfter: 1.4, confidence: 91, blastRadius: "Low",    state: "Approved",      eta: "3m",  owner: "infosec_lead" },
  { id: "AI-TQ-3199", cve: "CVE-2025-4471", asset: "billing-db-01",     proposal: "Upgrade Postgres 14.7 → 15.4",                  riskBefore: 7.4, riskAfter: 0.9, confidence: 88, blastRadius: "High",   state: "Awaiting Eval", eta: "—",   owner: "dba_mssql_01" },
  { id: "AI-TQ-3198", cve: "CVE-2025-3210", asset: "claims-dw-01",      proposal: "Enforce TLS 1.3, disable TLS 1.0",              riskBefore: 5.8, riskAfter: 1.2, confidence: 99, blastRadius: "Low",    state: "Auto-applied",  eta: "0m",  owner: "dba_mssql_01" },
  { id: "AI-TQ-3197", cve: "CVE-2026-0214", asset: "ec2-claims-api",    proposal: "Rebuild AMI with patched kernel",               riskBefore: 6.9, riskAfter: 1.0, confidence: 84, blastRadius: "High",   state: "Pending",       eta: "45m", owner: "cloud_ops_aws" },
  { id: "AI-TQ-3196", cve: "CVE-2025-9982", asset: "coventra-phi-backup",proposal:"Apply S3 bucket policy: block public ACL",      riskBefore: 7.1, riskAfter: 0.5, confidence: 99, blastRadius: "Low",    state: "Auto-applied",  eta: "0m",  owner: "cloud_ops_aws" },
  { id: "AI-TQ-3195", cve: "CVE-2025-7741", asset: "redis-rl-cache",    proposal: "Require AUTH + rotate credentials via CyberArk",riskBefore: 4.6, riskAfter: 0.7, confidence: 92, blastRadius: "Medium", state: "Pending",       eta: "8m",  owner: "devops_jenkins" },
  { id: "AI-TQ-3194", cve: "CVE-2026-0050", asset: "ad-dc-01",          proposal: "KRBTGT password reset (×2)",                    riskBefore: 8.6, riskAfter: 1.8, confidence: 87, blastRadius: "High",   state: "Awaiting Eval", eta: "—",   owner: "sysadmin_ops" },
  { id: "AI-TQ-3193", cve: "CVE-2025-6610", asset: "fw-perimeter-01",   proposal: "PAN-OS 11.1.3 → 11.1.5",                         riskBefore: 5.4, riskAfter: 1.1, confidence: 90, blastRadius: "Medium", state: "Pending",       eta: "22m", owner: "netadmin_01" },
  { id: "AI-TQ-3192", cve: "—",             asset: "ec2-etl-worker",    proposal: "Deploy SG default-deny + VPC flow logs",        riskBefore: 4.0, riskAfter: 0.6, confidence: 95, blastRadius: "Low",    state: "Approved",      eta: "5m",  owner: "cloud_ops_aws" },
  { id: "AI-TQ-3191", cve: "CVE-2026-1051", asset: "email-gw-01",       proposal: "Enable DKIM + DMARC reject (Proofpoint)",       riskBefore: 5.1, riskAfter: 0.8, confidence: 98, blastRadius: "Low",    state: "Auto-applied",  eta: "0m",  owner: "infosec_lead" },
  { id: "AI-TQ-3190", cve: "CVE-2025-8800", asset: "phi-db-01",         proposal: "Apply Oracle audit + cap bulk query rate",      riskBefore: 6.3, riskAfter: 1.4, confidence: 86, blastRadius: "Medium", state: "Pending",       eta: "15m", owner: "dba_oracle_01" },
];

export type Volume = {
  id: string;
  title: string;
  asset: string;
  cvss: string;
  framework: string;
  author: string;
  pages: number;
  date: string;
  format: "PDF" | "DOCX" | "HTML";
  size: string;
  status: "Draft" | "Reviewed" | "Published";
};

export const technicalVolumes: Volume[] = [
  { id: "RPT-TV-4821", title: "edi-srv-01 Kernel & Runtime CVE Sweep",       asset: "edi-srv-01",         cvss: "9.2", framework: "CIS",       author: "ai-author@coventra",  pages: 64, date: "2026-06-08", format: "PDF",  size: "4.1 MB", status: "Published" },
  { id: "RPT-TV-4820", title: "member-portal-01 OWASP Top-10 Forensics",     asset: "member-portal-01",   cvss: "8.1", framework: "OWASP",     author: "soc_analyst_03",      pages: 38, date: "2026-06-07", format: "PDF",  size: "2.7 MB", status: "Published" },
  { id: "RPT-TV-4819", title: "phi-db-01 Encryption Review (HSM key audit)", asset: "phi-db-01",          cvss: "9.1", framework: "HIPAA",     author: "ai-author@coventra",  pages: 42, date: "2026-06-07", format: "PDF",  size: "3.0 MB", status: "Reviewed" },
  { id: "RPT-TV-4818", title: "ec2-claims-api Container Hardening",          asset: "ec2-claims-api",     cvss: "6.9", framework: "NSA-K8s",   author: "cloud_ops_aws",       pages: 56, date: "2026-06-06", format: "HTML", size: "1.4 MB", status: "Published" },
  { id: "RPT-TV-4817", title: "ad-dc-01 Kerberos Posture Assessment",        asset: "ad-dc-01",           cvss: "8.6", framework: "MITRE",     author: "ai-author@coventra",  pages: 71, date: "2026-06-05", format: "PDF",  size: "5.6 MB", status: "Published" },
  { id: "RPT-TV-4816", title: "fw-perimeter-01 PAN-OS Firmware Audit",       asset: "fw-perimeter-01",    cvss: "5.4", framework: "NIST",      author: "netadmin_01",         pages: 29, date: "2026-06-05", format: "DOCX", size: "0.9 MB", status: "Draft" },
  { id: "RPT-TV-4815", title: "coventra-phi-backup Public-exposure Sweep",   asset: "coventra-phi-backup",cvss: "7.1", framework: "CIS-AWS",   author: "ai-author@coventra",  pages: 34, date: "2026-06-04", format: "PDF",  size: "2.1 MB", status: "Published" },
  { id: "RPT-TV-4814", title: "claims-dw-01 SOX/SOC2 Evidence Pack",         asset: "claims-dw-01",       cvss: "5.8", framework: "SOC 2",     author: "audit_mgr_01",        pages: 88, date: "2026-06-04", format: "PDF",  size: "6.8 MB", status: "Reviewed" },
  { id: "RPT-TV-4813", title: "redis-rl-cache Auth & TLS Findings",          asset: "redis-rl-cache",     cvss: "6.6", framework: "CIS",       author: "ai-author@coventra",  pages: 22, date: "2026-06-03", format: "HTML", size: "0.7 MB", status: "Published" },
  { id: "RPT-TV-4812", title: "edi-srv-01 End-of-life Migration Plan",       asset: "edi-srv-01",         cvss: "8.6", framework: "ISO 27001", author: "ai-author@coventra",  pages: 47, date: "2026-06-02", format: "PDF",  size: "3.3 MB", status: "Draft" },
  { id: "RPT-TV-4811", title: "ec2-etl-worker IAM Role Review",              asset: "ec2-etl-worker",     cvss: "4.0", framework: "CIS-AWS",   author: "ai-author@coventra",  pages: 19, date: "2026-06-01", format: "HTML", size: "0.5 MB", status: "Reviewed" },
  { id: "RPT-TV-4810", title: "email-gw-01 DMARC/DKIM Posture",              asset: "email-gw-01",        cvss: "5.1", framework: "M3AAWG",    author: "infosec_lead",        pages: 12, date: "2026-05-31", format: "PDF",  size: "0.4 MB", status: "Published" },
];

export type TopRisk = {
  rank: number;
  asset: string;
  cvss: number;
  severity: Severity;
  category: string;
  exposure: "Internet" | "Internal" | "Hybrid";
  exploited: boolean;
  age: string;
  owner: string;
  remediation: string;
};

export const topRisks: TopRisk[] = [
  { rank: 1,  asset: "edi-srv-01",          cvss: 9.2, severity: "Critical", category: "RCE",             exposure: "Hybrid",   exploited: true,  age: "14d", owner: "sysadmin_ops",   remediation: "Patch X12 parser" },
  { rank: 2,  asset: "phi-db-01",           cvss: 9.1, severity: "Critical", category: "Bulk PHI Exfil",  exposure: "Internal", exploited: false, age: "3d",  owner: "dba_oracle_01",  remediation: "Imperva DAM cap + audit" },
  { rank: 3,  asset: "ad-dc-01",            cvss: 8.6, severity: "High",     category: "Kerberos Abuse",  exposure: "Internal", exploited: true,  age: "5d",  owner: "sysadmin_ops",   remediation: "KRBTGT reset ×2" },
  { rank: 4,  asset: "edi-srv-01",          cvss: 8.6, severity: "High",     category: "EoL OS",          exposure: "Hybrid",   exploited: false, age: "62d", owner: "sysadmin_ops",   remediation: "Migrate to Server 2022" },
  { rank: 5,  asset: "member-portal-01",    cvss: 8.1, severity: "High",     category: "SQLi",            exposure: "Internet", exploited: true,  age: "1d",  owner: "infosec_lead",   remediation: "WAF rule + Nginx patch" },
  { rank: 6,  asset: "billing-db-01",       cvss: 7.4, severity: "High",     category: "Unpatched Engine",exposure: "Internal", exploited: false, age: "18d", owner: "dba_mssql_01",   remediation: "Postgres 15.4" },
  { rank: 7,  asset: "coventra-phi-backup", cvss: 7.1, severity: "High",     category: "Public Bucket",   exposure: "Internet", exploited: false, age: "0d",  owner: "cloud_ops_aws",  remediation: "Auto-mitigated (block-public)" },
  { rank: 8,  asset: "ec2-claims-api",      cvss: 6.9, severity: "Medium",   category: "Container Escape",exposure: "Internal", exploited: false, age: "9d",  owner: "cloud_ops_aws",  remediation: "Rebuild AMI" },
  { rank: 9,  asset: "redis-rl-cache",      cvss: 6.6, severity: "Medium",   category: "Auth Missing",    exposure: "Hybrid",   exploited: false, age: "4d",  owner: "devops_jenkins", remediation: "Require AUTH" },
  { rank: 10, asset: "fw-perimeter-01",     cvss: 5.4, severity: "Medium",   category: "Firmware",        exposure: "Internet", exploited: false, age: "27d", owner: "netadmin_01",    remediation: "PAN-OS 11.1.5" },
];
