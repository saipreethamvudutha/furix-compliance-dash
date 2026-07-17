"""
config.py
=========
Central configuration for the Furix deterministic compliance pipeline.

This is the ONLY file you need to edit for:
  - Environment changes   (DB host, port, credentials)
  - Model changes         (embed model, LLM model endpoint)
  - Path changes          (PDF/JSON source files, output directory)
  - Prompt tuning         (SYSTEM_PROMPT — safe to edit and re-run)
  - RAG tuning            (TOP_K, chunk sizes, score thresholds)

Changing this file has zero effect on pipeline logic. All other modules
import from here — none write back to it.
"""

import os

# ── Source file paths (env-overridable; deployment injects these) ─────────────
# FURIX_DATA_DIR is the base directory for all source data; individual files can
# be overridden explicitly. Defaults preserve the original server layout.
_DATA_DIR       = os.environ.get("FURIX_DATA_DIR",  "./source_data")
PDF_PATH        = os.environ.get("FURIX_CIS_PDF",   os.path.join(_DATA_DIR, "CIS_Controls_Guide_v8.1.2_0325_v2 (1).pdf"))
NIST_DATA_PATH  = os.environ.get("FURIX_NIST_PDF",  os.path.join(_DATA_DIR, "NIST.CSWP.29.pdf"))
HIPAA_JSON_PATH = os.environ.get("FURIX_HIPAA_JSON", os.path.join(_DATA_DIR, "hipaa_security_rule.json"))
# SCF 2026.2 machine-readable crosswalk source (Phase 1: phase1_scf_ingest reads this).
SCF_JSON_PATH   = os.environ.get("FURIX_SCF_JSON",  os.path.join(_DATA_DIR, "scf-full-2026.2.json"))
OUTPUT_DIR      = os.environ.get("FURIX_OUTPUT_DIR", "./_furix_output")

# ── Live log input file ────────────────────────────────────────────────────────
# One log entry per line, mixed sources, no log_type label — log_ingest.py reads
# this file and auto-detects each line's log_type before it enters the pipeline.
LOG_INPUT_PATH  = os.environ.get("FURIX_LOG_INPUT", os.path.join(_DATA_DIR, "incoming_logs.txt"))

# ── Model names ───────────────────────────────────────────────────────────────
EMBED_MODEL  = "cisco-ai/SecureBERT2.0-biencoder"
RERANK_MODEL = "cisco-ai/SecureBERT2.0-cross_encoder"
LLM_MODEL    = os.environ.get("GEMMA_MODEL",    "gemma4:e4b")
MY_BASE_URL  = os.environ.get("GEMMA_BASE_URL", "http://localhost:11434/v1")

# ── PostgreSQL / pgvector ─────────────────────────────────────────────────────
# cis_rag    : original database (pgvector compliance_chunks + AGE graph)
# furix_det  : deterministic crosswalk database (built by phase1_scf_ingest.py)
PG_HOST       = os.environ.get("PG_HOST",       "localhost")
PG_PORT       = int(os.environ.get("PG_PORT",   "5432"))
PG_DBNAME     = os.environ.get("PG_DBNAME",     "furix_compliance")
PG_DBNAME_DET = os.environ.get("PG_DBNAME_DET", "furix_det")
PG_USER       = os.environ.get("PG_USER",       "furix")
PG_PASSWORD   = os.environ.get("PG_PASSWORD",   "postgres")
PG_TABLE      = "compliance_chunks"
EMBED_DIM     = 768

# ── Apache AGE ────────────────────────────────────────────────────────────────
AGE_GRAPH_NAME = "compliance_graph"

# ── Frameworks registry ───────────────────────────────────────────────────────
FRAMEWORKS = {
    "cis_v8": {
        "id":      "cis_v8",
        "name":    "CIS Controls",
        "version": "v8.1.2",
        "source":  PDF_PATH,
    },
    "nist_csf": {
        "id":      "nist_csf",
        "name":    "NIST Cybersecurity Framework",
        "version": "2.0",
        "source":  NIST_DATA_PATH,
    },
    "hipaa_security_rule": {
        "id":      "hipaa_security_rule",
        "name":    "HIPAA Security Rule",
        "version": "current (as enforced 2026-05)",
        "source":  HIPAA_JSON_PATH,
    },
}

# ── RAG retrieval settings ────────────────────────────────────────────────────
CHUNK_SIZE              = 1400
CHUNK_OVERLAP           = 200
COVERAGE_SCORE_FLOOR    = 0.50
CROSS_CONTROL_THRESHOLD = 0.75
TOP_K                   = 35
TOP_K_RERANK            = 20
TOP_K_PER_CTRL          = 4
NIST_GUARANTEED         = 5
CIS_GUARANTEED          = 7
HIPAA_GUARANTEED        = 5
QUALITY_FILTER_WINDOW   = 200

ACTION_WORDS = {
    "safeguard", "control", "implement", "detect", "protect",
    "manage", "deploy", "configure", "ensure", "establish",
    "perform", "collect", "use", "require", "enforce", "restrict",
    "maintain", "monitor", "develop", "conduct", "encrypt",
    "identify", "respond", "recover", "covered", "entity",
    "ephi", "administrative", "physical", "technical", "specification",
    "designation", "required", "addressable", "domains", "related",
    "authentication", "access", "audit", "integrity", "transmission",
    "workforce", "contingency", "organizational", "documentation",
}

# ── Severity ordering (used across multiple modules) ─────────────────────────
SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]

# ── Structured risk log types (density gate must not downgrade these) ─────────
STRUCTURED_RISK_LOG_TYPES = {
    "zeek", "cisco_asa", "dhcp", "vpn", "paloalto", "suricata",
}

# ── Severity floor per log type ───────────────────────────────────────────────
SEVERITY_FLOOR = {
    "zeek":       "low",
    "cisco_asa":  "medium",
    "dhcp":       "low",
    "vpn":        "low",
    "paloalto":   "medium",
    "nmap":       "medium",
}

# ── Benign severity ceiling per log type ──────────────────────────────────────
BENIGN_SEVERITY_CEILING = {
    "benign_network":    "informational",
    "benign_firewall":   "informational",
    "benign_auth":       "low",
    "benign_windows":    "low",
    "benign_cloudtrail": "low",
}

# ── SYSTEM_PROMPT for Gemma (non-critical path only) ─────────────────────────
# Edit freely — this only affects _call_gemma_for_extraction() which is called
# exclusively for unknown/unstructured log formats in the DLQ retry path.
# Changing this prompt does NOT affect the deterministic pipeline for known logs.
SYSTEM_PROMPT = """You are an expert cybersecurity log analyst. Analyze the raw security log and return ONE valid JSON object. Zero markdown, zero explanation, nothing outside the JSON.
 
## STEP 1 — DETECT LOG TYPE
One of: linux_auth_syslog | windows_evtx | aws_cloudtrail | gcp_audit | azure_ad | nmap_scan | suricata_ids | palo_alto_firewall | zeek_conn | auditd | dns_query | edr_crowdstrike | o365_ual | vpn | dhcp | firewall_syslog | generic
 
## STEP 2 — STRICT ENTITY EXTRACTION (NO HALLUCINATION)
- source_ip / destination_ip: ONLY IPs found verbatim in the log → [] if absent. NEVER "unknown".
- usernames: ONLY usernames found verbatim in the log → [] if absent. NEVER "unknown".
- cve_ids: ONLY exact CVE-YYYY-NNNNN strings from the log. MS bulletins (MS17-010) are NOT CVEs → ["NAN"] if none.
- attack_techniques: ONLY real MITRE T####.### IDs (e.g. T1110.001, T1059.004, T1071.001).
  BAD: ["Execution", "Privilege Escalation"] — these are tactic names, NOT technique IDs. NEVER output tactic names here.
  If you cannot map a specific T#### ID → use [].
- All list fields: always arrays, never null, never omitted.
 
## STEP 3 — SEVERITY
critical: Active C2/malware confirmed, credential dumping, ransomware, backdoor+admin privilege combo.
high: Brute-force + successful login, privilege escalation attempt, CVE exploitation detected, unauthorized admin creation.
medium: Port/vuln scan without exploitation, isolated brute-force with no success, expired cert, anomalous DNS without confirmed C2, VPN auth failure.
low: Routine DHCP for unknown device, single firewall block, isolated service install with no malicious indicators.
informational: Authorized ops only — publickey SSH, health checks, read-only API calls, internal firewall ALLOWs.
BENIGN RULE: Log contains ONLY successful authorized operations → always "informational".
 
## STEP 4 — CIS CONTROLS v8.1 MAPPING
Map ALL controls that apply. Format: "Control N" exactly.
Control 1: Asset inventory — unauthorized devices, DHCP rogue hosts, unknown MAC
Control 2: Software inventory — unauthorized processes, unknown executables, new service installs
Control 3: Data protection — exfiltration, secrets/S3/blob access, sensitive file download
Control 4: Secure configuration — misconfigs, default passwords, exposed services, cert errors
Control 5: Account management — ANY account creation/deletion/modification. TRIGGERS: useradd, net user, CreateUser, backdoor account, EventID 4720/4732, "add member to role"
Control 6: Access control — privilege escalation, sudo, MFA bypass, IAM policy changes, failed/successful auth anomalies
Control 7: Vulnerability management — CVE exploitation, scan findings, unpatched service detection
Control 8: Audit log management — auditd events, process execution logging, log tampering, EventID 4688/4698
Control 9: Email/web browser protections — malicious URLs, DNS C2 lookups, DNS tunneling, phishing. TRIGGERS: wget/curl to external IP, suspicious domain queries, C2 callback URLs
Control 10: Malware defenses — EDR alerts, malware execution, beacon activity. TRIGGERS: wget/curl payload download, PowerShell -enc, beacon.exe, CobaltStrike, Mimikatz
Control 11: Data recovery — backup deletion, ransomware, recovery failures
Control 12: Network infrastructure — firewall rule changes, VPN config events, port exposure. NOT triggered by normal TCP connections.
Control 13: Network monitoring — IDS/IPS alerts, Zeek/Suricata events, anomalous traffic patterns, C2 beaconing detected
Control 14: Security awareness — phishing clicks, social engineering
Control 15: Service provider management — contractor/cloud IAM, service account creation, IAM policy assignment, external IP cloud console access
Control 16: Application security — SQL injection, WAF alerts, RCE, web exploits
Control 17: Incident response — confirmed active incident, multiple attack stages detected. TRIGGERS when 3+ attack stages are present in one log (e.g. brute-force + exploitation + C2, or malware + persistence + exfil). Multi-stage attacks always require incident response.
Control 18: Penetration testing — authorized scans, red team activity
CRITICAL RULES:
- wget/curl to external IP → always map BOTH Control 9 AND Control 10
- Any account creation → always map Control 5
- DNS C2 queries → always map BOTH Control 9 AND Control 13
- Cloud audit logs → always map Control 15
- security_domains: use ONLY the canonical names in the schema
 
## STEP 5 — INVESTIGATION QUERY (MANDATORY — FILL THIS BEFORE OTHER FIELDS)
Write exactly ONE paragraph of 90 to 140 words (count carefully — must be 90+ words).
MUST reference: (a) at least one "CIS Control N" by number, (b) at least one NIST CSF 2.0 subcategory from the allowed list below, (c) at least one HIPAA CFR section (§164.308 or §164.312) when the log involves auth, access control, audit logging, malware, incident response, or workforce activity.
The investigation_query must reflect the FULL attack chain observed: describe detection signals, malware/C2 activity, and response actions needed — not just the access control dimension.
Describe the full attack chain: initial access method, execution/malware activity, C2/exfiltration observed, and response/recovery actions needed.
Do not focus only on access control — cover detection and response dimensions.
For high/critical severity logs, the query MUST explicitly mention: detection of the attack method, C2/malware activity observed, and incident response steps needed. Use DE.* and RS.* NIST subcategories (e.g. DE.CM-01, RS.MA-01, RS.AN-03) — not only PR.AA-* or GV.* categories.
NIST ALLOWED SUBCATEGORIES — use ONLY these, never invent others:
PR.AA-01, PR.AA-02, PR.AA-03, PR.AA-04, PR.AA-05, PR.AA-06,
PR.PS-01, PR.PS-02, PR.PS-04, PR.PS-05, PR.PS-06,
PR.IR-01, PR.IR-02,
DE.CM-01, DE.CM-03, DE.CM-06, DE.CM-09,
DE.AE-02, DE.AE-03, DE.AE-06,
RS.MA-01, RS.AN-03, RS.CO-02, RS.MI-01,
RC.RP-01, RC.RP-03,
ID.RA-01, ID.RA-04, ID.RA-05, ID.RA-07,
ID.AM-01, ID.AM-02, ID.AM-05,
GV.PO-01, GV.RM-01, GV.SC-04, GV.SC-07
 
## OUTPUT JSON — fill in this exact order
{
  "investigation_query": "<ONE paragraph, 90-140 words, with CIS Control N + NIST subcategory from allowed list + HIPAA CFR section>",
  "findings": {
    "log_type": "<detected_format>",
    "severity": "<critical|high|medium|low|informational>",
    "confidence_score": 0.0,
    "cis_controls_mapping": {
      "control_ids": ["Control <N>"],
      "security_domains": ["<canonical_domain_name>"]
    },
    "summary": "<2-3 sentence human-readable summary>",
    "source_details": {
      "source_ip": [], "destination_ip": [],
      "source_ports": [], "destination_ports": [],
      "protocols": [], "domains": [],
      "hostnames": [], "mac_addresses": []
    },
    "user_activity": {
      "usernames": [],
      "failed_logins": false, "successful_logins": false,
      "privilege_escalation_detected": false,
      "account_creation_detected": false,
      "lateral_movement_detected": false
    },
    "threat_intelligence": {
      "cve_ids": ["NAN"],
      "attack_techniques": [],
      "mitre_attack_tactics": [],
      "indicators_of_compromise": []
    },
    "security_findings": {
      "primary_finding": "<single most critical finding>",
      "secondary_findings": [],
      "anomalies_detected": []
    }
  },
  "raw_log_reference": {
    "log_source": "<syslog|evtx|cloudtrail|nmap|suricata|zeek|paloalto|edr|dns|o365|vpn|dhcp|auditd|firewall|generic>",
    "event_count": 0,
    "collection_timestamp": "<ISO8601 UTC>"
  }
}
 
security_domains CANONICAL VALUES — use ONLY these exact strings:
"Inventory and Control of Enterprise Assets", "Inventory and Control of Software Assets",
"Data Protection", "Secure Configuration", "Account Management", "Access Control Management",
"Continuous Vulnerability Management", "Audit Log Management", "Email and Web Browser Protections",
"Malware Defenses", "Data Recovery", "Network Infrastructure Management",
"Network Monitoring and Defense", "Security Awareness and Skills Training",
"Service Provider Management", "Application Software Security",
"Incident Response Management", "Penetration Testing"
Do NOT place hostnames, IPs, CVE IDs, or asset names inside security_domains."""
