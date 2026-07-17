"""
detection_engine.py
===================
Stage A of the Furix deterministic pipeline — the Findings Engine.

Responsibilities:
  - Threat density pre-filter (compute_threat_density)
  - Deterministic log analysis with regex entity extraction (analyze_log_with_llm)
    Gemma is isolated to _call_gemma_for_extraction(), called ONLY for unknown
    log formats via the DLQ retry path (enrich_with_llm=True).
  - CIS Controls v8.1 mapping via keyword rule engine (run_keyword_detector,
    validate_and_correct_cis_mapping) — authoritative, never overridden by LLM.
  - Severity correction (post_llm_severity_correction, get_benign_severity,
    apply_benign_suppression).
  - Per-control query builder (build_per_control_queries_from_llm) used by
    retrieval_engine.py to scope pgvector queries.

Imports from: config.py, db_connections.py
"""

import re, json, time
from collections import defaultdict

from config import (
    SYSTEM_PROMPT, LLM_MODEL,
    SEVERITY_ORDER, STRUCTURED_RISK_LOG_TYPES, SEVERITY_FLOOR,
    BENIGN_SEVERITY_CEILING,
)
from db_connections import nim_client, CIS_TO_NIST_MAPPINGS

VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}

import json, re

_CVE_PATTERN    = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


# ── Severity coercion ─────────────────────────────────────────────────────────
def _coerce_severity(raw) -> str:
    if isinstance(raw, list):
        raw = raw[0] if raw else "low"
    if not isinstance(raw, str):
        return "low"
    coerced = raw.strip().lower()
    return coerced if coerced in VALID_SEVERITIES else "low"


# ── Sanitize findings ─────────────────────────────────────────────────────────
def _sanitize_findings(findings: dict) -> dict:
    findings["severity"] = _coerce_severity(findings.get("severity"))

    # ── CRITICAL FIX: guarantee all top-level keys always exist ──────────────
    findings.setdefault("source_details",      {})
    findings.setdefault("user_activity",        {})
    findings.setdefault("threat_intelligence",  {})
    findings.setdefault("security_findings",    {})
    findings.setdefault("cis_controls_mapping", {})  # ← THE crash key

    # Guarantee sub-keys within cis_controls_mapping
    cis = findings["cis_controls_mapping"]
    cis.setdefault("control_ids",    [])
    cis.setdefault("safeguard_ids",  [])
    cis.setdefault("security_domains", [])

    # Guarantee sub-keys within user_activity (used by HIPAA mapper)
    ua_defaults = {
        "usernames": [], "failed_logins": False, "successful_logins": False,
        "privilege_escalation_detected": False, "account_creation_detected": False,
        "lateral_movement_detected": False,
    }
    for k, v in ua_defaults.items():
        findings["user_activity"].setdefault(k, v)

    # Guarantee sub-keys within threat_intelligence
    ti_defaults = {
        "cve_ids": ["NAN"], "attack_techniques": [],
        "mitre_attack_tactics": [], "indicators_of_compromise": [],
    }
    for k, v in ti_defaults.items():
        findings["threat_intelligence"].setdefault(k, v)

    # Cross-populate: if attack_techniques contains tactic names (LLM non-compliance),
    # move them to mitre_attack_tactics and clear attack_techniques
    _TACTIC_NAMES = {
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact", "Reconnaissance"
    }
    ti = findings["threat_intelligence"]
    techniques = ti.get("attack_techniques", [])
    tactic_hits    = [t for t in techniques if t in _TACTIC_NAMES]
    technique_hits = [t for t in techniques if t not in _TACTIC_NAMES]
    if tactic_hits:
        existing_tactics = ti.get("mitre_attack_tactics", [])
        ti["mitre_attack_tactics"] = list(dict.fromkeys(existing_tactics + tactic_hits))
        ti["attack_techniques"]    = technique_hits
        # Enforce: mitre_attack_tactics must only contain tactic names, not T#### IDs
        # Enforce: attack_techniques must only contain T####.### IDs, not tactic names
        _TECHNIQUE_RE = re.compile(r'^T\d{4}(\.\d{3})?$')
        raw_tactics = ti.get("mitre_attack_tactics", [])
        raw_techniques = ti.get("attack_techniques", [])
        # Move any T#### IDs found in tactics → techniques
        promoted_techniques = [t for t in raw_tactics if _TECHNIQUE_RE.match(t)]
        clean_tactics       = [t for t in raw_tactics if not _TECHNIQUE_RE.match(t)]
        # Keep only valid tactic names (must be in _TACTIC_NAMES)
        ti["mitre_attack_tactics"] = [t for t in clean_tactics if t in _TACTIC_NAMES]
        ti["attack_techniques"]    = list(dict.fromkeys(
            [t for t in raw_techniques if _TECHNIQUE_RE.match(t)] + promoted_techniques
        ))

    sd = findings.get("source_details", {})
    for field in ("source_ip", "destination_ip"):
        sd[field] = list(dict.fromkeys(
            v for v in sd.get(field, [])
            if isinstance(v, str) and v.lower() != "unknown"
        ))
    ua = findings.get("user_activity", {})
    ua["usernames"] = list(dict.fromkeys(
        v for v in ua.get("usernames", [])
        if isinstance(v, str) and v.lower() != "unknown"
    ))
    ti = findings.get("threat_intelligence", {})
    raw_cves   = ti.get("cve_ids", ["NAN"])
    valid_cves = [c for c in raw_cves if isinstance(c, str) and
                  (c.upper() == "NAN" or _CVE_PATTERN.match(c))]
    ti["cve_ids"] = valid_cves if valid_cves else ["NAN"]
    return findings


# ── Fallback query builder ────────────────────────────────────────────────────
def _build_fallback_query(findings: dict) -> str:
    f   = findings
    sd  = f.get("source_details", {})
    sf  = f.get("security_findings", {})
    cis = f.get("cis_controls_mapping", {})
    ti  = f.get("threat_intelligence", {})
    parts = []
    if sf.get("primary_finding"):
        parts.append(sf["primary_finding"])
    if sd.get("source_ip"):
        parts.append(f"Source IP(s): {', '.join(sd['source_ip'])}.")
    if sd.get("destination_ports"):
        parts.append(f"Destination ports: {sd['destination_ports']}.")
    if sd.get("protocols"):
        parts.append(f"Protocols: {', '.join(sd['protocols'])}.")
    if ti.get("mitre_attack_tactics"):
        parts.append(f"MITRE ATT&CK tactics: {', '.join(ti['mitre_attack_tactics'])}.")
    if ti.get("attack_techniques"):
        parts.append(f"Techniques: {', '.join(ti['attack_techniques'])}.")
    if cis.get("security_domains"):
        parts.append(f"Relevant CIS security domains: {', '.join(cis['security_domains'])}.")
    if cis.get("control_ids"):
        parts.append(f"CIS Controls to review: {', '.join(cis['control_ids'])}.")
    parts.append(f"Log format: {f.get('log_type', 'unknown')}.")
    return " ".join(parts) if parts else (
        f"Security event detected in {f.get('log_type', 'unknown')} log "
        f"requiring investigation of relevant CIS Controls v8.1 safeguards."
    )


# ── Fix 1: Truncation repair ──────────────────────────────────────────────────
def _repair_truncated_json(text: str) -> str:
    """
    Attempt to close a truncated JSON string so json.loads() can recover it.
    Handles the most common truncation patterns from Gemma 3n:
    - String value cut mid-sentence (unclosed quote)
    - Object/array not closed (missing }} or ]])
    Works by counting opens vs closes and appending what's missing.
    """
    # Strip to the outermost { ... } region
    start = text.find("{")
    if start == -1:
        return text
    text = text[start:]

    # Close any open string — find last unescaped quote parity
    in_string   = False
    escape_next = False
    for ch in text:
        if escape_next:
            escape_next = False
            continue
        if ch == "\\":
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string

    if in_string:
        text += '"'   # close the open string

    # Now count open braces and brackets to close them
    depth_brace  = 0
    depth_bracket = 0
    in_string    = False
    escape_next  = False
    for ch in text:
        if escape_next:
            escape_next = False
            continue
        if ch == "\\":
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth_brace += 1
        elif ch == "}":
            depth_brace -= 1
        elif ch == "[":
            depth_bracket += 1
        elif ch == "]":
            depth_bracket -= 1

    # Close in reverse order: first brackets, then braces
    text += "]" * max(0, depth_bracket)
    text += "}" * max(0, depth_brace)
    return text


# ── Fix 2: Multi-strategy JSON parser ────────────────────────────────────────
def _parse_llm_json(raw_text: str) -> tuple:
    """
    Try 4 strategies in order to extract valid JSON from LLM output.
    Returns (parsed_dict, error_message_or_None, strategy_used).

    Strategy 1 — Direct parse after stripping markdown fences
    Strategy 2 — Extract outermost {...} and parse
    Strategy 3 — Repair truncation then parse
    Strategy 4 — Field-by-field regex extraction (last resort)
    """
    # Strip markdown fences
    clean = re.sub(r"^```(?:json)?\s*", "", raw_text, flags=re.MULTILINE)
    clean = re.sub(r"\s*```$",           "", clean,    flags=re.MULTILINE).strip()

    # Strategy 1 — direct parse
    try:
        return json.loads(clean), None, "direct"
    except json.JSONDecodeError:
        pass

    # Strategy 2 — extract outermost braces
    m = re.search(r"(\{[\s\S]*\})", clean)
    if m:
        try:
            return json.loads(m.group(1)), None, "brace_extract"
        except json.JSONDecodeError:
            pass

    # Strategy 3 — repair truncation then parse
    repaired = _repair_truncated_json(clean)
    try:
        parsed = json.loads(repaired)
        return parsed, None, "truncation_repair"
    except json.JSONDecodeError:
        pass

    # Strategy 4 — field-by-field regex extraction
    # Extracts whatever fields are present even from badly truncated JSON.
    # Enough to build findings + fallback query without aborting.
    partial = {}
    def _rx(pattern, text, default=None):
        m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        return m.group(1).strip().strip('"') if m else default

    # Top-level scalar fields
    lt  = _rx(r'"log_type"\s*:\s*"([^"]+)"',       clean)
    sev = _rx(r'"severity"\s*:\s*"([^"]+)"',        clean)
    sum_ = _rx(r'"summary"\s*:\s*"([^"\\]*)',        clean)  # up to first escape
    cf  = _rx(r'"confidence_score"\s*:\s*([\d.]+)', clean)
    pf  = _rx(r'"primary_finding"\s*:\s*"([^"\\]*)', clean)
    iq  = _rx(r'"investigation_query"\s*:\s*"([^"\\]*)', clean)

    # List fields — grab whatever items were emitted before truncation
    def _rx_list(key, text):
        m = re.search(rf'"{key}"\s*:\s*\[([^\]]*)', text, re.DOTALL)
        if not m:
            return []
        raw = m.group(1)
        return [s.strip().strip('"') for s in re.findall(r'"([^"]+)"', raw)]

    ctrl_ids   = _rx_list("control_ids",          clean)
    sfg_ids    = _rx_list("safeguard_ids",         clean)
    tactics    = _rx_list("mitre_attack_tactics",  clean)
    techniques = _rx_list("attack_techniques",     clean)
    src_ips    = _rx_list("source_ip",             clean)
    usernames  = _rx_list("usernames",             clean)
    cve_ids    = _rx_list("cve_ids",               clean) or ["NAN"]

    # Reassemble into the expected findings schema
    partial = {
        "findings": {
            "log_type":         lt  or "generic",
            "severity":         sev or "medium",
            "confidence_score": float(cf) if cf else 0.3,
            "summary":          sum_ or "Partial parse — see raw log.",
            "source_details": {
                "source_ip":         src_ips,
                "destination_ip":    [],
                "destination_ports": [],
                "protocols":         [],
            },
            "user_activity": {
                "usernames":                    usernames,
                "privilege_escalation_detected": bool(re.search(
                    r"privilege.escal|sudo|SeBackup", clean, re.IGNORECASE)),
            },
            "threat_intelligence": {
                "cve_ids":             cve_ids,
                "mitre_attack_tactics": tactics,
                "attack_techniques":    techniques,
            },
            "cis_controls_mapping": {
                "control_ids":    ctrl_ids,
                "safeguard_ids":  sfg_ids,
                "security_domains": [],
            },
            "security_findings": {
                "primary_finding":            pf or sum_ or "",
                "behavioral_indicators":      [],
                "anomaly_indicators":         [],
            },
        },
        "investigation_query":  iq or "",
        "raw_log_reference":    {},
    }
    # Tag the partial findings so severity correction knows it's a fallback
    partial["findings"]["_degraded_parse"] = True
    err = f"Partial parse via regex extraction (strategies 1–3 failed)"
    return partial, err, "regex_extraction"

# %%
# ── Deterministic log analyzer (Phase 2) ─────────────────────────────────────
# Gemma is NO LONGER on the critical path.
# analyze_log_with_llm() now returns a deterministic skeleton built entirely
# from the keyword detector, threat density signals, and the SCF crosswalk.
# Gemma is only called when enrich_with_llm=True, which is set ONLY by the
# DLQ unknown-format handler and the narrative summary generator.
# The SYSTEM_PROMPT, _repair_truncated_json, and _parse_llm_json are kept
# for the Gemma call path so they continue to work when invoked.

def _call_gemma_for_extraction(raw_log: str, verbose: bool = True) -> dict:
    """
    Internal: calls Gemma for unstructured log extraction.
    Only used when enrich_with_llm=True is passed to analyze_log_with_llm().
    Returns the same dict shape as the old analyze_log_with_llm() for
    compatibility with the DLQ retry path.
    """
    sep = "=" * 72
    if verbose:
        print(f"\n{sep}")
        print(f"  [GEMMA] UNSTRUCTURED LOG EXTRACTION  |  {LLM_MODEL}")
        print(sep)
        print(f"  Log size   : {len(raw_log.splitlines())} lines / {len(raw_log)} chars")

    raw_text = ""
    for _attempt in range(3):
        try:
            response = nim_client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": f"Analyze this raw security log:\n\n{raw_log}"}
                ],
                temperature=0.1 + (_attempt * 0.05),
                max_tokens=4000,
                response_format={"type": "json_object"},
            )
            raw_text      = (response.choices[0].message.content or "").strip()
            finish_reason = response.choices[0].finish_reason
            if raw_text and finish_reason == "stop":
                break
            if raw_text and finish_reason is None:
                _repaired = _repair_truncated_json(raw_text)
                try:
                    json.loads(_repaired)
                    break
                except json.JSONDecodeError:
                    pass
            if verbose:
                print(f"  ⚠️  Attempt {_attempt + 1}: finish={finish_reason}, retrying...")
            time.sleep(1.0)
        except Exception as e:
            print(f"[GEMMA ERROR] API call failed (attempt {_attempt + 1}): {e}")
            if _attempt == 2:
                return {"findings": {}, "investigation_query": "",
                        "raw_log_reference": {}, "_raw_response": "",
                        "_parse_error": str(e), "_query_fallback_used": False,
                        "_source": "gemma_failed"}
            time.sleep(2.0)

    parsed, parse_error, strategy = _parse_llm_json(raw_text)
    findings            = parsed.get("findings",            {})
    investigation_query = parsed.get("investigation_query", "")
    raw_log_reference   = parsed.get("raw_log_reference",  {})

    if findings:
        findings = _sanitize_findings(findings)

    query_fallback_used = False
    MIN_QUERY_WORDS = 90
    if findings and len(investigation_query.split()) < MIN_QUERY_WORDS:
        investigation_query = _build_fallback_query(findings)
        query_fallback_used = True

    if verbose:
        if parse_error:
            print(f"  ⚠️  JSON parse degraded (strategy: {strategy}): {parse_error}")
        else:
            print(f"  ✅ Gemma extraction parsed (strategy: {strategy})")

    return {
        "findings":             findings,
        "investigation_query":  investigation_query,
        "raw_log_reference":    raw_log_reference,
        "_raw_response":        raw_text,
        "_parse_error":         parse_error,
        "_parse_strategy":      strategy,
        "_query_fallback_used": query_fallback_used,
        "_source":              "gemma",
    }


def analyze_log_with_llm(
    raw_log: str,
    verbose:         bool = True,
    log_type:        str  = "auto",
    enrich_with_llm: bool = False,
) -> dict:
    """
    Phase 2 deterministic analyzer.

    Critical path (enrich_with_llm=False, the default):
      - Builds findings skeleton from keyword detector + threat density signals.
      - NO Gemma call. No latency. No JSON repair. No truncation risk.
      - investigation_query built from _build_fallback_query() over deterministic findings.
      - This is the path used for ALL 25 known log types in run_full_pipeline().

    Non-critical path (enrich_with_llm=True):
      - Calls Gemma for entity extraction on unknown/unstructured log formats.
      - Used ONLY by the DLQ unknown-format handler.
      - Gemma output is MERGED into the deterministic skeleton, never replaces it.
      - CIS mapping from Gemma is DISCARDED — validate_and_correct_cis_mapping()
        always runs afterward and is authoritative.
    """
    sep = "=" * 72

    # ── Build deterministic findings skeleton ─────────────────────────────────
    # severity starts at "low" and is raised by threat density and content rules
    # in post_llm_severity_correction() and the density gate — both run after this.
    det_findings = {
        "log_type":         log_type,
        "severity":         "low",
        "confidence_score": 0.95,
        "summary":          f"Deterministic analysis of {log_type} log.",
        "source_details": {
            "source_ip":         [],
            "destination_ip":    [],
            "source_ports":      [],
            "destination_ports": [],
            "protocols":         [],
            "domains":           [],
            "hostnames":         [],
            "mac_addresses":     [],
        },
        "user_activity": {
            "usernames":                     [],
            "failed_logins":                 False,
            "successful_logins":             False,
            "privilege_escalation_detected": False,
            "account_creation_detected":     False,
            "lateral_movement_detected":     False,
        },
        "threat_intelligence": {
            "cve_ids":              ["NAN"],
            "attack_techniques":    [],
            "mitre_attack_tactics": [],
            "indicators_of_compromise": [],
        },
        "cis_controls_mapping": {
            "control_ids":     [],
            "safeguard_ids":   [],
            "security_domains":[],
        },
        "security_findings": {
            "primary_finding":     "",
            "secondary_findings":  [],
            "anomalies_detected":  [],
        },
    }

    # ── Deterministic entity extraction from raw log ───────────────────────────
    # Extract IPs, usernames, CVEs, and key flags directly with regex.
    # This replaces the LLM entity extraction for known log formats.

    # IPs
    _ip_re = re.compile(
        r'(?:src|source|from|client|src_ip|sourceIPAddress|ipAddress|'
        r'RemoteAddressIP4|callerIp)\s*[=:"\s]+([0-9]{1,3}(?:\.[0-9]{1,3}){3})',
        re.IGNORECASE
    )
    _ip_bare = re.compile(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3})')
    src_ips = list(dict.fromkeys(_ip_re.findall(raw_log)))
    if not src_ips:
        # Fallback: grab all IPs, limit to 5 to avoid noise
        src_ips = list(dict.fromkeys(_ip_bare.findall(raw_log)))[:5]
    det_findings["source_details"]["source_ip"] = src_ips

    # CVEs
    cve_hits = list(dict.fromkeys(
        re.findall(r'CVE-\d{4}-\d{4,}', raw_log, re.IGNORECASE)
    ))
    det_findings["threat_intelligence"]["cve_ids"] = cve_hits if cve_hits else ["NAN"]

    # Usernames — common log patterns
    _user_re = re.compile(
        r'(?:user|username|userName|UserId|account|acct|srcuser)\s*[=:"\s]+([A-Za-z0-9._@\-]{2,64})',
        re.IGNORECASE
    )
    usernames = list(dict.fromkeys(
        u for u in _user_re.findall(raw_log)
        if u.lower() not in ('null','none','unknown','nan','true','false','root','system')
    ))
    det_findings["user_activity"]["usernames"] = usernames[:10]

    # Boolean flags from threat patterns
    if re.search(r'failed password|authentication fail|eventid:\s*4625|res=failed', raw_log, re.I):
        det_findings["user_activity"]["failed_logins"] = True
    if re.search(r'accepted publickey|logon.*success|consollogin.*success|res=success', raw_log, re.I):
        det_findings["user_activity"]["successful_logins"] = True
    if re.search(r'privilege.escal|sudo|SeBackup|key="priv_esc"', raw_log, re.I):
        det_findings["user_activity"]["privilege_escalation_detected"] = True
    # Okta: Super Administrator grant = privilege escalation
    if re.search(r'user\.account\.privilege\.grant|privilegeGranted.*Super.Admin|Super.Administrator', raw_log, re.I):
        det_findings["user_activity"]["privilege_escalation_detected"] = True
    if re.search(r'useradd|net user.*\/add|createuser|eventid:\s*4720|a user account was created', raw_log, re.I):
        det_findings["user_activity"]["account_creation_detected"] = True
    # Okta: provision user with backdoor target = account creation
    if re.search(r'application\.provision\.user|Backdoor Account|backdoor@', raw_log, re.I):
        det_findings["user_activity"]["account_creation_detected"] = True
    if re.search(r'lateral.move|smb.lateral|pass.the.hash', raw_log, re.I):
        det_findings["user_activity"]["lateral_movement_detected"] = True

    # Primary finding — first high-signal threat sentence or fallback
    threat_lines = [
        ln.strip() for ln in raw_log.splitlines()
        if any(t in ln.lower() for t in (
            'cve-', 'mimikatz', 'cobalt', 'beacon', 'payload', 'backdoor',
            'exploit', 'malware', 'injection', 'escalat', 'brute', 'failed password'
        ))
    ]
    det_findings["security_findings"]["primary_finding"] = (
        threat_lines[0][:200] if threat_lines else f"{log_type} security event detected."
    )

    # ── Gemma enrichment (non-critical path only) ─────────────────────────────
    gemma_result = None
    if enrich_with_llm:
        if verbose:
            print(f"  [analyze] Calling Gemma for unstructured extraction (log_type={log_type})")
        gemma_result = _call_gemma_for_extraction(raw_log, verbose=verbose)
        g_findings   = gemma_result.get("findings", {})

        if g_findings:
            # Merge Gemma entity extraction into deterministic skeleton
            # Rule: deterministic values win on conflicts; Gemma fills empties only.
            g_sd = g_findings.get("source_details", {})
            g_ua = g_findings.get("user_activity",  {})
            g_ti = g_findings.get("threat_intelligence", {})
            g_sf = g_findings.get("security_findings", {})

            if g_sd.get("source_ip") and not det_findings["source_details"]["source_ip"]:
                det_findings["source_details"]["source_ip"] = g_sd["source_ip"]
            if g_ua.get("usernames") and not det_findings["user_activity"]["usernames"]:
                det_findings["user_activity"]["usernames"] = g_ua["usernames"]
            for flag in ("failed_logins","successful_logins","privilege_escalation_detected",
                         "account_creation_detected","lateral_movement_detected"):
                if g_ua.get(flag):
                    det_findings["user_activity"][flag] = True
            if g_ti.get("cve_ids") and g_ti["cve_ids"] != ["NAN"]:
                existing = det_findings["threat_intelligence"]["cve_ids"]
                merged_cves = list(dict.fromkeys(
                    ([c for c in existing if c != "NAN"] if existing != ["NAN"] else [])
                    + g_ti["cve_ids"]
                ))
                det_findings["threat_intelligence"]["cve_ids"] = merged_cves or ["NAN"]
            if g_ti.get("attack_techniques"):
                det_findings["threat_intelligence"]["attack_techniques"] = g_ti["attack_techniques"]
            if g_ti.get("mitre_attack_tactics"):
                det_findings["threat_intelligence"]["mitre_attack_tactics"] = g_ti["mitre_attack_tactics"]
            if g_sf.get("primary_finding") and not det_findings["security_findings"]["primary_finding"]:
                det_findings["security_findings"]["primary_finding"] = g_sf["primary_finding"]
            # CRITICAL: CIS mapping from Gemma is intentionally NOT merged here.
            # validate_and_correct_cis_mapping() is always authoritative.

    # ── Sanitize and build investigation query ────────────────────────────────
    det_findings = _sanitize_findings(det_findings)
    investigation_query = _build_fallback_query(det_findings)

    if verbose:
        sep_short = "-" * 72
        print(f"\n{sep_short}")
        print(f"  DETERMINISTIC ANALYSIS  |  log_type: {log_type.upper()}")
        print(f"{sep_short}")
        print(f"  Source IPs  : {det_findings['source_details']['source_ip']}")
        print(f"  Usernames   : {det_findings['user_activity']['usernames']}")
        print(f"  CVEs        : {det_findings['threat_intelligence']['cve_ids']}")
        print(f"  Priv Esc    : {det_findings['user_activity']['privilege_escalation_detected']}")
        print(f"  Acct Create : {det_findings['user_activity']['account_creation_detected']}")
        source_tag = "[GEMMA+DET]" if enrich_with_llm and gemma_result else "[DET]"
        print(f"  Source      : {source_tag}")
        print(f"{sep_short}\n")

    return {
        "findings":             det_findings,
        "investigation_query":  investigation_query,
        "raw_log_reference":    {},
        "_raw_response":        "",
        "_parse_error":         None,
        "_parse_strategy":      "deterministic",
        "_query_fallback_used": True,
        "_source":              "deterministic",
    }


print("✅ Phase 2: analyze_log_with_llm() is now deterministic")
print("   Gemma is OFF the critical path.")
print("   enrich_with_llm=True enables Gemma only for unknown formats (DLQ path).")

# %%
# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6 — Deterministic CIS Validator / Corrector (Phase 1d)
# ─────────────────────────────────────────────────────────────────────────────

DOMAIN_CONTROL_MAP: dict = {
    "Vulnerability Management":                   ["Control 7"],
    "Network Security":                           ["Control 12", "Control 13"],
    "Network Monitoring":                         ["Control 13"],
    "Network Monitoring and Defense":             ["Control 13"],
    "Network Infrastructure":                     ["Control 12"],
    "Network Infrastructure Management":          ["Control 12"],
    "Inventory and Control of Enterprise Assets": ["Control 1"],
    "Asset Inventory":                            ["Control 1"],
    "Software Asset Management":                  ["Control 2"],
    "Software Inventory":                         ["Control 2"],
    "Account Management":                         ["Control 5"],
    "Access Control":                             ["Control 6"],
    "Access Control Management":                  ["Control 6"],
    "Audit Log Management":                       ["Control 8"],
    "Audit Logging":                              ["Control 8"],
    "Malware Defenses":                           ["Control 10"],
    "Malware Defense":                            ["Control 10"],
    "Data Protection":                            ["Control 3"],
    "Secure Configuration":                       ["Control 4"],
    "Application Software Security":              ["Control 16"],
    "Application Security":                       ["Control 16"],
    "Incident Response":                          ["Control 17"],
    "Incident Response Management":               ["Control 17"],
    "Email and Web Browser Protections":          ["Control 9"],
    "Email/Web Browser Protections":              ["Control 9"],
    "Email Web Browser":                          ["Control 9"],
    "Web Browser Protections":                    ["Control 9"],
    "Data Recovery":                              ["Control 11"],
    "Security Awareness":                         ["Control 14"],
    "Security Awareness Training":                ["Control 14"],
    "Service Provider Management":                ["Control 15"],
    "Penetration Testing":                        ["Control 18"],
}

KEYWORD_CONTROL_MAP: dict = {
    # ── Control 1 — Asset Inventory ──────────────────────────────────────────
    # TIGHTENED: require specific DHCP discovery phrases, not just "rogue"
    "dhcpdiscover from":              [("Control 1", 2)],
    "dhcpoffer on":                   [("Control 1", 2)],
    "unknown client":                 [("Control 1", 2)],
    "nmap scan report for":           [("Control 1", 2), ("Control 7", 2)],
    "host is up":                     [("Control 1", 1), ("Control 7", 1)],
    "rogue device":                   [("Control 1", 2)],
    "rogue-device":                   [("Control 1", 2)],

    # ── Control 2 — Software Inventory ───────────────────────────────────────
    # TIGHTENED: "mimikatz" and "evil.exe" are specific enough; "7045" kept
    "mimikatz":                       [("Control 2", 2), ("Control 10", 2)],
    "evil.exe":                       [("Control 2", 2), ("Control 10", 2)],
    "new service was installed":      [("Control 2", 2)],
    "eventid: 7045":                  [("Control 2", 2), ("Control 10", 2)],

    # ── Control 3 — Data Protection ──────────────────────────────────────────
    "getsecretvalue":                 [("Control 3", 2)],
    "secretsmanager":                 [("Control 3", 2)],
    "deletebucket":                   [("Control 3", 2)],
    "filedownloaded":                 [("Control 3", 2)],
    "sensitive_employee":             [("Control 3", 2)],
    # TIGHTENED: "sharepoint" alone was too broad — require sensitive context
    "sharepoint.com/sites":           [("Control 3", 2)],

    # ── Control 4 — Secure Configuration ─────────────────────────────────────
    "certificate has expired":        [("Control 4", 2)],
    "verify error: depth":            [("Control 4", 2)],
    # TIGHTENED: removed "misconfigur" (too generic), kept specific phrases
    "ftp-anon":                       [("Control 4", 2)],
    "anonymous ftp login":            [("Control 4", 2)],
    # TIGHTENED: "possible syn" → full phrase; "dpt=22/dpt=445" removed (too generic)
    "possible syn flooding":          [("Control 4", 2), ("Control 13", 2)],
    "syn scan detected":              [("Control 4", 2), ("Control 13", 2)],

    # ── Control 5 — Account Management ───────────────────────────────────────
    "eventid: 4720":                  [("Control 5", 2)],
    "eventid: 4732":                  [("Control 5", 2)],
    "a user account was created":     [("Control 5", 2)],
    "backdoor_user":                  [("Control 5", 2)],
    "backdoor_admin":                 [("Control 5", 2)],
    "net user backdoor":              [("Control 5", 2)],
    "net localgroup administrators":  [("Control 5", 2), ("Control 6", 2)],
    "add member to role":             [("Control 5", 2), ("Control 6", 2)],

    # ── Control 6 — Access Control ───────────────────────────────────────────
    "eventid: 4625":                  [("Control 6", 2), ("Control 5", 1)],
    # TIGHTENED: "failed password for invalid user" not just "failed password"
    "failed password for invalid user": [("Control 6", 2), ("Control 5", 1)],
    "failed password for root":       [("Control 6", 2)],
    "eventid: 4672":                  [("Control 6", 2)],
    "privilege escalation attempt":   [("Control 6", 2)],
    # TIGHTENED: "mfaused":"no" not just "mfaused"
    "\"mfaused\":\"no\"":             [("Control 6", 2)],
    "sudo":                           [("Control 6", 2)],
    "key=\"priv_esc\"":               [("Control 6", 2)],
    "attachuserpolicy":               [("Control 6", 2)],
    "administratoraccess":            [("Control 6", 2)],
    "aaa user authentication":        [("Control 6", 2)],

    # ── Control 7 — Vulnerability Management ─────────────────────────────────
    "cve-":                           [("Control 7", 2)],
    "vulnerable":                     [("Control 7", 2)],
    "eternalblue":                    [("Control 7", 2)],
    "ms17-010":                       [("Control 7", 2)],
    "bod 22-01":                      [("Control 7", 2)],
    # TIGHTENED: "/tcp   open" was firing on any open port — now more specific
    "open  http":                     [("Control 7", 1), ("Control 4", 1)],
    "open  ssh":                      [("Control 7", 1), ("Control 4", 1)],
    "open  ms-wbt-server":            [("Control 7", 1), ("Control 12", 1)],
    "open  microsoft-ds":             [("Control 12", 1)],
    "open  mysql":                    [("Control 7", 2), ("Control 12", 1)],
    "open  postgresql":               [("Control 7", 2), ("Control 12", 1)],

    # ── Control 8 — Audit Log Management ─────────────────────────────────────
    "type=syscall":                   [("Control 8", 2)],
    "type=execve":                    [("Control 8", 2)],
    "type=user_auth":                 [("Control 8", 2)],
    "msg=audit(":                     [("Control 8", 2)],
    # TIGHTENED: "auditd" alone removed — require full auditd phrase
    "auditd[":                        [("Control 8", 2)],
    "eventid: 4698":                  [("Control 8", 2), ("Control 10", 1)],
    "eventid: 4688":                  [("Control 8", 2)],

    # ── Control 9 — Email & Web Browser Protections ──────────────────────────
    # TIGHTENED: "malware-c2.ru" specific domain kept; generic "malware" removed
    "malware-c2.ru":                  [("Control 9", 2), ("Control 13", 2)],
    "redirectmessageto":              [("Control 9", 2)],
    "set-transportrule":              [("Control 9", 2)],
    # TIGHTENED: bare "smtp/imap/pop3" removed — require blocked/alert context
    "smtp blocked":                   [("Control 9", 1), ("Control 12", 1)],

    # ── Control 10 — Malware Defenses ────────────────────────────────────────
    "cobaltstrikebeacon":             [("Control 10", 2)],
    "et malware cobalt":              [("Control 10", 2)],
    # TIGHTENED: "beacon" alone removed — too generic; use specific signatures
    "beacon checkin":                 [("Control 10", 2)],
    "malware command and control":    [("Control 10", 2), ("Control 13", 2)],
    # TIGHTENED: "wget" alone removed — require suspicious download pattern
    "wget -q http":                   [("Control 10", 2)],
    "wget.*payload":                  [("Control 10", 2)],
    "/tmp/payload.sh":                [("Control 10", 2)],
    "powershell -enc":                [("Control 10", 2), ("Control 8", 2)],
    "processrollup2":                 [("Control 10", 2), ("Control 8", 2)],
    "c2.malicious-domain":            [("Control 10", 2), ("Control 13", 2)],
    # TIGHTENED: "-c2-" and "c2-" removed — too short and ambiguous
    "stage2":                         [("Control 10", 2)],

    # ── Control 12 — Network Infrastructure Management ───────────────────────
    "openvpn[":                       [("Control 12", 2)],
    "anyconnect:":                    [("Control 12", 2)],
    # TIGHTENED: "ufw block" kept; bare "proto=tcp" removed (fires on everything)
    "ufw block":                      [("Control 12", 2), ("Control 13", 2)],
    "in=eth0 out=":                   [("Control 12", 2), ("Control 13", 2)],

    # ── Control 13 — Network Monitoring ──────────────────────────────────────
    "et scan potential":              [("Control 13", 2)],
    "et exploit":                     [("Control 13", 2), ("Control 7", 2)],
    "suricata":                       [("Control 13", 2)],
    # TIGHTENED: "zeek" alone kept — it's specific enough
    "zeek":                           [("Control 13", 2)],
    "dnsrequest":                     [("Control 13", 2), ("Control 9", 1)],
    "base64encoded.attacker":         [("Control 13", 2), ("Control 10", 2)],
    "networkconnect":                 [("Control 13", 2)],
    # TIGHTENED: "port 4444" → require remote port context
    "remoteport\":4444":              [("Control 13", 2), ("Control 10", 2)],
    "dest_port\":4444":               [("Control 13", 2), ("Control 10", 2)],

    # ── Control 15 — Service Provider Management ─────────────────────────────
    # TIGHTENED: "contractor" alone removed — require full VPN/access phrase
    "username = contractor":          [("Control 15", 2)],
    "contractor/":                    [("Control 15", 2)],
    "iam.amazonaws.com":              [("Control 15", 2), ("Control 5", 1)],

    # ── Control 16 — Application Software Security ───────────────────────────
    "sql injection detected":         [("Control 16", 2)],
    "rule 942100":                    [("Control 16", 2)],
    "modsecurity: access denied":     [("Control 16", 2), ("Control 13", 1)],
    "cve-2024-3400":                  [("Control 16", 2), ("Control 7", 2)],
    "pan-os command injection":       [("Control 16", 2), ("Control 7", 2)],

    # ── Control 17 — Incident Response ───────────────────────────────────────
    # TIGHTENED: bare "incident" removed — require full phrase
    "active incident":                [("Control 17", 2)],
    "incident response":              [("Control 17", 2)],

    "c2":  [("Control 17", 2)],
    "payload.sh": [("Control 17", 2)],
    "stage2":     [("Control 17", 2)],

    # ── DNS → Control 9 (missing entirely in original) ───────────────────────
    "queries: info: client":          [("Control 9",  2), ("Control 13", 1)],
    "malware-c2":                     [("Control 9",  2), ("Control 13", 2)],
    "query: malware":                 [("Control 9",  2), ("Control 13", 2)],
    "base64encoded":                  [("Control 9",  2), ("Control 13", 2)],
    "attacker.com":                   [("Control 9",  2), ("Control 13", 2)],
    "query denied":                   [("Control 13", 2)],
    "wpad.internal":                  [("Control 9",  1)],
    "dns sinkhol":                    [("Control 9",  2), ("Control 13", 2)],

    # ── Control 15 — cloud provider / contractor IAM patterns ────────────────
    # CloudTrail
    "createuser":                     [("Control 15", 2), ("Control 5",  1)],
    "attachuserpolicy":               [("Control 15", 2), ("Control 6",  1)],
    "iam.amazonaws.com":              [("Control 15", 2), ("Control 5",  1)],
    "contractor01":                   [("Control 15", 2)],
    "signin.amazonaws.com":           [("Control 15", 1), ("Control 6",  1)],
    # GCP
    "createserviceaccount":           [("Control 15", 2), ("Control 5",  1)],
    "setiampolicy":                   [("Control 15", 2), ("Control 5",  1)],
    "backdoor-sa":                    [("Control 15", 2), ("Control 5",  2)],
    "corp-prod.iam.gserviceaccount":  [("Control 15", 2)],
    "google.iam.admin":               [("Control 15", 2), ("Control 5",  1)],
    "roles/owner":                    [("Control 15", 2), ("Control 5",  1)],
    "storage.buckets.getiampolicy":   [("Control 3",  2), ("Control 15", 1)],
    "storage.objects.get":            [("Control 3",  2)],   # GCP object read
    "storage.objects.list":           [("Control 3",  2)],   # GCP bucket list
    "corp-backup":                    [("Control 3",  3)],   # backup bucket name = data protection
    "prod-backup":                    [("Control 3",  3)],   # backup bucket name = data protection

    # Azure
    "add oauth2permissiongrant":      [("Control 15", 2), ("Control 6",  1)],
    "malicious-app":                  [("Control 15", 2), ("Control 10", 1)],
    "serviceprincipal":               [("Control 15", 2)],

    # ── Benign cloudtrail — suppress Control 12/13 false positives ────────────
    # These are read-only describe/get operations — not network infrastructure
    "describeinstances":              [("Control 3",  1)],
    "describesecuritygroups":         [("Control 4",  1)],
    "getobject":                      [("Control 3",  1)],
    "putobject":                      [("Control 3",  1)],
    "log-shipper":                    [("Control 8",  1)],
    "deploy-bot":                     [("Control 3",  1)],

    # ── Strengthen Control 13 for network logs ────────────────────────────────
    "dnsrequest\":":                  [("Control 13", 2)],
    "networkconnect\":":              [("Control 13", 2)],
    "conn_state":                     [("Control 13", 2)],
    "#fields ts uid":                 [("Control 13", 2)],   # Zeek header

    # ── Benign firewall — correctly anchor to Control 13 ─────────────────────
    "ufw allow":                      [("Control 12", 1), ("Control 13", 1)],
    "in=eth0 out= src=10":            [("Control 13", 1)],

    # ── VPN — strengthen Control 4 config detection ───────────────────────────
    "certificate has expired":        [("Control 4",  2), ("Control 12", 1)],
    "verify error: depth=0":          [("Control 4",  2)],
    "tls: initial packet":            [("Control 12", 2)],

    # ── wazuh_siem — Control 8 (file integrity / syscheck) ───────────────────
    "integrity checksum changed":    [("Control 8", 3)],
    "syscheck_entry_modified":       [("Control 8", 3)],
    "syscheck":                      [("Control 8", 2)],
    "/etc/passwd":                   [("Control 8", 2), ("Control 6", 1)],
    "/etc/shadow":                   [("Control 8", 2), ("Control 6", 2)],
    "sha256_after":                  [("Control 8", 2)],
    "ossec":                         [("Control 8", 2)],

    # ── wazuh_siem — Control 16 (SQL injection via WAF/SIEM rule) ─────────────
    "web attack: sql injection":     [("Control 16", 3)],
    "sql injection attempt":         [("Control 16", 3), ("Control 13", 1)],
    "rule.*31108":                   [("Control 16", 2)],
    "login.php":                     [("Control 16", 1)],

    # ── nmap — Control 4 (exposed services = misconfiguration) ───────────────
    "3389/tcp":                      [("Control 4", 2), ("Control 12", 1)],
    "445/tcp":                       [("Control 4", 2), ("Control 12", 1)],
    "ms-wbt-server":                 [("Control 4", 2), ("Control 12", 2)],
    "microsoft-ds":                  [("Control 4", 1), ("Control 12", 1)],
    "open  ftp":                     [("Control 4", 2), ("Control 7", 1)],
    "open  telnet":                  [("Control 4", 3)],
    "microsoft terminal services":   [("Control 4", 2), ("Control 12", 2)],

    # ── Cisco ASA — Control 13 (land attack, rate exceeded = monitoring alert)
    "land attack":                   [("Control 13", 3), ("Control 12", 1)],
    "object drop rate":              [("Control 13", 2)],
    "burst rate":                    [("Control 13", 2)],
    "%asa-2-":                       [("Control 13", 2)],   # severity 2 = critical ASA
    "%asa-3-":                       [("Control 13", 2)],   # severity 3 = error ASA
    "%asa-4-106023":                 [("Control 12", 2), ("Control 13", 1)],
    "deny tcp src outside":          [("Control 12", 2), ("Control 13", 1)],
    "tcp access denied by acl":      [("Control 12", 2), ("Control 13", 2)],

    # ── DHCP — Control 12 (rogue device on network = infra event) ────────────
    "rogue":                         [("Control 1", 2), ("Control 12", 2)],  # raised to 2
    "ba:dc:0f":                      [("Control 1", 3), ("Control 12", 2)],  # added Control 12
    "dhcpdiscover from":             [("Control 1", 2), ("Control 12", 2)],  # new: DHCP discover phrase
    "unknown client":                [("Control 1", 2), ("Control 12", 2)],  # new: DHCP unknown device

    # ── VPN — Control 6 (svc_account VPN = access control concern) ───────────
    "svc_account":                   [("Control 6", 2), ("Control 12", 1)],
    "aaa user authentication successful": [("Control 6", 2), ("Control 12", 1)],

    # ── benign_network — anchor to Control 13 (monitoring sees the traffic) ──
    "get /api/health":               [("Control 13", 2)],
    "get /api/status":               [("Control 13", 2)],
    "get /metrics":                  [("Control 13", 2)],
    "prometheus/":                   [("Control 13", 2)],
    "kube-probe":                    [("Control 13", 2)],

    # ── Keyword additions ────────────────────────────────────────────────────────
    # Wazuh is a SIEM/IDS — every alert it generates maps to Control 13
    "wazuh":                          [("Control 13", 3), ("Control 8", 2)],
    '"manager":':                     [("Control 13", 2)],   # wazuh JSON field
    '"rule":':                        [("Control 13", 2), ("Control 8", 2)],
    "rule.*description.*brute":       [("Control 13", 3)],
    "rule.*description.*sql":         [("Control 16", 3), ("Control 13", 2)],
    "rule.*description.*integrity":   [("Control 8",  3)],
    "syscheck_entry_modified":        [("Control 8",  3)],
    "multiple.*failed.*ssh":          [("Control 13", 2), ("Control 6", 2)],

    # PAN-OS THREAT subtype = IDS alert = Control 13
    "subtype.*threat":              [("Control 13", 3), ("Control 12", 1)],
    "threat_id":                    [("Control 13", 3)],
    "action.*blocked":              [("Control 13", 2), ("Control 12", 2)],
    "action.*reset-both":           [("Control 13", 2)],
    "category-of-threat":           [("Control 13", 3)],
    "pan-os command injection":     [("Control 16", 3), ("Control 13", 2)],  # already exists, update
    "smb lateral":                  [("Control 13", 3), ("Control 12", 2)],
    "lateral movement":             [("Control 13", 3)],

    # ── DHCP rogue device → also Control 12 (network segmentation) ───────────
    r"rogue|unknown client.*dhcp|ba:dc|rogue.*dhcp": {
        "controls": ["Control 1", "Control 12"],
        "weight":   2,
        "reason":   "Rogue DHCP device implies network segmentation failure"
    },
    # ── GCP backup bucket access → Control 3 (data protection) ───────────────
    r"backup.*bucket|storage\.objects\.(get|list)|getobject.*backup|"
    r"corp-backup|prod-backup": {
        "controls": ["Control 3"],
        "weight":   2,
        "reason":   "Backup/storage access → data protection Control 3"
    },
    # ── GCP owner role assignment → Control 3 + 15 ───────────────────────────
    r"gserviceaccount|cloudaudit\.googleapis|logname.*projects.*logs": {
        "controls": ["Control 3", "Control 5", "Control 15"],
        "weight":   3,
        "reason":   "GCP-specific IAM activity → data protection + service provider mgmt"
    },

    # ── Okta SSO / Identity provider ─────────────────────────────────────────
    # Okta logs use structured JSON event type strings — these are the exact
    # field values that appear in eventType and debugData fields.
    "user.account.privilege.grant":    [("Control 5", 2), ("Control 6", 2)],
    "user.mfa.factor.deactivate":      [("Control 6", 3)],
    "application.provision.user":      [("Control 5", 2), ("Control 15", 1)],
    "Super Administrator":             [("Control 6", 3)],
    "privilegeGranted":                [("Control 6", 2)],
    "Backdoor Account":                [("Control 5", 3)],
    r'mfaAttempted\":\"false\"':       [("Control 6", 2)],
    r'New Geo-Location\":\"POSITIVE\"': [("Control 6", 1)],
}

LOG_TYPE_SUPPRESSED_CONTROLS = {
    "wazuh_siem": ["Control 5", "Control 7", "Control 9"],
    "syslog":     ["Control 12", "Control 7"],   # C2 curl doesn't mean infra management
    "auditd":     ["Control 7"],    # curl download ≠ vulnerability management
    "edr":                 ["Control 6"],
    "crowdstrike_falcon":  ["Control 6"],
    "vpn":                 ["Control 5"],
    "gcp_audit":           ["Control 6"],
    "paloalto":   [],               # no suppression — handle via keyword add below
}

def validate_cis_mapping(findings: dict) -> bool:
    domains  = findings.get("cis_controls_mapping", {}).get("security_domains", [])
    ctrl_ids = findings.get("cis_controls_mapping", {}).get("control_ids", [])
    ctrl_nums = set(re.findall(r"Control \d+", " ".join(ctrl_ids)))
    if not domains or not ctrl_ids:
        return False
    expected: set = set()
    for domain in domains:
        domain_l = domain.lower()
        for key, controls in DOMAIN_CONTROL_MAP.items():
            if key.lower() in domain_l or domain_l in key.lower():
                expected.update(controls)
    if not expected:
        return True
    return bool(ctrl_nums & expected)


# Minimum total confidence weight for a keyword-detected control to be accepted
KEYWORD_MIN_WEIGHT = 2   # controls scoring below this are suppressed

def run_keyword_detector(raw_log: str) -> list:
    """
    Accumulates confidence weights per control from KEYWORD_CONTROL_MAP.
    A control is only added if its total weight >= KEYWORD_MIN_WEIGHT.
    This prevents single weak-signal keywords from adding false-positive controls.
    """
    log_lower  = raw_log.lower()
    weights: dict = defaultdict(int)

    for kw, ctrl_list in KEYWORD_CONTROL_MAP.items():
        if kw.lower() in log_lower:
            # Handle both formats:
            # list-of-tuples: [("Control 6", 2), ("Control 5", 1)]
            # dict format:    {"controls": ["Control 1"], "weight": 2, "reason": "..."}
            if isinstance(ctrl_list, dict):
                w = ctrl_list.get("weight", 1)
                for ctrl in ctrl_list.get("controls", []):
                    weights[ctrl] += w
            else:
                for ctrl, weight in ctrl_list:
                    weights[ctrl] += weight

    found = [
        ctrl for ctrl, w in weights.items()
        if w >= KEYWORD_MIN_WEIGHT
    ]
    return sorted(found, key=lambda x: int(re.search(r'\d+', x).group()))


def validate_and_correct_cis_mapping(
    findings: dict, raw_log: str, verbose: bool = True,
    log_type: str = "auto"
) -> dict:
    sep = "-" * 72
    if verbose:
        print(f"\n{sep}")
        print("  CIS VALIDATOR / CORRECTOR")
        print(sep)

# Guarantee the key exists on the dict before any reads or writes
    if "cis_controls_mapping" not in findings:
        findings["cis_controls_mapping"] = {"control_ids": [], "safeguard_ids": [], "security_domains": []}
    cis          = findings["cis_controls_mapping"]
    cis.setdefault("control_ids",     [])
    cis.setdefault("safeguard_ids",   [])
    cis.setdefault("security_domains",[])
    llm_ctrl_ids = list(cis.get("control_ids",      []))
    llm_domains  = list(cis.get("security_domains", []))

    if verbose:
        print(f"  LLM control_ids      : {llm_ctrl_ids}")
        print(f"  LLM security_domains : {llm_domains}")

    is_consistent = validate_cis_mapping(findings)
    if verbose:
        status = "CONSISTENT" if is_consistent else "MISMATCH DETECTED"
        marker = "OK " if is_consistent else "!! "
        print(f"  Consistency check    : [{marker}] {status}")

    det_ctrl_ids = run_keyword_detector(raw_log)
    if verbose:
        print(f"  Deterministic ctrl_ids: {det_ctrl_ids}")

    normalised_llm = []
    for c in llm_ctrl_ids:
        m = re.search(r"Control\s+(\d+)", c, re.IGNORECASE)
        if m:
            normalised_llm.append(f"Control {m.group(1)}")

    llm_set = set(normalised_llm)
    det_set = set(det_ctrl_ids)

    if not is_consistent:
        merged = sorted(
            llm_set | det_set,
            key=lambda x: int(re.search(r'\d+', x).group())
        )
    else:
        log_lower = raw_log.lower()
        weights: dict = defaultdict(int)
        for kw, ctrl_list in KEYWORD_CONTROL_MAP.items():
            if kw.lower() in log_lower:
                # Handle both formats (mirrors run_keyword_detector logic):
                # list-of-tuples: [("Control 6", 2), ...]
                # dict format:    {"controls": [...], "weight": 2, "reason": "..."}
                if isinstance(ctrl_list, dict):
                    w = ctrl_list.get("weight", 1)
                    for ctrl in ctrl_list.get("controls", []):
                        weights[ctrl] += w
                else:
                    for ctrl, weight in ctrl_list:
                        weights[ctrl] += weight

        high_conf_det = {ctrl for ctrl, w in weights.items() if w >= 3}
        low_conf_det  = {ctrl for ctrl, w in weights.items()
                         if KEYWORD_MIN_WEIGHT <= w < 3}

        if verbose:
            print(f"  High-conf det ctrl   : {sorted(high_conf_det)}")
            print(f"  Low-conf det ctrl    : {sorted(low_conf_det)}")

        domain_expected: set = set()
        for domain in llm_domains:
            domain_l = domain.lower()
            for key, controls in DOMAIN_CONTROL_MAP.items():
                if key.lower() in domain_l or domain_l in key.lower():
                    domain_expected.update(controls)

        if verbose:
            print(f"  Domain-expected ctrl : {sorted(domain_expected)}")

        allowed_additions = (
            (high_conf_det - llm_set) |
            ((low_conf_det - llm_set) & domain_expected)
        )

        merged = sorted(
            llm_set | allowed_additions,
            key=lambda x: int(re.search(r'\d+', x).group())
        )
    # ── Log-type-specific false positive suppression ──────────────────────────
    suppressed_for_type = LOG_TYPE_SUPPRESSED_CONTROLS.get(log_type, [])
    if suppressed_for_type:
        before_suppress = set(merged)
        merged = [c for c in merged if c not in suppressed_for_type]
        removed_by_type = before_suppress - set(merged)
        if removed_by_type and verbose:
            print(f"  Type-suppressed      : {sorted(removed_by_type)} "
                  f"(log_type={log_type})")

    if set(merged) != llm_set:
        added = sorted(
            set(merged) - llm_set,
            key=lambda x: int(re.search(r'\d+', x).group())
        )
        if verbose:
            print(f"  Added by detector    : {added}")
            print(f"  Final control_ids    : {merged}")
            action = "CORRECTED (mismatch)" if not is_consistent else "ENRICHED (omissions filled)"
            print(f"  Action               : {action}")
        findings.setdefault("cis_controls_mapping", {})["control_ids"] = merged
    else:
        if verbose:
            print(f"  Final control_ids    : {merged}")
            print("  Action               : No change needed")

    if verbose:
        print(sep)

    return findings


print(f"✅ Deterministic CIS validator / corrector defined")
print(f"   DOMAIN_CONTROL_MAP  : {len(DOMAIN_CONTROL_MAP)} entries")
print(f"   KEYWORD_CONTROL_MAP : {len(KEYWORD_CONTROL_MAP)} keywords")
print(f"   KEYWORD_MIN_WEIGHT  : {KEYWORD_MIN_WEIGHT}")

# %%
# ─────────────────────────────────────────────────────────────────────────────
# FIX 3 — Threat signal density pre-filter
# Addresses: benign_auth/benign_windows over-severity,
#            benign_network/benign_cloudtrail wrong control predictions
# ─────────────────────────────────────────────────────────────────────────────

# High-signal threat indicators — presence of any = not benign
THREAT_SIGNAL_PATTERNS = [
    r'CVE-\d{4}-\d{4,}',
    r'mimikatz', r'cobaltstr', r'beacon\.exe', r'meterpreter',
    r'payload\.sh', r'payload\.ps1', r'evil\.exe',
    r'failed password for (invalid user|root)',
    r'privilege escalation',
    r'eventid:\s*4625', r'eventid:\s*4720', r'eventid:\s*4732',
    r'eventid:\s*7045',
    r'deletebucket', r'getsecretvalue', r'createuser',
    r'backdoor', r'et malware', r'et exploit', r'et scan',
    r'sql injection', r'modsecurity',
    r'malware-c2', r'c2\.malicious',
    r'powershell -enc', r'powershell -nop',
    r'sekurlsa', r'net user.*\/add',
    r'attachuserpolicy.*administratoraccess',
    r'roles/owner.*backdoor',
    r'add member to role',
    r'mfaused.*no',
    r'threatSuspected.*true',
    r'riskstate.*atRisk',
    r'pan-os command injection',
    r'eternalblue', r'ms17-010',
    r'type=execve.*curl.*http',
    r'type=syscall.*priv_esc',
]

# Benign operation patterns — logs dominated by these are low-risk
BENIGN_SIGNAL_PATTERNS = [
    r'accepted publickey',
    r'systemctl restart',
    r'rsync -av',
    r'GET /api/health',
    r'GET /api/status',
    r'GET /metrics',
    r'kube-probe',
    r'Prometheus/',
    r'windowsupdate',
    r'describeinstances',
    r'describesecuritygroups',
    r'getobject.*corp-artifacts',
    r'putobject.*corp-logs',
    r'ufw allow.*10\.0\.0',
    r'dpt=443|dpt=53|dpt=5432|dpt=6379|dpt=8080',
]

# STRUCTURED_RISK_LOG_TYPES, SEVERITY_FLOOR, SEVERITY_ORDER are imported from
# config.py (see the `from config import ...` block at the top of this file).
# They were previously re-defined here with identical values, which silently
# shadowed the config imports and made config tuning a no-op. Removed so config
# is the single source of truth. Values unchanged.
COMPILED_THREAT = [re.compile(p, re.IGNORECASE) for p in THREAT_SIGNAL_PATTERNS]
COMPILED_BENIGN = [re.compile(p, re.IGNORECASE) for p in BENIGN_SIGNAL_PATTERNS]

# ── Benign scheduled task context patterns ────────────────────────────────────
# EventID 4698 is NOT in THREAT_SIGNAL_PATTERNS anymore. Instead we evaluate
# it contextually: benign task name = benign signal, malicious content = threat.
BENIGN_TASK_NAMES = re.compile(
    r'windows.?update|microsoftwindows\\windows.?update|'
    r'updateorchestrator|sppsvc|wuauclt|software.?protection',
    re.IGNORECASE
)
MALICIOUS_TASK_INDICATORS = re.compile(
    r'powershell.*-enc|-encoded.*JAB|http[s]?://\d{1,3}\.|'
    r'wget.*payload|curl.*payload|cmd.*\/c.*start.*http',
    re.IGNORECASE
)

def is_benign_scheduled_task(raw_log: str) -> bool:
    """
    Returns True if EventID 4698 is from a known-benign Windows task.
    Used to avoid misclassifying Windows Update as a threat.
    """
    has_4698        = bool(re.search(r'eventid:\s*4698', raw_log, re.I))
    if not has_4698:
        return False
    has_benign_name    = bool(BENIGN_TASK_NAMES.search(raw_log))
    has_malicious_sign = bool(MALICIOUS_TASK_INDICATORS.search(raw_log))
    return has_benign_name and not has_malicious_sign

def compute_threat_density(raw_log: str, log_type: str = "auto") -> dict:
    lines       = raw_log.strip().splitlines()
    total_lines = max(len(lines), 1)

    threat_hits     = 0
    benign_hits     = 0
    matched_threats = []

    for pattern in COMPILED_THREAT:
        matches = pattern.findall(raw_log)
        if matches:
            threat_hits += len(matches)
            matched_threats.append(pattern.pattern[:50])

    for pattern in COMPILED_BENIGN:
        matches = pattern.findall(raw_log)
        if matches:
            benign_hits += len(matches)

    # ── Context override: benign Windows scheduled task ───────────────────────
    # EventID 4698 was removed from THREAT_SIGNAL_PATTERNS. But if 4698 appears
    # in the log with a malicious task command, count it as a threat hit manually.
    has_4698 = bool(re.search(r'eventid:\s*4698', raw_log, re.I))
    if has_4698:
        if is_benign_scheduled_task(raw_log):
            # Legitimate Windows Update task — count as benign signal
            benign_hits += 1
        else:
            # Unknown or malicious task — count as threat
            threat_hits += 1
            matched_threats.append('eventid:\\s*4698 (malicious context)')

    threat_score = round(threat_hits / total_lines, 4)
    benign_score = round(benign_hits / total_lines, 4)
    net_score    = round(threat_score - benign_score, 4)

    is_structured_risk = log_type.lower() in STRUCTURED_RISK_LOG_TYPES

    is_benign = (
        not is_structured_risk
        and (
            (threat_hits == 0 and benign_hits > 0)
            or (net_score < -0.3 and threat_hits <= 1)
        )
    )

    return {
        "threat_hits":        threat_hits,
        "benign_hits":        benign_hits,
        "threat_score":       threat_score,
        "benign_score":       benign_score,
        "net_score":          net_score,
        "is_benign":          is_benign,
        "is_structured_risk": is_structured_risk,
        "matched_threats":    matched_threats,
    }

# BENIGN_SEVERITY_CEILING is imported from config.py (top-of-file import block).
# Previously re-defined here with identical values, shadowing the import; removed
# so config is the single source of truth. The cap is applied in get_benign_severity().

def get_benign_severity(density: dict, log_type: str = "auto") -> str:
    """
    Map threat density to appropriate severity for benign/low-signal logs.
    Uses BENIGN_SEVERITY_CEILING (not SEVERITY_FLOOR, which covers non-benign
    structured log types and is irrelevant here).
    """
    # Derive raw severity from density signals
    if density["threat_hits"] == 0 and density["benign_hits"] > 0:
        raw_sev = "informational"
    elif density["net_score"] < -0.3:
        raw_sev = "informational"
    else:
        raw_sev = "low"

    # Cap at the ceiling defined for this benign log type
    ceiling = BENIGN_SEVERITY_CEILING.get(log_type.lower())
    if ceiling:
        ceiling_idx = SEVERITY_ORDER.index(ceiling)
        raw_idx     = SEVERITY_ORDER.index(raw_sev)
        if raw_idx > ceiling_idx:
            return ceiling
    return raw_sev


BENIGN_SUPPRESSED_CONTROLS = {
    # Only suppress KNOWN FALSE POSITIVES — not the correct expected controls.
    # benign_network expected = Control 13, so DO NOT suppress it.
    # We only suppress Control 12 (infra mgmt) which the LLM adds incorrectly.
    "benign_network":    ["Control 12"],
    # benign_cloudtrail: Controls 12, 13 are FPs; Controls 3, 15 are correct
    "benign_cloudtrail": ["Control 12", "Control 13", "Control 5", "Control 6"],
    # benign_windows: Control 12 is FP; Control 8 is the correct expected control
    "benign_windows":    ["Control 12", "Control 5", "Control 6"],
    # benign_auth: Control 12 is FP; Controls 6, 8 are correct
    "benign_auth":       ["Control 12", "Control 5"],
    "benign_firewall":   [],
}

# ── Post-LLM severity correction ─────────────────────────────────────────────
# Applied BEFORE the density gate. Catches cases where the LLM over-rates
# severity by not distinguishing successful vs failed events.

_FAILED_ATTEMPT = re.compile(
    r'res=failed|authentication failure|failed password|'
    r'permission denied|access denied|type=USER_AUTH.*res=failed',
    re.IGNORECASE
)
_SUCCESS_CONFIRM = re.compile(
    r'success.*yes|res=success(?!.*failed)|succeeded|'
    r'ConsoleLogin.*Success|createLocalAdmin.*true|'
    # Removed: type=EXECVE and cron\[\d+\].*CMD — these are execution events,
    # not auth success signals. They were blocking severity correction on syslog.
    r'bash\s+/tmp/payload|'                 # payload executed = confirmed
    r'curl.*http.*c2|wget.*payload\.sh',    # C2/payload delivery confirmed
    re.IGNORECASE
)
_CONFIRMED_EXPLOIT = re.compile(
    r'cobaltstr|beacon\.exe|et malware|malware.*c2|'
    r'encrypt\.exe|ransomware|sekurlsa.*logonpasswords|'
    # syslog / auditd — payload delivery and C2 execution
    r'wget.*payload|/tmp/payload\.sh|curl.*c2|bash\s*/tmp/payload|'
    # windows — credential tools and malicious executables
    r'mimikatz|evil\.exe|powershell\s+-enc|'
    # cloud IAM privilege abuse — confirmed attacker escalation
    r'AdministratorAccess|backdoor_admin|backdoor_user|backdoor-sa|'
    r'Global.Administrator|roles/owner.*backdoor|backdoor.*roles/owner|'
    # endpoint — confirmed local admin creation
    r'createLocalAdmin.*true|net\s+user.*\/add|'
    # known exploit signatures
    r'eternalblue|ms17-010|'
    # Okta / identity provider confirmed privilege abuse
    r'Super.Administrator|privilegeGranted|'
    r'user\.account\.privilege\.grant|user\.mfa\.factor\.deactivate',
    re.IGNORECASE
)

def post_llm_severity_correction(findings: dict, raw_log: str, log_type: str) -> dict:
    """
    Corrects LLM severity when content evidence clearly contradicts it.

    Rule 1: CRITICAL + only failed attempts + no confirmed exploit → HIGH
            Rationale: failed attempts are indicators, not confirmed breaches.
            A failed sudo+curl is serious but not critical.

    Rule 2: Any severity + confirmed C2/ransomware but rated LOW/MEDIUM → HIGH min
            Rationale: LLM occasionally under-rates when confidence is low.
    """
    current_sev = findings.get("severity", "medium").lower()

    has_confirmed_exploit = bool(_CONFIRMED_EXPLOIT.search(raw_log))
    has_success           = bool(_SUCCESS_CONFIRM.search(raw_log))
    has_only_failures     = (bool(_FAILED_ATTEMPT.search(raw_log))
                             and not has_success)

    # Rule 1: CRITICAL but only failures and no confirmed post-exploitation
    if (current_sev == "critical"
            and has_only_failures
            and not has_confirmed_exploit):
        print(f"  [severity_correction] {log_type}: CRITICAL → HIGH "
              f"(only failed attempts detected, no confirmed post-exploitation)")
        findings["severity"] = "high"

    # Rule 2: confirmed exploit but rated too low
    elif (has_confirmed_exploit
          and current_sev in ("low", "medium", "informational")):
        print(f"  [severity_correction] {log_type}: {current_sev.upper()} → HIGH "
              f"(confirmed exploit/C2 signal present)")
        findings["severity"] = "high"

    return findings

def apply_benign_suppression(
    findings: dict, log_type: str, density: dict
) -> dict:
    """
    Removes known false-positive controls for specific benign log types.

    CHANGED FROM v4: suppression now runs for ALL logs in BENIGN_SUPPRESSED_CONTROLS
    regardless of whether density gate fired (is_benign=True/False).
    Reason: benign_windows has threat_hits=1 (EventID 4698) so is_benign=False,
    but Controls 5 and 6 are still false positives for a routine Windows log.
    The suppression list entries are hand-verified — safe to apply unconditionally.
    """
    suppressed = BENIGN_SUPPRESSED_CONTROLS.get(log_type, [])
    if not suppressed:
        return findings

    cis      = findings.get("cis_controls_mapping", {})
    original = cis.get("control_ids", [])
    filtered = [c for c in original if c not in suppressed]

    if filtered != original:
        removed = set(original) - set(filtered)
        print(f"  [benign_suppression] Removed {removed} from {log_type}")
        findings["cis_controls_mapping"]["control_ids"] = filtered

    # Fallback seed — if suppression emptied control_ids, inject minimum seed
    BENIGN_EMPTY_SEED = {
        "benign_network": ["Control 13"],
    }
    if not findings["cis_controls_mapping"]["control_ids"]:
        seed = BENIGN_EMPTY_SEED.get(log_type, [])
        if seed:
            print(f"  [benign_suppression] Injecting seed {seed} for Stage 2a")
            findings["cis_controls_mapping"]["control_ids"] = seed

    return findings


print("✅ Fix 2 applied — calibrated threat density gate")
print(f"   STRUCTURED_RISK_LOG_TYPES : {STRUCTURED_RISK_LOG_TYPES}")
print(f"   SEVERITY_FLOOR            : {SEVERITY_FLOOR}")
print("   is_benign now requires: NOT structured_risk AND benign_hits > 0")

# %%
# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7 — Per-Control Query Builder
# ─────────────────────────────────────────────────────────────────────────────

_CONTROL_SENTENCES: dict = {
    # ── REVISED: more specific, less catch-all ─────────────────────────────
    "Control 1":  "Maintain an active inventory of all enterprise hardware assets; detect and respond to unauthorized devices connected to the network.",
    "Control 2":  "Maintain an inventory of all authorized software; detect and block unauthorized or unmanaged applications and executables.",
    "Control 3":  "Classify and protect sensitive data through encryption, DLP tools, and access restrictions; prevent unauthorized data exfiltration.",
    "Control 4":  "Apply and enforce secure baseline configurations; disable unnecessary services, ports, and protocols on all enterprise assets.",
    "Control 5":  "Manage the full lifecycle of user accounts; enforce account lockout, disable unused accounts, and control privileged account access.",
    "Control 6":  "Enforce least-privilege access controls; require MFA for all privileged and remote access; restrict and audit administrative rights.",
    "Control 7":  "Perform automated vulnerability scans and apply security patches on a risk-prioritized monthly schedule; remediate detected CVEs.",
    "Control 8":  "Collect, retain, and review audit logs from all enterprise assets; generate alerts on suspicious events for forensic investigation.",
    "Control 9":  "Block malicious domains and phishing emails using DNS filtering and email gateway protections; prevent malicious URL access.",
    "Control 10": "Deploy anti-malware and EDR solutions; detect, block, and alert on malicious code execution and command-and-control beaconing.",
    "Control 11": "Perform automated backups of enterprise data and test restore processes regularly to ensure recovery from ransomware or data loss.",
    "Control 12": "Manage and secure network infrastructure devices; enforce firewall rules, VPN configurations, and restrict unnecessary network access.",
    "Control 13": "Deploy network intrusion detection and traffic flow monitoring; alert on anomalous connections, lateral movement, and C2 traffic.",
    "Control 14": "Deliver security awareness training to all staff; train employees to recognize phishing, social engineering, and reporting procedures.",
    "Control 15": "Assess and continuously monitor third-party service providers for security risks; enforce contractual security obligations.",
    "Control 16": "Implement secure SDLC practices; test applications for injection flaws, authentication weaknesses, and code execution vulnerabilities.",
    "Control 17": "Establish and exercise an incident response plan; define roles, communication channels, and recovery procedures for active incidents.",
    "Control 18": "Conduct periodic penetration tests and red team exercises to validate security controls and identify exploitable weaknesses.",
}

# Add after _CONTROL_SENTENCES dict
_NIST_CATEGORY_SENTENCES: dict = {
    "GV.OC": "Establish organizational context including mission, stakeholder expectations, and regulatory requirements.",
    "GV.RM": "Establish and monitor cybersecurity risk management strategy, appetite, and tolerance.",
    "GV.RR": "Define and enforce cybersecurity roles, responsibilities, and accountability.",
    "GV.PO": "Establish, communicate, and enforce cybersecurity policy.",
    "GV.OV": "Monitor and improve cybersecurity risk management outcomes.",
    "GV.SC": "Manage cybersecurity supply chain risks including third-party vendors and service providers.",
    "ID.AM": "Identify and manage assets including hardware, software, data, and services.",
    "ID.RA": "Identify, analyze, and prioritize cybersecurity risks to the organization.",
    "ID.IM": "Improve cybersecurity through lessons learned and ongoing risk assessments.",
    "PR.AA": "Manage identities and credentials; enforce least privilege and MFA for all access.",
    "PR.AT": "Provide cybersecurity awareness and training to all personnel.",
    "PR.DS": "Protect data at rest and in transit through encryption and access controls.",
    "PR.PS": "Manage configuration, software, and platform security across all enterprise assets.",
    "PR.IR": "Manage and protect technology infrastructure including network and systems.",
    "DE.CM": "Monitor assets and networks to detect anomalies, threats, and indicators of compromise.",
    "DE.AE": "Analyze detected events to understand attack targets, methods, and impact.",
    "RS.MA": "Manage and coordinate incident response activities.",
    "RS.AN": "Investigate incidents to understand scope, impact, and root cause.",
    "RS.CO": "Coordinate incident response with internal and external stakeholders.",
    "RS.MI": "Contain and mitigate the effects of cybersecurity incidents.",
    "RC.RP": "Execute and improve recovery plans to restore operations after incidents.",
    "RC.CO": "Coordinate restoration activities with internal and external stakeholders.",
}

def build_per_control_queries_from_llm(findings: dict) -> list:
    queries = []
    seen: set = set()
    for ctrl_label in findings.get("cis_controls_mapping", {}).get("control_ids", []):
        m = re.search(r"Control\s+(\d+)", ctrl_label, re.IGNORECASE)
        if not m:
            continue
        key = f"Control {m.group(1)}"
        if key in seen:
            continue
        seen.add(key)
        sentence = _CONTROL_SENTENCES.get(key, "")
        if sentence:
            queries.append((key, sentence))
    return queries


print("✅ Per-control query builder defined")

# %%
# ─────────────────────────────────────────────────────────────────────────────
# SecureBERT Embedder
# ─────────────────────────────────────────────────────────────────────────────