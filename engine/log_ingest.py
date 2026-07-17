"""
log_ingest.py
=============
Reads the live, mixed-source log file (config.LOG_INPUT_PATH) and turns it into
the same (log_type, raw_log) shape that pipeline.py used to get from the fixed
SAMPLE_LOGS dict — one entry per line.

Why one entry per line:
  Virtually every real log source writes one event per line — syslog (RFC
  3164/5424), and JSON-lines sources like CloudTrail, O365, Azure AD, Okta,
  GCP audit, Wazuh, Defender, and Suricata eve.json. Log shippers that
  centralise multiple sources into one file reconstruct multi-line events
  into a single flattened record before writing them, so by the time they
  land in a shared file, one line = one event. (Genuinely multi-line tool
  output, e.g. an nmap scan report, is the rare exception — not handled here.)

Why auto-detection instead of a fixed log_type per line:
  The incoming file carries no source label. detect_log_type() is a fast,
  deterministic, rule-based sniffer (JSON key fingerprints for JSON sources,
  prefix/keyword fingerprints for plain-text sources) — same no-LLM-on-the-
  critical-path philosophy as the rest of the pipeline. Anything it can't
  confidently classify falls back to "generic", which already routes through
  the existing Gemma-enrichment path (enrich_with_llm=True) as a safety net.

This module does not touch timing/instrumentation in pipeline.py at all —
it only supplies the list that the existing loop iterates over.
"""

import json
import os
import re

# ── JSON-source fingerprints ──────────────────────────────────────────────────
# Checked in order; first matching set of keys wins. Each entry is
# (log_type, required_keys) — all keys in required_keys must be present
# somewhere in the parsed JSON object (top level or one level of nesting
# is checked via _has_key_anywhere).

def _has_key(obj: dict, key: str) -> bool:
    if key in obj:
        return True
    for v in obj.values():
        if isinstance(v, dict) and key in v:
            return True
    return False


_JSON_SIGNATURES = [
    # (log_type, all-of-these-keys-must-be-present)
    ("wazuh_siem",         ["rule", "agent"]),
    ("microsoft_defender", ["AlertId"]),
    ("gcp_audit",          ["protoPayload"]),
    ("okta_sso",           ["eventType", "published"]),
    ("o365",               ["Operation", "UserId", "CreationTime"]),
    ("azure_ad",           ["operationName", "userPrincipalName"]),
    ("azure_ad",           ["operationName", "initiatedBy"]),
    ("suricata",           ["event_type", "alert"]),
    ("cloudtrail",         ["eventName", "eventSource"]),
    ("cloudtrail",         ["eventVersion"]),
]


def _detect_json_log_type(line: str):
    """Returns a log_type string if `line` parses as JSON and matches a known
    fingerprint, else None (not JSON, or JSON but unrecognised shape)."""
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    for log_type, required_keys in _JSON_SIGNATURES:
        if all(_has_key(obj, k) for k in required_keys):
            return log_type
    return None


# ── Plain-text source fingerprints ────────────────────────────────────────────
# Checked in order; first match wins. Each entry is (log_type, compiled_regex).
_TEXT_SIGNATURES = [
    ("windows_evtx", re.compile(r'EventID:\s*\d+', re.IGNORECASE)),
    ("cisco_asa",    re.compile(r'%ASA-\d', re.IGNORECASE)),
    ("suricata",     re.compile(r'\[\*\*\]|classtype:', re.IGNORECASE)),
    ("zeek",         re.compile(r'^#fields\s|conn_state', re.IGNORECASE)),
    ("auditd",       re.compile(r'type=(EXECVE|SYSCALL|USER_AUTH)\b|msg=audit\(', re.IGNORECASE)),
    ("paloalto",     re.compile(r'\bTRAFFIC,|\bTHREAT,|subtype=threat|category-of-threat', re.IGNORECASE)),
    ("dhcp",         re.compile(r'\bDHCPDISCOVER\b|\bDHCPOFFER\b|\bDHCPACK\b|dhcpd\[', re.IGNORECASE)),
    ("vpn",          re.compile(r'\bopenvpn\[|\banyconnect:|\bipsec\b', re.IGNORECASE)),
    ("crowdstrike_falcon", re.compile(r'ProcessRollup2|crowdstrike|falcon', re.IGNORECASE)),
    ("nmap",         re.compile(r'^Nmap scan report for', re.IGNORECASE)),
    # Generic syslog: "Mon  6 08:12:01 hostname process[pid]:" style prefix.
    ("syslog",       re.compile(
        r'^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+(\[\d+\])?:'
    )),
]


def detect_log_type(line: str) -> str:
    """
    Best-effort, deterministic classification of a single log line into one
    of the known log_type strings used throughout config.py/detection_engine.py.
    Falls back to "generic" — which already triggers the existing Gemma
    enrichment path in analyze_log_with_llm(), so an unrecognised line is
    never dropped, just handled on the slower path.
    """
    stripped = line.strip()
    if not stripped:
        return "generic"

    if stripped.startswith("{"):
        json_type = _detect_json_log_type(stripped)
        if json_type:
            return json_type

    for log_type, pattern in _TEXT_SIGNATURES:
        if pattern.search(stripped):
            return log_type

    return "generic"


def load_logs_from_file(path: str) -> list:
    """
    Reads `path` (one log entry per line) and returns a list of
    (log_type, raw_log) tuples — the same shape SAMPLE_LOGS.items() used to
    provide. Blank lines are skipped. Missing file returns an empty list
    with a warning rather than raising, so a batch run degrades gracefully.
    """
    if not os.path.exists(path):
        print(f"[log_ingest] WARNING: log file not found at {path} — no logs loaded.")
        return []

    entries = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            log_type = detect_log_type(line)
            entries.append((log_type, line))

    print(f"[log_ingest] Loaded {len(entries)} log entries from {path}")
    return entries
