"""
generate.py
===========
Deterministic synthetic security-log generator for Furix. Emits realistic
attack and benign log lines across the supported log types, modelled on
`SAMPLE_LOGS` in pipeline.py. Each generated line is crafted to (a) classify
correctly via `log_ingest.detect_log_type` and (b) trigger the intended
detections/policy rules, so a generated batch produces a realistic met/gap mix.

Deterministic by seed: same (seed, count, attack_ratio, types) → identical
output. Uses a fixed base timestamp + offsets (no wall clock) so runs reproduce.

CLI:
    python -m log_generator.generate --count 50 --attack-ratio 0.35 --seed 7
    python -m log_generator.generate --count 20 --types cloudtrail,windows_evtx
    python -m log_generator.generate --count 50 --post http://localhost:8000/api/ingest
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from typing import Callable

# fixed base epoch (2026-07-16T09:00:00Z) so timestamps are deterministic
_BASE_EPOCH = 1_784_970_000
_EXT_IPS = ["45.33.32.156", "185.220.101.7", "91.219.236.19", "103.208.220.5"]
_INT_IPS = ["10.0.0.9", "10.0.2.14", "172.16.4.20", "192.168.1.33"]
_USERS = ["contractor01", "jdoe", "svc_deploy", "analyst2", "ops_admin"]
_BENIGN_USERS = ["deploy", "backup", "monitoring", "healthcheck"]

LineFn = Callable[[random.Random, int], str]


def _ts_syslog(rng: random.Random, i: int) -> str:
    # "Jul 16 09:00:01" style — offset by i seconds for variety
    sec = i % 60
    minute = (i // 60) % 60
    return f"Jul 16 09:{minute:02d}:{sec:02d}"


def _iso(i: int) -> str:
    return f"2026-07-16T09:{(i // 60) % 60:02d}:{i % 60:02d}Z"


def _pick(rng: random.Random, seq):
    return seq[rng.randrange(len(seq))]


# ── cloudtrail ────────────────────────────────────────────────────────────────
def _ct_attack(rng, i):
    ip = _pick(rng, _EXT_IPS)
    kind = _pick(rng, ["createuser", "attachadmin", "getsecret", "nomfa", "deletebucket"])
    if kind == "createuser":
        return json.dumps({"eventName": "CreateUser", "eventSource": "iam.amazonaws.com",
                           "requestParameters": {"userName": "backdoor_admin"}, "sourceIPAddress": ip})
    if kind == "attachadmin":
        return json.dumps({"eventName": "AttachUserPolicy", "eventSource": "iam.amazonaws.com",
                           "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                                                 "userName": "backdoor_admin"}, "sourceIPAddress": ip})
    if kind == "getsecret":
        return json.dumps({"eventName": "GetSecretValue", "eventSource": "secretsmanager.amazonaws.com",
                           "requestParameters": {"secretId": "prod/db/password"}, "sourceIPAddress": ip})
    if kind == "deletebucket":
        return json.dumps({"eventName": "DeleteBucket", "eventSource": "s3.amazonaws.com",
                           "requestParameters": {"bucketName": "prod-backup-2026"}, "sourceIPAddress": ip})
    return json.dumps({"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
                       "responseElements": {"ConsoleLogin": "Success"},
                       "additionalEventData": {"MFAUsed": "No"}, "sourceIPAddress": ip})


def _ct_benign(rng, i):
    ip = _pick(rng, _INT_IPS)
    name = _pick(rng, ["DescribeInstances", "ListBuckets", "GetObject", "DescribeVolumes"])
    return json.dumps({"eventName": name, "eventSource": "ec2.amazonaws.com",
                       "responseElements": {"ConsoleLogin": "Success"},
                       "additionalEventData": {"MFAUsed": "Yes"}, "sourceIPAddress": ip})


# ── windows_evtx ──────────────────────────────────────────────────────────────
def _win_attack(rng, i):
    kind = _pick(rng, ["4720", "7045", "mimikatz", "4625"])
    if kind == "4720":
        return "EventID: 4720 A user account was created. Account Name: backdoor_user"
    if kind == "7045":
        return "EventID: 7045 A new service was installed. Service Name: EvilSvc ImagePath: C:\\Temp\\evil.exe"
    if kind == "mimikatz":
        return "EventID: 4688 New Process: C:\\Tools\\mimikatz.exe CommandLine: sekurlsa::logonpasswords"
    return f"EventID: 4625 An account failed to log on. Account: {_pick(rng, _USERS)} Source: {_pick(rng, _EXT_IPS)}"


def _win_benign(rng, i):
    return f"EventID: 4624 An account was successfully logged on. Account: {_pick(rng, _BENIGN_USERS)} LogonType: 5"


# ── syslog (ssh) ──────────────────────────────────────────────────────────────
def _sys_attack(rng, i):
    # single line (one event per line): repeated root failures → Control 6 gap
    ts = _ts_syslog(rng, i)
    ip = _pick(rng, _EXT_IPS)
    return f"{ts} web01 sshd[{4000 + i % 900}]: Failed password for root from {ip} port 51044 ssh2"


def _sys_benign(rng, i):
    ts = _ts_syslog(rng, i)
    return f"{ts} web01 sshd[{5000 + i % 900}]: Accepted publickey for {_pick(rng, _BENIGN_USERS)} from {_pick(rng, _INT_IPS)} port 43001 ssh2"


# ── okta_sso ──────────────────────────────────────────────────────────────────
def _okta_attack(rng, i):
    return json.dumps({"eventType": "user.account.privilege.grant", "published": _iso(i),
                       "outcome": {"result": "SUCCESS"}, "actor": {"alternateId": _pick(rng, _USERS)},
                       "target": [{"displayName": "Super Administrator"}],
                       "securityContext": {"threatSuspected": "true"}})


def _okta_benign(rng, i):
    return json.dumps({"eventType": "user.session.start", "published": _iso(i),
                       "outcome": {"result": "SUCCESS"}, "actor": {"alternateId": _pick(rng, _BENIGN_USERS)}})


# ── azure_ad ──────────────────────────────────────────────────────────────────
def _az_attack(rng, i):
    return json.dumps({"operationName": "Add member to role", "userPrincipalName": _pick(rng, _USERS) + "@corp.com",
                       "properties": {"role": "Global Administrator"}, "riskState": "atRisk",
                       "ipAddress": _pick(rng, _EXT_IPS)})


def _az_benign(rng, i):
    return json.dumps({"operationName": "Sign-in activity", "userPrincipalName": _pick(rng, _BENIGN_USERS) + "@corp.com",
                       "riskState": "none", "ipAddress": _pick(rng, _INT_IPS)})


# ── gcp_audit ─────────────────────────────────────────────────────────────────
def _gcp_attack(rng, i):
    return json.dumps({"protoPayload": {"methodName": "SetIamPolicy",
                       "authenticationInfo": {"principalEmail": "backdoor-sa@proj.iam.gserviceaccount.com"},
                       "request": {"policy": {"bindings": [{"role": "roles/owner"}]}}},
                       "resource": {"type": "project"}})


def _gcp_benign(rng, i):
    return json.dumps({"protoPayload": {"methodName": "storage.objects.get",
                       "authenticationInfo": {"principalEmail": "monitoring@proj.iam.gserviceaccount.com"}},
                       "resource": {"type": "gcs_bucket"}})


# ── o365 ──────────────────────────────────────────────────────────────────────
def _o365_attack(rng, i):
    return json.dumps({"Operation": "Set-TransportRule", "UserId": _pick(rng, _USERS) + "@corp.com",
                       "CreationTime": _iso(i), "Parameters": [{"Name": "RedirectMessageTo", "Value": "attacker@evil.com"}]})


def _o365_benign(rng, i):
    return json.dumps({"Operation": "UserLoggedIn", "UserId": _pick(rng, _BENIGN_USERS) + "@corp.com",
                       "CreationTime": _iso(i)})


# ── wazuh_siem ────────────────────────────────────────────────────────────────
def _wazuh_attack(rng, i):
    return json.dumps({"rule": {"level": 12, "description": "Multiple SSH brute force then success", "id": "5720"},
                       "agent": {"name": "web01"}, "data": {"srcip": _pick(rng, _EXT_IPS)}})


def _wazuh_benign(rng, i):
    return json.dumps({"rule": {"level": 3, "description": "sshd: authentication success", "id": "5715"},
                       "agent": {"name": "web01"}})


# ── microsoft_defender ────────────────────────────────────────────────────────
def _defender_attack(rng, i):
    return json.dumps({"AlertId": f"da{1000 + i}", "Title": "Ransomware behavior detected",
                       "Severity": "High", "Category": "Malware",
                       "MitreTechniques": ["T1486", "T1003.001"], "Cve": "CVE-2026-31431"})


def _defender_benign(rng, i):
    return json.dumps({"AlertId": f"da{2000 + i}", "Title": "Informational: scan completed",
                       "Severity": "Informational", "Category": "None"})


# ── nmap ──────────────────────────────────────────────────────────────────────
def _nmap_attack(rng, i):
    ip = _pick(rng, _INT_IPS)
    return f"Nmap scan report for {ip} — 22/tcp open ssh, 4444/tcp open metasploit, CVE-2024-21410 detected"


def _nmap_benign(rng, i):
    return f"Nmap scan report for {_pick(rng, _INT_IPS)} — host is up, all 1000 scanned ports filtered"


TEMPLATES: dict[str, dict[str, list[LineFn]]] = {
    "cloudtrail": {"attack": [_ct_attack], "benign": [_ct_benign]},
    "windows_evtx": {"attack": [_win_attack], "benign": [_win_benign]},
    "syslog": {"attack": [_sys_attack], "benign": [_sys_benign]},
    "okta_sso": {"attack": [_okta_attack], "benign": [_okta_benign]},
    "azure_ad": {"attack": [_az_attack], "benign": [_az_benign]},
    "gcp_audit": {"attack": [_gcp_attack], "benign": [_gcp_benign]},
    "o365": {"attack": [_o365_attack], "benign": [_o365_benign]},
    "wazuh_siem": {"attack": [_wazuh_attack], "benign": [_wazuh_benign]},
    "microsoft_defender": {"attack": [_defender_attack], "benign": [_defender_benign]},
    "nmap": {"attack": [_nmap_attack], "benign": [_nmap_benign]},
}

ALL_TYPES = list(TEMPLATES)


def generate_labeled(
    count: int = 50,
    attack_ratio: float = 0.35,
    types: list[str] | None = None,
    seed: int = 0,
) -> list[tuple[str, bool, str]]:
    """Return `count` (log_type, is_attack, line) tuples, deterministic per seed."""
    types = types or ALL_TYPES
    unknown = [t for t in types if t not in TEMPLATES]
    if unknown:
        raise ValueError(f"unknown log types: {unknown}. Known: {ALL_TYPES}")
    rng = random.Random(seed)
    out: list[tuple[str, bool, str]] = []
    for i in range(count):
        log_type = _pick(rng, types)
        is_attack = rng.random() < attack_ratio
        fn = _pick(rng, TEMPLATES[log_type]["attack" if is_attack else "benign"])
        out.append((log_type, is_attack, fn(rng, i)))
    return out


def generate(
    count: int = 50,
    attack_ratio: float = 0.35,
    types: list[str] | None = None,
    seed: int = 0,
) -> list[str]:
    """Return `count` synthetic log lines, deterministic for a given seed."""
    return [line for _, _, line in generate_labeled(count, attack_ratio, types, seed)]


def _main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="log_generator.generate")
    p.add_argument("--count", type=int, default=50)
    p.add_argument("--attack-ratio", type=float, default=0.35)
    p.add_argument("--types", type=str, default="", help="comma-separated subset of the known types")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--out", type=str, default="", help="write to a file instead of stdout")
    p.add_argument("--post", type=str, default="", help="POST the batch to a Furix /api/ingest URL")
    args = p.parse_args(argv)

    types = [t.strip() for t in args.types.split(",") if t.strip()] or None
    lines = generate(args.count, args.attack_ratio, types, args.seed)
    text = "\n".join(lines)

    if args.post:
        import urllib.request
        body = json.dumps({"text": text, "log_type": "auto"}).encode()
        req = urllib.request.Request(args.post, data=body,
                                     headers={"content-type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
            print(resp.read().decode())
        return 0
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"wrote {len(lines)} lines → {args.out}")
        return 0
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
