"""
preflight.py
============
Fail-closed production readiness checks (Wave-E hardening, addresses the audit's
P0/P1 "silent optional" findings). When `FURIX_ENV=production`, the API refuses
to start unless the security posture is real:

  * no default dev API key in the key set,
  * a durable job DB is configured (jobs must survive restarts),
  * if evidence encryption is configured, the cipher dependency is actually
    present (no silent plaintext fallback),
  * if OIDC/JWKS is configured, the verification dependency is present,
  * TLS/secret hygiene is asserted via explicit acknowledgement.

Outside production these become warnings, so local development stays friction-
free. The point is that a production deployment can never *silently* run in a
weaker mode than its configuration implies.
"""

from __future__ import annotations

import json
import os

from .auth import DEV_KEY


class PreflightError(RuntimeError):
    """A production readiness check failed — the process must not serve."""


def _is_prod() -> bool:
    return os.environ.get("FURIX_ENV", "").lower() == "production"


def _configured_keys() -> list[dict]:
    raw = ""
    kf = os.environ.get("FURIX_API_KEYS_FILE", "")
    if kf and os.path.exists(kf):
        with open(kf, encoding="utf-8") as fh:
            raw = fh.read()
    else:
        raw = os.environ.get("FURIX_API_KEYS", "")
    if not raw.strip():
        return []
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return []


def _crypto_available() -> bool:
    try:
        import cryptography  # noqa: F401,PLC0415
        return True
    except ImportError:
        return False


def _pyjwt_available() -> bool:
    try:
        import jwt  # noqa: F401,PLC0415
        return True
    except ImportError:
        return False


def collect_issues() -> list[str]:
    """Return the list of production-readiness violations ([] == ready)."""
    issues: list[str] = []
    keys = _configured_keys()

    # 1. no default/placeholder keys in production
    if any(str(k.get("key")) == DEV_KEY for k in keys):
        issues.append("default dev API key present in FURIX_API_KEYS — replace with real random keys")
    if any("CHANGE-ME" in str(k.get("key", "")) for k in keys):
        issues.append("placeholder CHANGE-ME key present in FURIX_API_KEYS — generate real keys "
                      "(openssl rand -hex 24)")
    if not keys:
        issues.append("no FURIX_API_KEYS configured — every request would be denied")

    # 2. durable jobs required in prod (FUR-OPS-001)
    if not os.environ.get("FURIX_JOB_DB"):
        issues.append("FURIX_JOB_DB not set — jobs would not survive a restart")

    # 3. evidence encryption configured → cipher dependency must be present
    if os.environ.get("FURIX_EVIDENCE_MASTER_KEY") and not _crypto_available():
        issues.append("FURIX_EVIDENCE_MASTER_KEY set but `cryptography` is not installed — "
                      "evidence would fall back to plaintext")

    # 4. OIDC RS256/JWKS configured → verification dependency must be present
    if os.environ.get("FURIX_OIDC_JWKS_URL") and not _pyjwt_available():
        issues.append("FURIX_OIDC_JWKS_URL set but `pyjwt[crypto]` is not installed — "
                      "RS256 tokens could not be verified")

    # 5. TLS acknowledgement — the bearer key is a secret in transit
    if os.environ.get("FURIX_TLS_TERMINATED", "").lower() not in ("1", "true", "yes"):
        issues.append("FURIX_TLS_TERMINATED not acknowledged — confirm TLS terminates in front "
                      "of the API before exposing it (set FURIX_TLS_TERMINATED=1)")
    return issues


def run(strict: bool | None = None) -> list[str]:
    """
    Run the checks. In production (or strict=True) a violation raises
    PreflightError and the process must not serve. Otherwise issues are warned
    and returned. Returns the issue list.
    """
    strict = _is_prod() if strict is None else strict
    issues = collect_issues()
    if not issues:
        print("[preflight] production readiness: OK")
        return issues
    if strict:
        raise PreflightError(
            "production readiness checks failed:\n  - " + "\n  - ".join(issues)
        )
    for i in issues:
        print(f"[preflight] WARNING: {i}")
    return issues
