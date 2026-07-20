"""
attestation.py
==============
Strict, signed attestation schema for manual/operational evidence (Wave-N).

The Wave-E manual attestations accepted any dict with a spec_id and a date. An
enterprise attestation must be **accountable and tamper-evident**: it names who
attested, what they attested, when, the evidence it points at, the tenant/scope
it applies to, and it is **signed** with a key whose id is recorded. An
attestation that is unsigned, badly signed, missing a required field, or
future-dated is `INVALID` and can only ever drive a control to
`MANUAL_PENDING` — never `PASS`.

Signature: HMAC-SHA256 over the canonical attestation payload with a per-key
secret from an `AttestationKeyRing` (`key_id → secret`). The signature covers
every material field, so changing any of them invalidates it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

# verification_status values
VERIFIED = "verified"
INVALID = "invalid"

REQUIRED_FIELDS = (
    "spec_id", "attester", "attested_at", "evidence_ref", "statement",
    "tenant", "scope", "key_id", "signature",
)

# fields the signature is computed over (everything material except the
# signature itself and the derived verification_status)
_SIGNED_FIELDS = ("spec_id", "attester", "attested_at", "evidence_ref",
                  "statement", "tenant", "scope", "key_id")


@dataclass(frozen=True)
class AttestationKeyRing:
    """Maps a key_id to its signing secret. Configured per tenant/deployment."""

    keys: Mapping[str, str]

    def secret(self, key_id: str) -> str | None:
        return self.keys.get(key_id)


def canonical_payload(att: Mapping[str, Any]) -> str:
    return json.dumps({k: att.get(k) for k in _SIGNED_FIELDS},
                      sort_keys=True, separators=(",", ":"))


def sign_attestation(att: Mapping[str, Any], secret: str) -> str:
    """Compute the HMAC-SHA256 signature for an attestation payload."""
    return hmac.new(secret.encode("utf-8"),
                    canonical_payload(att).encode("utf-8"), hashlib.sha256).hexdigest()


def make_attestation(*, spec_id: str, attester: str, attested_at: str, evidence_ref: str,
                     statement: str, tenant: str, scope: str, key_id: str,
                     keyring: AttestationKeyRing) -> dict[str, Any]:
    """Build a fully-signed attestation (used by attesters and in tests)."""
    att = {"spec_id": spec_id, "attester": attester, "attested_at": attested_at,
           "evidence_ref": evidence_ref, "statement": statement, "tenant": tenant,
           "scope": scope, "key_id": key_id}
    secret = keyring.secret(key_id)
    if secret is None:
        raise ValueError(f"no signing secret for key_id {key_id!r}")
    att["signature"] = sign_attestation(att, secret)
    return att


def verify_attestation(att: Mapping[str, Any], keyring: AttestationKeyRing,
                       *, tenant: str, as_of: str | None = None) -> tuple[str, list[str]]:
    """
    Verify an attestation. Returns (verification_status, reasons). VERIFIED only
    when every required field is present, the tenant matches, the timestamp is
    not in the future (relative to as_of), and the signature checks out against
    the named key. Otherwise INVALID with reasons.
    """
    reasons: list[str] = []
    missing = [f for f in REQUIRED_FIELDS if not att.get(f)]
    if missing:
        reasons.append(f"missing fields: {', '.join(missing)}")

    if att.get("tenant") and att["tenant"] != tenant:
        reasons.append(f"tenant mismatch: attestation for {att.get('tenant')!r}, evaluating {tenant!r}")

    # future-dated attestations are never valid
    if att.get("attested_at") and as_of:
        try:
            if datetime.fromisoformat(str(att["attested_at"])) > datetime.fromisoformat(str(as_of)):
                reasons.append("attestation is future-dated")
        except ValueError:
            reasons.append("attested_at is not a valid ISO timestamp")

    # signature check
    key_id = att.get("key_id")
    secret = keyring.secret(str(key_id)) if key_id else None
    if secret is None:
        reasons.append(f"unknown or unconfigured key_id: {key_id!r}")
    elif not att.get("signature"):
        reasons.append("missing signature")
    else:
        expected = sign_attestation(att, secret)
        if not hmac.compare_digest(expected, str(att["signature"])):
            reasons.append("signature does not verify")

    return (VERIFIED if not reasons else INVALID), reasons
