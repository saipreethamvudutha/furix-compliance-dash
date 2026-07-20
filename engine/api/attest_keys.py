"""
attest_keys.py
==============
Resolve the per-tenant attestation signing key ring from the environment
(Wave-F). The attestation submission API verifies every submitted signature
against this ring — so unless a deployment configures keys, submission is
fail-closed (no ring → nothing verifies → nothing is accepted).

`FURIX_ATTEST_KEYS` is JSON in one of two shapes:

* per-tenant:  ``{"acme": {"k1": "secret"}, "globex": {"k2": "..."}}``
* shared:      ``{"k1": "secret", "k2": "..."}``   (same ring for every tenant)

In development (``FURIX_ENV`` != ``production``) with no env configured, the
demo ring is used so the local workflow is exercisable; in production an
unconfigured ring yields an EMPTY ring (every submission is rejected) — never a
silent demo secret.
"""

from __future__ import annotations

import json
import os

from compliance_reporting.attestation import AttestationKeyRing

from .secrets_env import read_secret


def _is_prod() -> bool:
    return os.environ.get("FURIX_ENV", "development").lower() == "production"


def attestation_keyring_for(tenant: str) -> AttestationKeyRing:
    raw = read_secret("FURIX_ATTEST_KEYS")
    if raw:
        data = json.loads(raw)
        # nested per-tenant shape if any value is itself a dict
        if data and all(isinstance(v, dict) for v in data.values()):
            return AttestationKeyRing(dict(data.get(tenant, {})))
        # flat shared shape
        return AttestationKeyRing(dict(data))

    if _is_prod():
        return AttestationKeyRing({})  # fail-closed: no keys → nothing verifies

    # development convenience only
    from compliance_reporting.fixtures import demo_attestation_keyring
    return demo_attestation_keyring()
