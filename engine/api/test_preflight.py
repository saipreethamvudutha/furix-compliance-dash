"""
test_preflight.py
=================
Fail-closed production readiness (addresses the audit's P0/P1 "silent optional").

    python3 -m api.test_preflight
"""

from __future__ import annotations

import os
from contextlib import contextmanager

from .preflight import PreflightError, collect_issues, run


@contextmanager
def _env(**over):
    old = {k: os.environ.get(k) for k in over}
    try:
        for k, v in over.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


_GOOD_KEYS = '[{"key":"a-real-random-key","key_id":"admin","tenant":"acme","role":"admin"}]'


def test_default_dev_key_flagged():
    with _env(FURIX_ENV="production", FURIX_JOB_DB="/tmp/j.db", FURIX_TLS_TERMINATED="1",
              FURIX_API_KEYS='[{"key":"furix-dev-key","key_id":"dev","tenant":"default","role":"admin"}]'):
        issues = collect_issues()
        assert any("default dev API key" in i for i in issues)


def test_missing_job_db_flagged():
    with _env(FURIX_ENV="production", FURIX_TLS_TERMINATED="1", FURIX_JOB_DB=None,
              FURIX_API_KEYS=_GOOD_KEYS):
        assert any("FURIX_JOB_DB" in i for i in collect_issues())


def test_encryption_without_lib_flagged():
    with _env(FURIX_ENV="production", FURIX_JOB_DB="/tmp/j.db", FURIX_TLS_TERMINATED="1",
              FURIX_API_KEYS=_GOOD_KEYS, FURIX_EVIDENCE_MASTER_KEY="deadbeef"):
        issues = collect_issues()
        try:
            import cryptography  # noqa: F401
            assert not any("cryptography" in i for i in issues)  # present → no issue
        except ImportError:
            assert any("cryptography" in i for i in issues)      # absent → flagged


def test_oidc_jwks_without_lib_flagged():
    with _env(FURIX_ENV="production", FURIX_JOB_DB="/tmp/j.db", FURIX_TLS_TERMINATED="1",
              FURIX_API_KEYS=_GOOD_KEYS, FURIX_OIDC_JWKS_URL="https://idp/jwks"):
        issues = collect_issues()
        try:
            import jwt  # noqa: F401
            assert not any("pyjwt" in i for i in issues)
        except ImportError:
            assert any("pyjwt" in i for i in issues)


def test_tls_ack_required_in_prod():
    with _env(FURIX_ENV="production", FURIX_JOB_DB="/tmp/j.db", FURIX_API_KEYS=_GOOD_KEYS,
              FURIX_TLS_TERMINATED=None):
        assert any("TLS" in i for i in collect_issues())


def test_run_raises_in_production_on_violation():
    with _env(FURIX_ENV="production", FURIX_JOB_DB=None, FURIX_TLS_TERMINATED="1",
              FURIX_API_KEYS=_GOOD_KEYS):
        try:
            run()
            raise AssertionError("preflight did not fail closed in production")
        except PreflightError:
            pass


def test_clean_production_config_passes():
    # a fully-configured prod env (crypto/oidc not enabled) must pass
    with _env(FURIX_ENV="production", FURIX_JOB_DB="/tmp/j.db", FURIX_TLS_TERMINATED="1",
              FURIX_API_KEYS=_GOOD_KEYS, FURIX_EVIDENCE_MASTER_KEY=None,
              FURIX_OIDC_JWKS_URL=None):
        assert collect_issues() == []
        assert run() == []


def test_dev_mode_only_warns():
    with _env(FURIX_ENV="development", FURIX_JOB_DB=None, FURIX_API_KEYS=None,
              FURIX_TLS_TERMINATED=None):
        # returns issues but does not raise outside production
        assert isinstance(run(), list)


def test_encryption_requires_cipher_no_silent_plaintext():
    """The sealer must not silently pass through when a key is set and no cipher."""
    from compliance_reporting.evidence_crypto import EvidenceSealer, KeyRing, NoneCipher
    # explicitly passing NoneCipher is allowed (test path); the guard is in
    # default_cipher(require=True), exercised when cryptography is absent.
    from compliance_reporting.evidence_crypto import default_cipher
    try:
        import cryptography  # noqa: F401
        assert default_cipher(require=True).algorithm != "none"
    except ImportError:
        try:
            default_cipher(require=True)
            raise AssertionError("default_cipher(require=True) silently returned a passthrough")
        except RuntimeError:
            pass


if __name__ == "__main__":
    import sys
    import traceback

    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} preflight tests passed")
    sys.exit(1 if failed else 0)
