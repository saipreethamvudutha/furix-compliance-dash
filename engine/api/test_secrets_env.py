"""
test_secrets_env.py
==================
Docker-secrets-friendly env resolution (Wave-I): `X_FILE` (a mounted secret
file) wins over inline `X`.

    python3 -m api.test_secrets_env
"""

from __future__ import annotations

import os
import tempfile

from .secrets_env import read_secret


def test_inline_env_is_returned_when_no_file():
    os.environ.pop("FURIX_TEST_SECRET_FILE", None)
    os.environ["FURIX_TEST_SECRET"] = "inline-value"
    try:
        assert read_secret("FURIX_TEST_SECRET") == "inline-value"
    finally:
        os.environ.pop("FURIX_TEST_SECRET", None)


def test_file_takes_precedence_and_is_stripped():
    with tempfile.NamedTemporaryFile("w", suffix=".secret", delete=False) as fh:
        fh.write("  file-value\n")
        path = fh.name
    os.environ["FURIX_TEST_SECRET"] = "inline-value"
    os.environ["FURIX_TEST_SECRET_FILE"] = path
    try:
        assert read_secret("FURIX_TEST_SECRET") == "file-value"  # file wins, trimmed
    finally:
        os.environ.pop("FURIX_TEST_SECRET", None)
        os.environ.pop("FURIX_TEST_SECRET_FILE", None)
        os.unlink(path)


def test_unreadable_secret_file_fails_closed_to_empty():
    os.environ["FURIX_TEST_SECRET"] = "inline-value"
    os.environ["FURIX_TEST_SECRET_FILE"] = "/nonexistent/path/secret"
    try:
        # a configured-but-unreadable secret returns "" so the caller trips its
        # fail-closed check rather than silently using the inline value.
        assert read_secret("FURIX_TEST_SECRET") == ""
    finally:
        os.environ.pop("FURIX_TEST_SECRET", None)
        os.environ.pop("FURIX_TEST_SECRET_FILE", None)


def test_default_used_when_unset():
    os.environ.pop("FURIX_TEST_SECRET", None)
    os.environ.pop("FURIX_TEST_SECRET_FILE", None)
    assert read_secret("FURIX_TEST_SECRET", "fallback") == "fallback"


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
    print(f"\n{len(tests) - failed}/{len(tests)} secrets-env tests passed")
    sys.exit(1 if failed else 0)
