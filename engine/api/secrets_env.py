"""
secrets_env.py
==============
Docker-secrets-friendly env resolution (Wave-I / deployment contract). For any
sensitive setting `X`, a `X_FILE` variable pointing at a mounted secret file
takes precedence over the inline `X` — so production can inject secrets via
Docker/Kubernetes secrets (files under /run/secrets) instead of environment
variables that leak into `docker inspect`, logs, and child processes.

Mirrors the pattern already used for `FURIX_API_KEYS_FILE`.
"""

from __future__ import annotations

import os


def read_secret(name: str, default: str = "") -> str:
    """Return the value of `name`, preferring the file named by `{name}_FILE`."""
    path = os.environ.get(f"{name}_FILE", "")
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            # a configured secret file that cannot be read is a hard misconfig;
            # return empty so the caller's fail-closed check trips.
            return ""
    return os.environ.get(name, default)
