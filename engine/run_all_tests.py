#!/usr/bin/env python3
"""
run_all_tests.py
================
Runs every self-contained engine test module and aggregates the result. Used by
CI and for a one-command local check. Exits non-zero if any module fails.

    python3 run_all_tests.py
"""

from __future__ import annotations

import importlib
import os
import sys

# Strict mode (set by CI): a REQUIRED suite that is skipped — because its
# third-party dependency is missing or the module won't import — becomes a
# FAILURE. A skipped required suite must never be mistaken for a passing one.
STRICT = os.environ.get("FURIX_TEST_STRICT") == "1"

# Suites that need third-party dependencies to run meaningfully. Under strict
# mode these deps MUST be present (CI installs test-requirements.txt); their
# absence fails the run instead of silently skipping the coverage.
REQUIRED_DEPS: dict[str, tuple[str, ...]] = {
    "api.test_integration": ("fastapi", "httpx"),
    "compliance_reporting.test_oscal": ("jsonschema",),
}

MODULES = [
    "compliance_reporting.test_reporting",
    "compliance_reporting.test_evidence",
    "compliance_reporting.test_config",
    "compliance_reporting.test_manual",
    "compliance_reporting.test_attestation",
    "compliance_reporting.test_attestation_store",
    "compliance_reporting.test_collectors",
    "compliance_reporting.test_aws_boto3",
    "compliance_reporting.test_connector_registry",
    "compliance_reporting.test_exceptions",
    "compliance_reporting.test_oscal",
    "compliance_reporting.adapters.test_adapter",
    "compliance_reporting.detection.test_detection",
    "compliance_reporting.test_delivery",
    "test_scf_crosswalk",
    "test_attack_enrich",
    "log_generator.test_generate",
    "api.test_service",
    "api.test_jobs",
    "api.test_auth",
    "api.test_durable",
    "api.test_preflight",
    "api.test_integration",
]


def _missing_deps(deps: tuple[str, ...]) -> list[str]:
    missing = []
    for d in deps:
        try:
            importlib.import_module(d)
        except Exception:  # noqa: BLE001
            missing.append(d)
    return missing


def _run_module(name: str) -> tuple[int, int]:
    """Run a module's test_* functions; return (passed, failed)."""
    missing = _missing_deps(REQUIRED_DEPS.get(name, ()))
    if missing:
        if STRICT:
            print(f"  FAIL  {name}: required dependencies missing: {', '.join(missing)}")
            return (0, 1)
        print(f"  SKIP  {name} (missing deps: {', '.join(missing)})")
        return (0, 0)
    try:
        mod = importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if STRICT:
            print(f"  FAIL  {name}: required suite is not importable: {exc}")
            return (0, 1)
        print(f"  SKIP  {name} (not importable here)")
        return (0, 0)
    tests = [(n, f) for n, f in sorted(vars(mod).items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for tname, fn in tests:
        try:
            fn()
            passed += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL  {name}.{tname}: {exc}")
    # In strict mode a required suite that ran zero tests is a failure — it means
    # the coverage silently evaporated (e.g. every test self-skipped).
    if STRICT and (passed + failed) == 0:
        print(f"  FAIL  {name}: required suite ran no tests")
        return (0, 1)
    status = "ok " if failed == 0 else "FAIL"
    print(f"  [{status}] {name}: {passed}/{passed + failed}")
    return (passed, failed)


def main() -> int:
    total_p = total_f = 0
    for m in MODULES:
        p, f = _run_module(m)
        total_p += p
        total_f += f
    mode = " (strict)" if STRICT else ""
    print(f"\n{'=' * 48}\nTOTAL{mode}: {total_p} passed, {total_f} failed")
    return 1 if total_f else 0


if __name__ == "__main__":
    sys.exit(main())
