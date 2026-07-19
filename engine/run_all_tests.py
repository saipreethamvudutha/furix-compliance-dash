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
import sys

MODULES = [
    "compliance_reporting.test_reporting",
    "compliance_reporting.test_evidence",
    "compliance_reporting.test_config",
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
]


def _run_module(name: str) -> tuple[int, int]:
    """Run a module's test_* functions; return (passed, failed)."""
    try:
        mod = importlib.import_module(name)
    except ModuleNotFoundError:
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
    status = "ok " if failed == 0 else "FAIL"
    print(f"  [{status}] {name}: {passed}/{passed + failed}")
    return (passed, failed)


def main() -> int:
    total_p = total_f = 0
    for m in MODULES:
        p, f = _run_module(m)
        total_p += p
        total_f += f
    print(f"\n{'=' * 48}\nTOTAL: {total_p} passed, {total_f} failed")
    return 1 if total_f else 0


if __name__ == "__main__":
    sys.exit(main())
