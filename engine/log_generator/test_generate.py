"""
test_generate.py
================
Tests the synthetic log generator, including the key correctness property:
every generated line classifies to its INTENDED log type via the real,
dependency-free `log_ingest.detect_log_type` (so a generated batch actually
exercises the right pipeline paths).

    python3 -m log_generator.test_generate
"""

from __future__ import annotations

from log_ingest import detect_log_type

from . import generate, generate_labeled, ALL_TYPES


def test_count_exact():
    assert len(generate(count=50, seed=1)) == 50
    assert len(generate(count=7, seed=1)) == 7
    assert len(generate(count=0, seed=1)) == 0


def test_deterministic_by_seed():
    a = generate(count=40, attack_ratio=0.4, seed=123)
    b = generate(count=40, attack_ratio=0.4, seed=123)
    assert a == b
    # different seed → different output (overwhelmingly likely)
    assert generate(count=40, seed=123) != generate(count=40, seed=999)


def test_every_line_classifies_to_intended_type():
    # THE correctness property: generated logs route to the right pipeline path.
    mismatches = []
    for log_type, _is_attack, line in generate_labeled(count=200, attack_ratio=0.5, seed=7):
        # each entry is a single line; classify its first line
        detected = detect_log_type(line.splitlines()[0])
        if detected != log_type:
            mismatches.append((log_type, detected, line[:70]))
    assert not mismatches, f"classification mismatches: {mismatches[:5]}"


def test_attack_ratio_honoured_approximately():
    labeled = generate_labeled(count=1000, attack_ratio=0.3, seed=42)
    attacks = sum(1 for _, is_atk, _ in labeled if is_atk)
    ratio = attacks / len(labeled)
    assert 0.25 <= ratio <= 0.35, ratio   # ~0.30 with tolerance


def test_type_subset_respected():
    subset = ["cloudtrail", "windows_evtx"]
    for log_type, _, line in generate_labeled(count=60, types=subset, seed=3):
        assert log_type in subset
        assert detect_log_type(line.splitlines()[0]) in subset


def test_unknown_type_rejected():
    try:
        generate(count=5, types=["not_a_type"], seed=1)
        raise AssertionError("expected ValueError for unknown type")
    except ValueError:
        pass


def test_all_types_have_attack_and_benign():
    from . import TEMPLATES
    for t in ALL_TYPES:
        assert TEMPLATES[t]["attack"] and TEMPLATES[t]["benign"], t


def test_attack_lines_carry_threat_signals():
    # spot-check that attack templates contain the tokens the engine keys on
    labeled = generate_labeled(count=400, attack_ratio=1.0, seed=5)
    joined_by_type: dict[str, str] = {}
    for lt, _, line in labeled:
        joined_by_type.setdefault(lt, "")
        joined_by_type[lt] += line + "\n"
    assert "backdoor" in joined_by_type.get("cloudtrail", "").lower() or \
           "administratoraccess" in joined_by_type.get("cloudtrail", "").lower()
    assert "mimikatz" in joined_by_type.get("windows_evtx", "").lower() or \
           "7045" in joined_by_type.get("windows_evtx", "")
    assert "failed password" in joined_by_type.get("syslog", "").lower()
    assert "super administrator" in joined_by_type.get("okta_sso", "").lower()


if __name__ == "__main__":
    import sys, traceback
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
    print(f"\n{len(tests) - failed}/{len(tests)} generator tests passed")
    sys.exit(1 if failed else 0)
