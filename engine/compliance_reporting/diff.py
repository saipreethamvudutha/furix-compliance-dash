"""
diff.py
=======
Deterministic comparison of two compliance reports — the "did we get better
or worse?" engine, and the source of regression alerts.

diff_reports(old, new) answers, with stable ordering:
  * per framework: old %, new %, delta, direction
  * per control:   regressed / improved / still_at_risk / newly_monitored
  * per test:      newly_failing / newly_passing
  * violations:    totals and delta

alerts_from_diff(diff) turns regressions into structured alert dicts —
the primitive a webhook, Slack notifier, or ticket creator consumes.
Delivery is deliberately out of scope: this module computes, never sends.
"""

from __future__ import annotations

from typing import Any, Mapping

from .history import check_report_integrity

_AT_RISK, _COMPLIANT, _NOT_MONITORED = "at_risk", "compliant", "not_monitored"


def _by_id(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {row[key]: row for row in rows}


def diff_reports(
    old: Mapping[str, Any], new: Mapping[str, Any], *, verify: bool = True
) -> dict[str, Any]:
    """
    Compare two reports (typically consecutive batches). Both are integrity-
    checked first unless verify=False (only sensible in unit tests).

    Returns a plain dict, deterministic for a given pair of inputs.
    """
    if verify:
        check_report_integrity(old)
        check_report_integrity(new)

    # ── frameworks ────────────────────────────────────────────────────────────
    old_fw = _by_id(old["frameworks"], "framework_id")
    new_fw = _by_id(new["frameworks"], "framework_id")
    frameworks: list[dict[str, Any]] = []
    for fw_id in sorted(set(old_fw) | set(new_fw)):
        o = old_fw.get(fw_id, {}).get("compliance_pct")
        n = new_fw.get(fw_id, {}).get("compliance_pct")
        if o is None or n is None:
            delta, direction = None, "no_data"
        else:
            delta = round(n - o, 1)
            direction = "improved" if delta > 0 else ("regressed" if delta < 0 else "unchanged")
        frameworks.append(
            {
                "framework_id": fw_id,
                "name": (new_fw.get(fw_id) or old_fw.get(fw_id, {})).get("name", fw_id),
                "old_pct": o,
                "new_pct": n,
                "delta": delta,
                "direction": direction,
            }
        )

    # ── controls ──────────────────────────────────────────────────────────────
    old_ctrl = _by_id(old["controls"], "control_id")
    new_ctrl = _by_id(new["controls"], "control_id")
    regressed, improved, still_at_risk, newly_monitored = [], [], [], []
    for cid in sorted(set(old_ctrl) | set(new_ctrl), key=lambda c: int(c.split()[-1])):
        o = old_ctrl.get(cid, {}).get("status", _NOT_MONITORED)
        n = new_ctrl.get(cid, {}).get("status", _NOT_MONITORED)
        row = {
            "control_id": cid,
            "title": (new_ctrl.get(cid) or old_ctrl.get(cid, {})).get("title", ""),
            "old_status": o,
            "new_status": n,
            "new_violations": new_ctrl.get(cid, {}).get("violation_count", 0),
            "worst_severity": new_ctrl.get(cid, {}).get("worst_severity", ""),
        }
        if n == _AT_RISK and o != _AT_RISK:
            regressed.append(row)
        elif o == _AT_RISK and n == _COMPLIANT:
            improved.append(row)
        elif o == _AT_RISK and n == _AT_RISK:
            still_at_risk.append(row)
        elif o == _NOT_MONITORED and n in (_COMPLIANT, _AT_RISK):
            newly_monitored.append(row)

    # ── tests ─────────────────────────────────────────────────────────────────
    old_tests = _by_id(old["tests"], "test_id")
    new_tests = _by_id(new["tests"], "test_id")
    newly_failing, newly_passing = [], []
    for tid in sorted(set(old_tests) | set(new_tests)):
        o = old_tests.get(tid, {}).get("status", "no_data")
        n = new_tests.get(tid, {}).get("status", "no_data")
        row = {
            "test_id": tid,
            "title": (new_tests.get(tid) or old_tests.get(tid, {})).get("title", ""),
            "severity": (new_tests.get(tid) or old_tests.get(tid, {})).get("severity", ""),
            "old_status": o,
            "new_status": n,
            "occurrences": new_tests.get(tid, {}).get("occurrences", 0),
        }
        if n == "fail" and o != "fail":
            newly_failing.append(row)
        elif o == "fail" and n == "pass":
            newly_passing.append(row)

    old_v = old["summary"]["total_violations"]
    new_v = new["summary"]["total_violations"]

    return {
        "old_report_id": old["report_id"],
        "new_report_id": new["report_id"],
        "old_generated_at": old["generated_at"],
        "new_generated_at": new["generated_at"],
        "frameworks": frameworks,
        "controls": {
            "regressed": regressed,
            "improved": improved,
            "still_at_risk": still_at_risk,
            "newly_monitored": newly_monitored,
        },
        "tests": {"newly_failing": newly_failing, "newly_passing": newly_passing},
        "violations": {"old_total": old_v, "new_total": new_v, "delta": new_v - old_v},
        "summary_line": _summary_line(frameworks, regressed, improved, old_v, new_v),
    }


def _summary_line(frameworks, regressed, improved, old_v, new_v) -> str:
    moved = [f for f in frameworks if f["direction"] in ("improved", "regressed")]
    fw_bit = (
        "; ".join(f"{f['framework_id']} {f['old_pct']}%→{f['new_pct']}%" for f in moved)
        or "framework posture unchanged"
    )
    return (
        f"violations {old_v}→{new_v}; {len(regressed)} control(s) regressed, "
        f"{len(improved)} improved; {fw_bit}"
    )


# ── alerts ─────────────────────────────────────────────────────────────────────
ALERT_CONTROL_REGRESSED = "control_regressed"
ALERT_FRAMEWORK_DROPPED = "framework_dropped"
ALERT_VIOLATIONS_SPIKE = "violations_increased"


def alerts_from_diff(
    diff: Mapping[str, Any], *, framework_drop_threshold: float = 5.0
) -> list[dict[str, Any]]:
    """
    Structured, deterministic alerts for the regressions in a diff.
    Severity is inherited from the failing tests where possible. An empty
    list means "nothing got worse" — improvements never alert.
    """
    alerts: list[dict[str, Any]] = []

    for row in diff["controls"]["regressed"]:
        alerts.append(
            {
                "type": ALERT_CONTROL_REGRESSED,
                "severity": row["worst_severity"] or "high",
                "control_id": row["control_id"],
                "message": (
                    f"{row['control_id']} ({row['title']}) went "
                    f"{row['old_status']} → at_risk with "
                    f"{row['new_violations']} violation(s)"
                ),
            }
        )

    for fw in diff["frameworks"]:
        if fw["direction"] == "regressed" and abs(fw["delta"]) >= framework_drop_threshold:
            alerts.append(
                {
                    "type": ALERT_FRAMEWORK_DROPPED,
                    "severity": "high",
                    "framework_id": fw["framework_id"],
                    "message": (
                        f"{fw['name']} compliance dropped "
                        f"{fw['old_pct']}% → {fw['new_pct']}% ({fw['delta']:+.1f})"
                    ),
                }
            )

    if diff["violations"]["delta"] > 0:
        alerts.append(
            {
                "type": ALERT_VIOLATIONS_SPIKE,
                "severity": "medium",
                "message": (
                    f"total violations rose {diff['violations']['old_total']} → "
                    f"{diff['violations']['new_total']}"
                ),
            }
        )

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: (order.get(a["severity"], 9), a["type"], a.get("control_id", "")))
    return alerts


def render_diff_text(diff: Mapping[str, Any]) -> str:
    """Human-readable diff summary for terminals and log files."""
    lines = [
        f"diff {diff['old_report_id'][:8]} ({diff['old_generated_at']})",
        f"  →  {diff['new_report_id'][:8]} ({diff['new_generated_at']})",
        "",
        diff["summary_line"],
        "",
    ]
    for fw in diff["frameworks"]:
        arrow = {"improved": "▲", "regressed": "▼", "unchanged": "—", "no_data": "·"}[fw["direction"]]
        lines.append(
            f"  {arrow} {fw['name']:<24} {fw['old_pct']}% → {fw['new_pct']}%"
        )
    for label, rows in (
        ("REGRESSED", diff["controls"]["regressed"]),
        ("IMPROVED", diff["controls"]["improved"]),
    ):
        for row in rows:
            lines.append(
                f"  [{label}] {row['control_id']} {row['title']} "
                f"({row['old_status']} → {row['new_status']})"
            )
    for row in diff["tests"]["newly_failing"]:
        lines.append(f"  [NEW FAIL] {row['test_id']} {row['title']} ×{row['occurrences']}")
    for row in diff["tests"]["newly_passing"]:
        lines.append(f"  [NOW PASS] {row['test_id']} {row['title']}")
    return "\n".join(lines)
