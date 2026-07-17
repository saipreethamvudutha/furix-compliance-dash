"""
Command-line interface for the compliance reporting engine.

    python3 -m compliance_reporting demo    [--store DIR]
    python3 -m compliance_reporting history [--store DIR]
    python3 -m compliance_reporting trend   [--store DIR]
    python3 -m compliance_reporting diff    OLD_ID NEW_ID [--store DIR]
    python3 -m compliance_reporting verify  REPORT_ID     [--store DIR]
    python3 -m compliance_reporting detect  --log-type T [--file F | LOG_TEXT]

`demo` runs BOTH fixture batches (attack week + remediated week), saves them
to the store, prints the diff, and DELIVERS regression alerts through the
configured sinks. `detect` runs the ATT&CK/Sigma pivot on a single log and
shows the control ← technique ← rule provenance. `verify` re-verifies a stored
report: integrity always; full recomputation against the archived batch when
one was stored.

Configuration is via environment variables (see settings.py). Exit codes:
0 ok · 1 verification/integrity/delivery failure · 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .delivery import deliver_alerts
from .detection import AttackPivotResolver
from .diff import alerts_from_diff, diff_reports, render_diff_text
from .fixtures import demo_batch, demo_batch_remediated
from .history import IntegrityError, ReportStore
from .registry import FrameworkRegistry
from .render_html import render_html_report
from .report_builder import build_report
from .settings import Settings
from .verifier import verify_report


def _print_posture(report: dict) -> None:
    b, s = report["batch"], report["summary"]
    print(f"report {report['report_id'][:8]} · {b['total_logs']} logs · "
          f"{s['total_violations']} violations")
    for fw in report["frameworks"]:
        pct = fw["compliance_pct"]
        print(f"  {fw['name']:<24} {'n/a' if pct is None else f'{pct:g}%':<8} "
              f"({fw['requirements_compliant']} ok / {fw['requirements_at_risk']} at risk / "
              f"{fw['requirements_not_monitored']} unmonitored)")


def cmd_demo(store: ReportStore, settings: Settings) -> int:
    registry = FrameworkRegistry.from_live()
    runs = [
        ("attack week", demo_batch()),
        ("after remediation", demo_batch_remediated()),
    ]
    reports = []
    for label, batch in runs:
        report = build_report(batch, registry=registry, engine_version=settings.engine_version)
        verification = verify_report(report, batch)
        print(f"── {label} " + "─" * (50 - len(label)))
        _print_posture(report)
        print(f"  {verification.summary().splitlines()[0]}")
        if not verification.ok:
            print(verification.summary())
            return 1
        path = store.save(report, batch=batch)
        html = path.with_suffix(".html")
        html.write_text(render_html_report(report), encoding="utf-8")
        print(f"  stored → {path}")
        reports.append(report)
        print()

    # forward diff (improvement) then reverse (regression) to show alert delivery
    diff = diff_reports(reports[0], reports[1])
    print("── diff: attack week → after remediation " + "─" * 12)
    print(render_diff_text(diff))
    print(f"\nforward alerts (improvements never page): {len(alerts_from_diff(diff))}")

    regression = diff_reports(reports[1], reports[0], verify=False)
    reg_alerts = alerts_from_diff(regression, framework_drop_threshold=settings.framework_drop_threshold)
    print(f"\n── if this had been a REGRESSION, {len(reg_alerts)} alert(s) would deliver:")
    context = {"new_report_id": reports[0]["report_id"], "old_report_id": reports[1]["report_id"]}
    results = deliver_alerts(reg_alerts, settings.build_sinks(), context=context)
    for r in results:
        status = "ok" if r.ok else f"FAILED: {r.error}"
        print(f"  sink {r.sink}: {r.delivered} delivered ({status})")
    return 0 if all(r.ok for r in results) else 1


def cmd_detect(log_text: str, log_type: str) -> int:
    resolver = AttackPivotResolver.load()
    result = resolver.resolve(log_text, log_type)
    print(f"log_type: {log_type}")
    print(f"controls: {', '.join(result.control_ids) or '(none)'}")
    print(f"techniques: {', '.join(result.technique_ids) or '(none)'}")
    print(f"worst level: {result.worst_level}")
    if result.provenance():
        print("provenance (control ← technique ← rule):")
        for row in result.provenance():
            print(f"  {row['control_id']:<11} ← {row['technique_id']:<10} "
                  f"({row['technique_name']}) ← {row['rule_id']} [{row['rule_level']}]")
    return 0


def cmd_history(store: ReportStore) -> int:
    entries = store.entries()
    if not entries:
        print("store is empty")
        return 0
    for e in entries:
        pcts = " · ".join(
            f"{fw}:{'n/a' if p is None else f'{p:g}%'}"
            for fw, p in sorted(e.framework_pct.items())
        )
        print(f"{e.generated_at}  {e.report_id[:8]}  logs={e.total_logs} "
              f"violations={e.total_violations}  {pcts}")
    return 0


def cmd_trend(store: ReportStore) -> int:
    series = store.trend()
    if not series:
        print("store is empty")
        return 0
    frameworks = sorted(series[-1]["framework_pct"])
    header = f"{'generated_at':<26}{'violations':>11}" + "".join(f"{fw:>22}" for fw in frameworks)
    print(header)
    for row in series:
        cells = "".join(
            f"{('n/a' if row['framework_pct'].get(fw) is None else f'{row['framework_pct'][fw]:g}%'):>22}"
            for fw in frameworks
        )
        print(f"{row['generated_at']:<26}{row['total_violations']:>11}{cells}")
    return 0


def cmd_diff(store: ReportStore, old_id: str, new_id: str) -> int:
    old, new = store.load(_resolve(store, old_id)), store.load(_resolve(store, new_id))
    diff = diff_reports(old, new)
    print(render_diff_text(diff))
    alerts = alerts_from_diff(diff)
    print(f"\nalerts: {len(alerts)}")
    for a in alerts:
        print(f"  [{a['severity']}] {a['type']}: {a['message']}")
    return 0


def cmd_verify(store: ReportStore, report_id: str) -> int:
    report = store.load(_resolve(store, report_id))  # integrity check inside
    print(f"integrity OK for {report['report_id']}")
    batch = store.load_batch(report["report_id"])
    if batch is None:
        print("no archived batch — full recomputation unavailable (integrity-only verify)")
        return 0
    result = verify_report(report, batch)
    print(result.summary())
    return 0 if result.ok else 1


def _resolve(store: ReportStore, prefix: str) -> str:
    """Allow 8-char id prefixes the way git does."""
    matches = [e.report_id for e in store.entries() if e.report_id.startswith(prefix)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise FileNotFoundError(f"no stored report matches {prefix!r}")
    raise ValueError(f"ambiguous prefix {prefix!r}: {matches}")


def main(argv: list[str] | None = None) -> int:
    settings = Settings.from_env()
    parser = argparse.ArgumentParser(prog="compliance_reporting")
    parser.add_argument("--store", type=Path, default=settings.store_path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo")
    sub.add_parser("history")
    sub.add_parser("trend")
    p_diff = sub.add_parser("diff")
    p_diff.add_argument("old_id")
    p_diff.add_argument("new_id")
    p_verify = sub.add_parser("verify")
    p_verify.add_argument("report_id")
    p_detect = sub.add_parser("detect")
    p_detect.add_argument("--log-type", required=True)
    p_detect.add_argument("--file", type=Path, help="read the log from a file")
    p_detect.add_argument("log_text", nargs="?", default="", help="inline log text")

    args = parser.parse_args(argv)
    store = ReportStore(args.store)
    try:
        if args.command == "demo":
            return cmd_demo(store, settings)
        if args.command == "history":
            return cmd_history(store)
        if args.command == "trend":
            return cmd_trend(store)
        if args.command == "diff":
            return cmd_diff(store, args.old_id, args.new_id)
        if args.command == "verify":
            return cmd_verify(store, args.report_id)
        if args.command == "detect":
            log_text = args.file.read_text(encoding="utf-8") if args.file else args.log_text
            if not log_text:
                print("error: provide LOG_TEXT or --file", file=sys.stderr)
                return 2
            return cmd_detect(log_text, args.log_type)
    except (IntegrityError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
