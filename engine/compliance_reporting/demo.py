"""
demo.py — end-to-end demonstration without any database or model.

    python3 -m compliance_reporting.demo [output_dir]

Builds the report from the bundled fixture batch, verifies it, prints the
posture summary, and writes compliance_report.{json,html}.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .fixtures import demo_batch
from .registry import FrameworkRegistry
from .report_builder import build_report
from .render_html import render_html_report
from .verifier import verify_report


def main(out_dir: Path) -> int:
    batch = demo_batch()
    registry = FrameworkRegistry.from_live()  # falls back to snapshot offline

    report = build_report(batch, registry=registry)
    verification = verify_report(report, batch)

    print(f"report_id     : {report['report_id']}")
    print(f"content sha256: {report['integrity']['content_sha256']}")
    print(f"crosswalk     : {report['crosswalk_provenance']}")
    print(f"batch         : {report['batch']['total_logs']} logs "
          f"({report['batch']['successful_logs']} analysed, "
          f"{report['batch']['failed_logs']} failed), "
          f"{report['summary']['total_violations']} violations")
    for fw in report["frameworks"]:
        pct = fw["compliance_pct"]
        print(f"  {fw['name']:<24} {'n/a' if pct is None else f'{pct:g}% compliant':<16} "
              f"({fw['requirements_compliant']} ok / {fw['requirements_at_risk']} at risk / "
              f"{fw['requirements_not_monitored']} unmonitored)")
    print()
    print(verification.summary())
    if not verification.ok:
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "compliance_report.json"
    html_path = out_dir / "compliance_report.html"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    html_path.write_text(render_html_report(report))
    print(f"\nwrote {json_path}\nwrote {html_path}")
    return 0


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("_demo_output")
    raise SystemExit(main(target))
