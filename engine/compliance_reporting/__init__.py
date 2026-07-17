"""
compliance_reporting
====================
Vanta/Drata-style compliance reporting for the Furix deterministic pipeline.

Implements the industry-standard three-layer join on top of a batch run:

    test (policy rule POL-001..015)  →  control (CIS v8.1)  →  framework
                                                                (CIS / NIST CSF / HIPAA)

Design rules (deliberately stricter than the rest of the repo):
  * No side effects at import time — nothing runs, nothing connects.
  * No hard dependency on the databases: the crosswalk is injected from
    db_connections when available, else a bundled, clearly-labelled snapshot.
  * Deterministic output: the report's content hash covers everything except
    volatile metadata, and report_id is derived from that hash — the same
    batch always produces the identical report.
  * Verifiable output: verifier.verify_report() recomputes the report from
    the raw batch through an independent code path and checks referential
    integrity, conservation laws, and the integrity hash.

Integration (add after complete_log_pipeline_run() in pipeline.py):

    from compliance_reporting import build_report, verify_report, render_html_report

    report = build_report(pipeline_results)
    verification = verify_report(report, pipeline_results)
    if not verification.ok:
        raise RuntimeError(f"Compliance report failed verification: {verification.failures}")

    out_json = OUTPUT_DIR / f"{ts}_compliance_report.json"
    out_json.write_text(json.dumps(report, indent=2))
    (OUTPUT_DIR / f"{ts}_compliance_report.html").write_text(render_html_report(report))
"""

from .registry import FrameworkRegistry, TEST_CATALOG, CONTROL_CATALOG
from .report_builder import build_report
from .verifier import verify_report, VerificationResult
from .render_html import render_html_report
from .history import ReportStore, IntegrityError, check_report_integrity
from .diff import diff_reports, alerts_from_diff, render_diff_text
from .delivery import deliver_alerts, ConsoleSink, JsonlSink, WebhookSink, MultiSink
from .settings import Settings
from .detection import AttackPivotResolver

__all__ = [
    "FrameworkRegistry",
    "TEST_CATALOG",
    "CONTROL_CATALOG",
    "build_report",
    "verify_report",
    "VerificationResult",
    "render_html_report",
    "ReportStore",
    "IntegrityError",
    "check_report_integrity",
    "diff_reports",
    "alerts_from_diff",
    "render_diff_text",
    "deliver_alerts",
    "ConsoleSink",
    "JsonlSink",
    "WebhookSink",
    "MultiSink",
    "Settings",
    "AttackPivotResolver",
]
