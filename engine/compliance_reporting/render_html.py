"""
render_html.py
==============
Renders a compliance report dict (from report_builder.build_report) into a
single self-contained HTML dashboard — framework compliance rings, control
posture table, and per-test evidence drill-down. No external assets, no JS
dependencies; safe to attach to an email or drop on a file share.
"""

from __future__ import annotations

import html
from typing import Any, Mapping

_STATUS_LABEL = {
    "compliant": "Compliant",
    "at_risk": "At risk",
    "unknown": "No violations observed",
    "not_monitored": "Not monitored",
    "pass": "Pass",
    "fail": "Fail",
    "no_data": "No data",
}

_CSS = """
:root{--bg:#F4F6F8;--card:#FFFFFF;--ink:#18202B;--soft:#4A5568;--muted:#8A94A3;
--line:#DFE4EA;--ok:#0F766E;--ok-bg:#DDF0EE;--bad:#B42318;--bad-bg:#F9E3E0;
--warn:#B45309;--warn-bg:#F8ECD9;--na:#64748B;--na-bg:#E9EDF2;
--mono:ui-monospace,'SF Mono',Menlo,monospace;
--sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif}
@media (prefers-color-scheme: dark){:root{--bg:#0E1218;--card:#161C25;--ink:#E7EBF1;
--soft:#B8C0CC;--muted:#7C8698;--line:#28303C;--ok:#3EC3B8;--ok-bg:#123230;
--bad:#F08A7E;--bad-bg:#331B18;--warn:#E0B25C;--warn-bg:#2E2312;--na:#94A3B4;--na-bg:#202836}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.6 var(--sans);-webkit-font-smoothing:antialiased}
.wrap{max-width:1080px;margin:0 auto;padding:36px 22px 80px}
h1{font-size:1.7rem;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:1.15rem;margin:40px 0 14px}
.meta{font-family:var(--mono);font-size:.72rem;color:var(--muted);line-height:1.8}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin-top:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px}
.fw-name{font-weight:600}
.fw-sub{font-family:var(--mono);font-size:.72rem;color:var(--muted);margin-top:2px}
.ring{display:flex;align-items:center;gap:16px;margin-top:12px}
.donut{width:74px;height:74px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.donut span{background:var(--card);width:54px;height:54px;border-radius:50%;display:flex;
align-items:center;justify-content:center;font-family:var(--mono);font-weight:700;font-size:.82rem}
.legend{font-size:.8rem;color:var(--soft)}
.legend b{font-family:var(--mono)}
.pill{font-family:var(--mono);font-size:.66rem;font-weight:700;letter-spacing:.05em;
text-transform:uppercase;padding:3px 9px;border-radius:999px;white-space:nowrap}
.p-ok{color:var(--ok);background:var(--ok-bg)}.p-bad{color:var(--bad);background:var(--bad-bg)}
.p-warn{color:var(--warn);background:var(--warn-bg)}.p-na{color:var(--na);background:var(--na-bg)}
table{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line);
border-radius:12px;overflow:hidden;font-size:.88rem}
th{font-family:var(--mono);font-size:.66rem;letter-spacing:.08em;text-transform:uppercase;
color:var(--muted);text-align:left;padding:10px 14px;border-bottom:1px solid var(--line)}
td{padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top;color:var(--soft)}
tr:last-child td{border-bottom:0}
td .cid{font-family:var(--mono);font-weight:600;color:var(--ink);white-space:nowrap}
.tablebox{overflow-x:auto;border-radius:12px}
details{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:0;margin-top:10px;overflow:hidden}
summary{cursor:pointer;padding:13px 18px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
summary::-webkit-details-marker{display:none}
summary .tid{font-family:var(--mono);font-weight:700}
summary .ttl{color:var(--soft)}
summary .n{margin-left:auto;font-family:var(--mono);font-size:.76rem;color:var(--muted)}
.ev{border-top:1px solid var(--line);padding:12px 18px;font-family:var(--mono);font-size:.74rem;
color:var(--soft);overflow-x:auto}
.ev .row{padding:6px 0;border-bottom:1px dashed var(--line)}
.ev .row:last-child{border-bottom:0}
.ev .val{color:var(--ink);word-break:break-all}
.footer{margin-top:48px;font-family:var(--mono);font-size:.7rem;color:var(--muted);line-height:1.8}
"""


def _esc(value: Any) -> str:
    return html.escape(str(value))


def _pill(status: str) -> str:
    cls = {
        "compliant": "p-ok", "pass": "p-ok",
        "at_risk": "p-bad", "fail": "p-bad",
        "unknown": "p-warn",
        "not_monitored": "p-na", "no_data": "p-na",
    }.get(status, "p-warn")
    return f'<span class="pill {cls}">{_esc(_STATUS_LABEL.get(status, status))}</span>'


def _framework_card(fw: Mapping[str, Any]) -> str:
    # The donut shows COVERAGE (share of requirements monitored) — an honest
    # metric for detection-only evidence. A compliance % would need positive
    # assertions and is shown only when compliance_pct is actually computable.
    cov = fw.get("coverage_pct") or 0.0
    donut = (
        f'<div class="donut" style="background:conic-gradient(var(--ok) {cov * 3.6}deg,'
        f'var(--na-bg) {cov * 3.6}deg 360deg)"><span>{_esc(f"{cov:g}%")}<br>'
        f'<small>coverage</small></span></div>'
    )
    return f"""
<div class="card">
  <div class="fw-name">{_esc(fw["name"])}</div>
  <div class="fw-sub">{_esc(fw["framework_id"])}</div>
  <div class="ring">{donut}
    <div class="legend">
      <div><b>{fw["requirements_at_risk"]}</b> at risk</div>
      <div><b>{fw["requirements_unknown"]}</b> monitored, no violations observed</div>
      <div><b>{fw["requirements_not_monitored"]}</b> not monitored</div>
      <div><b>{fw["requirements_compliant"]}</b> positively compliant</div>
    </div>
  </div>
</div>"""


def _controls_table(report: Mapping[str, Any]) -> str:
    rows = []
    order = {"at_risk": 0, "unknown": 1, "compliant": 2, "not_monitored": 3}
    for c in sorted(report["controls"], key=lambda c: (order.get(c["status"], 9), int(c["control_id"].split()[-1]))):
        failing = ", ".join(c["failing_tests"]) or "—"
        rows.append(
            f'<tr><td><span class="cid">{_esc(c["control_id"])}</span></td>'
            f"<td>{_esc(c['title'])}</td>"
            f"<td>{_pill(c['status'])}</td>"
            f"<td>{c['violation_count'] or '—'}</td>"
            f"<td>{_esc(c['worst_severity'] or '—')}</td>"
            f"<td>{_esc(failing)}</td>"
            f"<td>{c['observation_count']}</td></tr>"
        )
    return (
        '<div class="tablebox"><table><thead><tr>'
        "<th>Control</th><th>Title</th><th>Status</th><th>Violations</th>"
        "<th>Worst severity</th><th>Failing tests</th><th>Times observed</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def _test_details(report: Mapping[str, Any]) -> str:
    blocks = []
    order = {"fail": 0, "unknown": 1, "pass": 2, "no_data": 3}
    for t in sorted(report["tests"], key=lambda t: (order.get(t["status"], 9), t["test_id"])):
        evidence_rows = "".join(
            f'<div class="row">#{ev["log_index"]} · {_esc(ev["log_type"])} · '
            f'{_esc(ev["severity"])} · {_esc(ev["timestamp"])}<br>'
            f'<span class="val">{_esc(ev["triggered_field"])} = {_esc(ev["triggered_value"])}</span><br>'
            f'finding {_esc(ev["finding_uuid"])} · sha256 {_esc(ev["evidence_sha256"][:16])}…</div>'
            for ev in t["evidence"]
        ) or '<div class="row">No evidence — test did not fire in this batch.</div>'
        controls = ", ".join(t["control_ids"])
        blocks.append(
            f'<details{" open" if t["status"] == "fail" else ""}><summary>'
            f'<span class="tid">{_esc(t["test_id"])}</span>{_pill(t["status"])}'
            f'<span class="ttl">{_esc(t["title"])}</span>'
            f'<span class="n">{t["occurrences"]}× · {_esc(controls)}</span>'
            f'</summary><div class="ev">{evidence_rows}</div></details>'
        )
    return "".join(blocks)


def render_html_report(report: Mapping[str, Any]) -> str:
    """Render the full dashboard; returns a complete HTML document string."""
    b, s = report["batch"], report["summary"]
    framework_cards = "".join(_framework_card(fw) for fw in report["frameworks"])
    sev = ", ".join(f"{k}: {v}" for k, v in s["violations_by_severity"].items()) or "none"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Compliance Report {_esc(report["report_id"][:8])}</title>
<style>{_CSS}</style></head><body><div class="wrap">
<h1>Compliance Report</h1>
<div class="meta">
report {_esc(report["report_id"])} · generated {_esc(report["generated_at"])} ·
engine v{_esc(report["engine_version"])} · schema {_esc(report["schema_version"])}<br>
batch: {b["total_logs"]} logs ({b["successful_logs"]} analysed, {b["failed_logs"]} failed) ·
violations: {s["total_violations"]} ({_esc(sev)})<br>
crosswalk: {_esc(report["crosswalk_provenance"])}<br>
integrity sha256 {_esc(report["integrity"]["content_sha256"])}
</div>
<div class="cards">{framework_cards}</div>
<h2>Control posture — CIS Controls v8.1</h2>
{_controls_table(report)}
<h2>Tests ({s["tests_failed"]} failed / {s.get("tests_unknown", 0)} unknown of {s["tests_total"]})</h2>
{_test_details(report)}
<div class="footer">Generated by the Furix deterministic compliance pipeline ·
verify with compliance_reporting.verify_report(report, batch) ·
report_id is uuid5(content_sha256): identical batches produce identical reports.</div>
</div></body></html>"""
