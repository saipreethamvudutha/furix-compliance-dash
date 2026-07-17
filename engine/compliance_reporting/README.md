# furix-compliance-reporting

Deterministic, self-verifying, multi-framework compliance reporting for the
Furix pipeline. **Zero runtime dependencies** — the entire engine runs on the
Python standard library, a deliberate durability and supply-chain property.

## What it does

Turns a batch of Furix pipeline results into an auditor-grade compliance report
across **CIS Controls v8.1, NIST CSF 2.0, HIPAA Security Rule, and PCI DSS 4.0**,
using the industry-standard three-layer model:

```
test (policy rule / Sigma detection) → control (CIS) → framework requirement
```

Every report is hash-sealed and reproducible; an independent verifier recomputes
every number from the raw batch; regressions between batches raise deliverable
alerts.

## Modules

| Module | Role |
|---|---|
| `registry.py` | Static catalogs (15 tests, 18 controls) + framework crosswalk |
| `report_builder.py` | The three-layer rollup + integrity seal |
| `verifier.py` | Independent recomputation + tamper detection (~220 checks) |
| `render_html.py` | Self-contained dashboard |
| `history.py` | Durable, integrity-checked report store + trend series |
| `diff.py` | Report-to-report comparison + regression alerts |
| `delivery.py` | Alert sinks: console, JSONL audit, Slack-compatible webhook |
| `detection/` | **ATT&CK pivot**: Sigma rules → techniques → controls (zero-dep) |
| `settings.py` | Environment-overridable configuration |

## Quickstart

```bash
python3 -m compliance_reporting.test_reporting            # 23 tests
python3 -m compliance_reporting.detection.test_detection  # 10 tests
python3 -m compliance_reporting.test_delivery             #  9 tests

python3 -m compliance_reporting demo                      # full lifecycle
python3 -m compliance_reporting detect --log-type cloudtrail '<log json>'
```

Install as a package (optional):

```bash
pip install -e .          # provides the `furix-compliance` command
```

## Pipeline integration

After `complete_log_pipeline_run()` in `pipeline.py`:

```python
from compliance_reporting import build_report, verify_report, render_html_report, ReportStore
from compliance_reporting.diff import diff_reports, alerts_from_diff
from compliance_reporting.delivery import deliver_alerts
from compliance_reporting.settings import Settings

settings = Settings.from_env()
store = ReportStore(settings.store_path)

report = build_report(pipeline_results, engine_version=settings.engine_version)
if not verify_report(report, pipeline_results).ok:
    raise RuntimeError("compliance report failed verification")

path = store.save(report, batch=pipeline_results)
path.with_suffix(".html").write_text(render_html_report(report))

prev = store.latest(2)
if len(prev) == 2:
    diff = diff_reports(store.load(prev[0].report_id), report)
    deliver_alerts(alerts_from_diff(diff), settings.build_sinks(),
                   context={"new_report_id": report["report_id"]})
```

The ATT&CK pivot replaces the keyword control-mapping step:

```python
from compliance_reporting.detection import AttackPivotResolver
resolver = AttackPivotResolver.load()
result = resolver.resolve(raw_log, log_type)
result.control_ids     # ["Control 5", "Control 6", ...]
result.provenance()    # control ← technique ← rule audit trail
```

## Production checklist

1. `export_snapshot_from_live()` once (DB up) to replace the dev crosswalk snapshot with real SCF-derived edges.
2. Ingest the full MITRE CTID mappings-explorer JSON into `detection/technique_map.json`.
3. Add SCF PCI/ISO/SOC-2 columns in `phase1_scf_ingest.py` for more frameworks.
4. Set `FURIX_ALERT_WEBHOOK` to your Slack/PagerDuty endpoint.
