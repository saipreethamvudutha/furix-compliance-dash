"""
service.py
==========
The API's service layer — all the logic, none of the HTTP. Kept free of FastAPI
so it is unit-testable without a web server (and without torch/DB): the per-log
analyzer is dependency-injected, so the whole ingest → build → verify → store →
diff → alert flow can be exercised with a stub analyzer offline. `api/main.py`
is a thin shell over these functions.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

from compliance_reporting.adapters.dashboard import report_to_frameworks, report_to_summary
from compliance_reporting.diff import alerts_from_diff, diff_reports
from compliance_reporting.history import ReportStore
from compliance_reporting.registry import FrameworkRegistry
from compliance_reporting.report_builder import build_report
from compliance_reporting.verifier import verify_report

# A per-log analyzer: (raw_log, log_type) -> pipeline result dict.
Analyzer = Callable[[str, str], Mapping[str, Any]]


class IngestError(RuntimeError):
    """Raised when an ingested batch fails independent verification."""


def now_iso() -> str:
    """Server-side UTC timestamp (ISO-8601) for audit records."""
    return datetime.now(timezone.utc).isoformat()


def _demo_aws_client():
    """A deterministic AWS client for the 'demo-aws' connector kind so the
    connector-health workflow is exercisable without live AWS credentials."""
    from compliance_reporting.collectors import FakeAwsClient  # noqa: PLC0415
    accounts = [{"account_id": f"{i:012d}"} for i in range(1, 4)]
    keys = {"000000000001": [{"key_id": "AKIADEMO", "status": "active", "age_days": 45}]}
    summaries = {a["account_id"]: {"root_mfa_enabled": True} for a in accounts}
    return FakeAwsClient(accounts=accounts, keys_by_account=keys, summaries=summaries,
                         page_size=2, independent_count=3)


def _connector_client(kind: str, cfg: Mapping[str, Any]):
    if kind == "demo-aws":
        return _demo_aws_client()
    if kind == "aws-org-iam":
        from compliance_reporting.aws_boto3 import Boto3AwsClient  # noqa: PLC0415
        return Boto3AwsClient(
            member_role_name=cfg.get("member_role_name", "OrganizationAccountAccessRole"),
            org_role_arn=cfg.get("org_role_arn"), external_id=cfg.get("external_id"),
            region=cfg.get("region", "us-east-1"))
    raise ValueError(f"unknown connector kind {kind!r}")


def collect_snapshot(tenant: str, kind: str, cfg: Mapping[str, Any],
                     signing_secret: str) -> dict[str, Any]:
    """Run a connector and return the full {snapshot, manifest} (mandatory-signed)."""
    from compliance_reporting.collectors import AwsOrgIamCollector, RetryPolicy  # noqa: PLC0415
    collector = AwsOrgIamCollector(client=_connector_client(kind, cfg), tenant=tenant,
                                   signing_secret=signing_secret, retry=RetryPolicy(base_delay=0.0))
    return collector.collect(collected_at=now_iso())


def make_connector_runner(tenant: str, signing_secret: str) -> Callable[[Mapping[str, Any]], dict]:
    """Build a runner(job)->manifest for the ConnectorScheduler. Dispatches on
    the job 'kind': 'demo-aws' (deterministic, no creds) or 'aws-org-iam' (the
    live boto3 collector). Manifests are mandatory-signed (fail-closed)."""

    def runner(job: Mapping[str, Any]) -> dict:
        out = collect_snapshot(tenant, job["kind"], job.get("config", {}) or {}, signing_secret)
        return out["manifest"]

    return runner


def run_posture(store: ReportStore, *, tenant: str, snapshot: Mapping[str, Any],
                manifest: Mapping[str, Any] | None = None, connector_id: str | None = None,
                registry: FrameworkRegistry | None = None, occurred_at: str,
                actor: str = "system", run_id: str | None = None) -> dict[str, Any]:
    """
    The unified posture-run pipeline (Wave-H): raw snapshot → immutable evidence
    → reconciliation (from the signed manifest) → config assertions → verified
    report → findings, recorded as ONE linked-ID PostureRun.

    Returns the persisted PostureRun with linked ids across every stage.
    """
    import hashlib  # noqa: PLC0415

    from compliance_reporting.evidence import EvidenceStore  # noqa: PLC0415
    from compliance_reporting.exceptions import new_finding_id  # noqa: PLC0415
    from compliance_reporting.posture_run import PostureRunStore  # noqa: PLC0415

    registry = registry or FrameworkRegistry.from_live()
    started = now_iso()

    # 1. retain the raw snapshot as an immutable, content-addressed evidence object
    ev = EvidenceStore(store.root)
    snap_json = json.dumps(snapshot, sort_keys=True)
    ev_obj = ev.put(snap_json, source="posture-snapshot", tenant=tenant,
                    observed_at=snapshot.get("collected_at"))
    if not ev.verify_object(ev_obj.sha256):
        raise IngestError("posture snapshot evidence failed persistence verification")

    # 2. ingest config → assertions + verified, stored report (persists per-resource evidence)
    ing = ingest_config(store, snapshot, tenant=tenant, registry=registry)
    report_id = ing["report_id"]
    report = store.load(report_id)

    # 3. evaluation summary (config assertions), with a combined evaluator hash
    cas = report.get("config_assertions", [])
    ev_pass = sum(1 for r in cas if r.get("status") == "pass")
    ev_fail = sum(1 for r in cas if r.get("status") == "fail")
    evaluator_hash = hashlib.sha256(
        "|".join(sorted(r.get("evaluator_hash", "") for r in cas)).encode()).hexdigest()[:16]

    # 4. open findings for every at-risk control; collect the linked ids
    fs = _finding_store(store)
    finding_ids: list[str] = []
    affected: list[str] = []
    for c in report["controls"]:
        if c["status"] != "at_risk":
            continue
        fid = new_finding_id(tenant, c["control_id"], "cis_v8", report_id)
        fs.open_finding(fid, control_id=c["control_id"], framework_id="cis_v8",
                        severity=c.get("worst_severity", "medium"), actor=actor,
                        occurred_at=occurred_at, discovered_report=report_id,
                        reason=f"{c['control_id']} at risk")
        finding_ids.append(fid)
        affected.append(c["control_id"])

    # 5. assemble the linked-ID posture run (deterministic run id from its report)
    m = dict(manifest or {})
    run_id = run_id or ("run-" + hashlib.sha256(
        f"{tenant}|{report_id}|{snapshot.get('collected_at', '')}".encode()).hexdigest()[:20])
    run = {
        "run_id": run_id, "tenant": tenant, "connector_id": connector_id,
        "started_at": started, "completed_at": now_iso(), "status": "completed",
        "collection": {
            "manifest_sha256": m.get("resource_sha256"), "signed": bool(m.get("signature")),
            "reconciled": bool(m.get("reconciled")),
            "reconciliation_basis": m.get("reconciliation_basis"),
            "expected_accounts": m.get("expected_accounts"),
            "observed_accounts": m.get("observed_accounts"),
        },
        "snapshot": {
            "source": snapshot.get("source"), "collected_at": snapshot.get("collected_at"),
            "resource_count": len(snapshot.get("resources", [])),
        },
        "evidence": {"snapshot_sha256": ev_obj.sha256,
                     "raw_uri": f"furix-evidence://{ev_obj.sha256}"},
        "evaluation": {"assertion_total": len(cas), "pass": ev_pass, "fail": ev_fail,
                       "evaluator_hash": evaluator_hash},
        "report_id": report_id,
        "verified": ing["verification"]["ok"],
        "verifier_level": ing["verification"].get("level"),
        "findings": finding_ids, "affected_controls": affected,
    }
    return PostureRunStore(store.root).save(run)


def list_posture_runs(store: ReportStore, tenant: str, *, limit: int = 50) -> list[dict[str, Any]]:
    from compliance_reporting.posture_run import PostureRunStore  # noqa: PLC0415
    return PostureRunStore(store.root).list(tenant, limit=limit)


def get_posture_run(store: ReportStore, tenant: str, run_id: str) -> dict[str, Any]:
    from compliance_reporting.posture_run import PostureRunStore  # noqa: PLC0415
    run = PostureRunStore(store.root).get(tenant, run_id)
    if run is None:
        raise FileNotFoundError(f"unknown posture run {run_id}")
    return run


def split_log_lines(text: str) -> list[str]:
    """One event per line (the log_ingest.py model). Blank lines dropped."""
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def classify_lines(lines: Sequence[str], declared: str = "auto") -> list[tuple[str, str]]:
    """
    Deterministic per-event type routing (FUR-CMP-005). When the caller
    declares a concrete type it is honoured; "auto" runs each line through
    detect_log_type() so every recognised format takes the deterministic
    known-type path. Only genuinely unrecognised lines remain "generic"
    (and even those stay deterministic unless FURIX_LLM_ENRICH=1).
    """
    if declared and declared != "auto":
        return [(declared, ln) for ln in lines]
    from log_ingest import detect_log_type  # noqa: PLC0415 — engine-root module
    return [(detect_log_type(ln), ln) for ln in lines]


def _default_analyzer() -> Analyzer:
    """Lazy-import the heavy pipeline so importing this module stays cheap."""
    import contextlib
    import io
    import os

    from pipeline import run_full_pipeline  # noqa: PLC0415 — heavy (torch + DB)

    # The pipeline prints verbose per-log output (phase banners, mappings,
    # timings). At bulk volume that stdout I/O dominates runtime and floods the
    # container logs, so silence it unless FURIX_VERBOSE_INGEST=1.
    verbose = os.environ.get("FURIX_VERBOSE_INGEST") == "1"

    def _run(raw: str, log_type: str) -> Mapping[str, Any]:
        if verbose:
            return run_full_pipeline(raw, log_type=log_type)
        with contextlib.redirect_stdout(io.StringIO()):
            return run_full_pipeline(raw, log_type=log_type)

    return _run


def ingest_batch(
    store: ReportStore,
    text: str,
    *,
    log_type: str = "auto",
    tenant: str = "default",
    config_snapshot: Any = None,
    attestations: Any = None,
    attestation_keyring: Any = None,
    analyzer: Analyzer | None = None,
    registry: FrameworkRegistry | None = None,
    deliver: bool = True,
    evidence_store: Any = None,
    evidence_required: bool = True,
    on_progress: Callable[[int, int, str], None] | None = None,
) -> dict[str, Any]:
    """
    Run each log line through the analyzer, retain the raw line immutably,
    build + verify a report, persist it, and (if a prior report exists) diff +
    deliver regression alerts.

    on_progress(processed, total, phase) is called during analysis and at each
    finalization phase, for the background-job progress bar.

    Returns {report_id, summary, frameworks, verification, alerts}.
    Raises IngestError if the built report fails verification.
    """
    analyzer = analyzer or _default_analyzer()
    registry = registry or FrameworkRegistry.from_live()

    # Immutable evidence store lives alongside this tenant's report store
    # (FUR-CMP-007): every raw line is retained, content-addressed, write-once.
    from compliance_reporting.evidence import EvidenceStore  # noqa: PLC0415
    ev_store = evidence_store or EvidenceStore(store.root)

    typed_lines = classify_lines(split_log_lines(text), log_type)
    total = len(typed_lines)
    results = []
    for i, (detected_type, line) in enumerate(typed_lines):
        result = dict(analyzer(line, detected_type))
        observed_at = ((result.get("findings") or {}).get("timestamp")
                       if isinstance(result.get("findings"), dict) else None)
        # Transactional evidence (Wave-N): a report must never present evidence
        # that was not durably retained. If persistence fails and evidence is
        # required, ABORT the ingest — no report with unbacked evidence.
        try:
            obj = ev_store.put(line, source=detected_type, tenant=tenant, observed_at=observed_at)
            if evidence_required and not ev_store.verify_object(obj.sha256):
                raise IngestError(f"evidence for log #{i} failed persistence verification")
        except (OSError, IngestError) as e:
            if evidence_required:
                raise IngestError(f"evidence could not be persisted for log #{i}: {e}") from e
        results.append({"log_type": detected_type, "result": result})
        if on_progress:
            on_progress(i + 1, total, "analyzing")

    if on_progress:
        on_progress(total, total, "finalizing")
    report = build_report(results, registry=registry, config_snapshot=config_snapshot,
                          attestations=attestations, attestation_keyring=attestation_keyring,
                          tenant=tenant)
    verification = verify_report(report, results)
    if not verification.ok:
        raise IngestError(f"report failed verification: {verification.failures}")

    # diff vs the most recent PRIOR report (before this one is saved)
    prior = store.latest(1)
    prior_id = prior[0].report_id if prior else None

    store.save(report, batch=results)

    alerts: list[dict[str, Any]] = []
    if prior_id and prior_id != report["report_id"]:
        d = diff_reports(store.load(prior_id), report)
        alerts = alerts_from_diff(d)
        if deliver and alerts:
            _deliver(alerts, report, prior_id)

    return {
        "report_id": report["report_id"],
        "lines_ingested": total,
        "summary": report_to_summary(report),
        "frameworks": report_to_frameworks(report),
        "verification": {
            "ok": verification.ok,
            "level": verification.level,
            "checks_run": verification.checks_run,
        },
        "alerts": alerts,
    }


def generate_and_ingest(
    store: ReportStore,
    *,
    count: int = 50,
    attack_ratio: float = 0.35,
    seed: int = 0,
    types: list[str] | None = None,
    tenant: str = "default",
    with_config: bool = True,
    analyzer: Analyzer | None = None,
    registry: FrameworkRegistry | None = None,
    on_progress: Callable[[int, int, str], None] | None = None,
) -> dict[str, Any]:
    """
    Generate synthetic logs and ingest them (the dashboard 'Generate demo logs'
    path). By default it also applies the demo config-posture snapshot so the
    report shows positively-verified `met` controls and an earned compliance %,
    not just detection findings.
    """
    from log_generator.generate import generate  # noqa: PLC0415

    snapshot = attests = ring = None
    if with_config:
        from compliance_reporting.fixtures import (  # noqa: PLC0415
            demo_attestation_keyring, demo_attestations, demo_config_snapshot)
        snapshot = demo_config_snapshot()
        attests = demo_attestations(tenant=tenant)   # signed for this tenant
        ring = demo_attestation_keyring()

    lines = generate(count=count, attack_ratio=attack_ratio, types=types, seed=seed)
    return ingest_batch(store, "\n".join(lines), log_type="auto", tenant=tenant,
                        config_snapshot=snapshot, attestations=attests,
                        attestation_keyring=ring, analyzer=analyzer,
                        registry=registry, on_progress=on_progress)


def ingest_config(
    store: ReportStore,
    snapshot: Mapping[str, Any],
    *,
    tenant: str = "default",
    registry: FrameworkRegistry | None = None,
    deliver: bool = True,
) -> dict[str, Any]:
    """
    Ingest a config-posture snapshot (FUR-CMP-009). Combines it with the most
    recent detection batch (if any) so posture reflects both event evidence and
    config state, then builds + verifies + persists a report.
    """
    registry = registry or FrameworkRegistry.from_live()
    prior = store.latest(1)
    prior_id = prior[0].report_id if prior else None
    batch = store.load_batch(prior_id) if prior_id else []

    # Retain each raw config resource immutably so config evidence has the same
    # furix-evidence:// lineage as log evidence (FUR-CMP-007).
    from compliance_reporting.connectors import parse_snapshot  # noqa: PLC0415
    from compliance_reporting.config_assertions import canonical_resource  # noqa: PLC0415
    from compliance_reporting.evidence import EvidenceStore  # noqa: PLC0415
    ev_store = EvidenceStore(store.root)
    snap = parse_snapshot(snapshot)
    for r in snap.resources:
        # transactional: a config assertion must not PASS on a resource whose
        # raw evidence could not be retained (Wave-N).
        try:
            obj = ev_store.put(canonical_resource(r), source=f"config:{r.resource_type}",
                               tenant=tenant, observed_at=r.observed_at)
            if not ev_store.verify_object(obj.sha256):
                raise IngestError(f"config resource {r.resource_id} failed persistence verification")
        except (OSError, IngestError) as e:
            raise IngestError(f"config evidence could not be persisted ({r.resource_id}): {e}") from e

    report = build_report(batch or [], registry=registry, config_snapshot=snap)
    verification = verify_report(report, batch or [])
    if not verification.ok:
        raise IngestError(f"config report failed verification: {verification.failures}")

    store.save(report, batch=batch or [])
    alerts: list[dict[str, Any]] = []
    if prior_id and prior_id != report["report_id"]:
        d = diff_reports(store.load(prior_id), report)
        alerts = alerts_from_diff(d)
        if deliver and alerts:
            _deliver(alerts, report, prior_id)
    return {
        "report_id": report["report_id"],
        "config_assertions": report["summary"].get("config_assertions_total", 0),
        "summary": report_to_summary(report),
        "frameworks": report_to_frameworks(report),
        "verification": {"ok": verification.ok, "level": verification.level,
                         "checks_run": verification.checks_run},
        "alerts": alerts,
    }


# ── finding / exception lifecycle (Wave 5) ────────────────────────────────────
def _finding_store(store: ReportStore):
    from compliance_reporting.exceptions import FindingStore  # noqa: PLC0415
    return FindingStore(store.root)


def derive_findings(store: ReportStore, report_id: str = "latest", *, tenant: str = "default",
                    actor: str = "system", occurred_at: str) -> dict[str, Any]:
    """
    Open a Finding for every at-risk control in a report (idempotent). This is
    how the assurance verdict feeds the remediation workflow.
    """
    from compliance_reporting.exceptions import new_finding_id  # noqa: PLC0415
    report = store.load(_resolve(store, report_id))
    fs = _finding_store(store)
    ctrl_sev = {c["control_id"]: c.get("worst_severity", "medium") for c in report["controls"]}
    opened = 0
    for c in report["controls"]:
        if c["status"] != "at_risk":
            continue
        fid = new_finding_id(tenant, c["control_id"], "cis_v8", report["report_id"])
        before = fs.get(fid)
        fs.open_finding(fid, control_id=c["control_id"], framework_id="cis_v8",
                        severity=ctrl_sev.get(c["control_id"], "medium"), actor=actor,
                        occurred_at=occurred_at, discovered_report=report["report_id"],
                        reason=f"{c['control_id']} at risk")
        if not before:
            opened += 1
    return {"report_id": report["report_id"], "opened": opened,
            "open_findings": len(fs.list(open_only=True))}


def list_findings(store: ReportStore, *, as_of: str | None = None,
                  open_only: bool = False) -> list[dict[str, Any]]:
    return _finding_store(store).list(as_of=as_of, open_only=open_only)


def finding_history(store: ReportStore, finding_id: str) -> list[dict[str, Any]]:
    return _finding_store(store).history(finding_id)


def transition_finding(store: ReportStore, finding_id: str, action: str, *, actor: str,
                       occurred_at: str, reason: str = "",
                       payload: dict[str, Any] | None = None) -> dict[str, Any]:
    from compliance_reporting.exceptions import LifecycleError  # noqa: PLC0415
    try:
        return _finding_store(store).transition(
            finding_id, action, actor=actor, occurred_at=occurred_at,
            reason=reason, payload=payload)
    except LifecycleError as e:
        raise IngestError(str(e))


def findings_by_control(store: ReportStore, *, as_of: str | None = None) -> dict[str, dict[str, Any]]:
    """control_id → its most-relevant open finding, for annotating the report."""
    out: dict[str, dict[str, Any]] = {}
    for f in _finding_store(store).list(as_of=as_of, open_only=True):
        cid = f.get("control_id")
        if cid and cid not in out:
            out[cid] = f
    return out


def _deliver(alerts, report, prior_id) -> None:
    try:
        from compliance_reporting.settings import Settings
        from compliance_reporting.delivery import deliver_alerts
        deliver_alerts(
            alerts, Settings.from_env().build_sinks(),
            context={"new_report_id": report["report_id"], "old_report_id": prior_id},
        )
    except Exception:  # delivery must never break ingest
        pass


# ── read paths ────────────────────────────────────────────────────────────────
def _resolve(store: ReportStore, report_id: str) -> str:
    if report_id in ("latest", "", None):
        latest = store.latest(1)
        if not latest:
            raise FileNotFoundError("no reports stored yet")
        return latest[0].report_id
    # allow 8-char prefixes
    matches = [e.report_id for e in store.entries() if e.report_id.startswith(report_id)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise FileNotFoundError(f"no stored report matches {report_id!r}")
    raise ValueError(f"ambiguous report id {report_id!r}")


def list_reports(store: ReportStore) -> list[dict[str, Any]]:
    return [e.to_dict() for e in reversed(store.entries())]  # newest first


def get_report(store: ReportStore, report_id: str) -> dict[str, Any]:
    return store.load(_resolve(store, report_id))


def get_frameworks(store: ReportStore, report_id: str = "latest",
                   as_of: str | None = None) -> list[dict[str, Any]]:
    # annotate at-risk rows with any open finding / accepted-exception status
    fbc = findings_by_control(store, as_of=as_of)
    return report_to_frameworks(store.load(_resolve(store, report_id)), fbc or None)


def get_summary(store: ReportStore, report_id: str = "latest") -> dict[str, Any]:
    return report_to_summary(store.load(_resolve(store, report_id)))


def get_trend(store: ReportStore) -> list[dict[str, Any]]:
    return store.trend()


# ── OSCAL + auditor export (Wave 5) ───────────────────────────────────────────
def get_oscal(store: ReportStore, report_id: str = "latest", *, kind: str = "assessment-results",
              as_of: str | None = None) -> dict[str, Any]:
    from compliance_reporting.oscal import build_assessment_results, build_poam, validate_oscal_schema
    report = store.load(_resolve(store, report_id))
    if kind == "poam":
        doc = build_poam(report, list_findings(store, as_of=as_of, open_only=True))
    else:
        doc = build_assessment_results(report)
    return {"oscal": doc, "validation": validate_oscal_schema(doc)}


def get_audit_package(store: ReportStore, report_id: str = "latest",
                      as_of: str | None = None) -> dict[str, Any]:
    """
    A scoped, self-contained evidence package for an auditor (FUR-CMP-015): the
    verified report summary + valid OSCAL assessment-results + POA&M + the open
    findings/exception workpaper — everything needed to inspect the assessment
    without trusting the live dashboard.
    """
    from compliance_reporting.oscal import build_assessment_results, build_poam, validate_oscal_schema
    report = store.load(_resolve(store, report_id))
    findings = list_findings(store, as_of=as_of, open_only=True)
    ar = build_assessment_results(report)
    poam = build_poam(report, findings)
    ar_val, poam_val = validate_oscal_schema(ar), validate_oscal_schema(poam)
    # An auditor package must not be issued unless schema validation actually RAN
    # and passed. `ran=False` (e.g. jsonschema unavailable) is NOT good enough —
    # an unvalidated "OSCAL export" is worse than none (fail-closed).
    validated = bool(ar_val["ran"] and ar_val["ok"] and poam_val["ran"] and poam_val["ok"])
    if not validated:
        raise IngestError(f"OSCAL package not schema-validated (ran={ar_val['ran']}/"
                          f"{poam_val['ran']}): {ar_val['errors'] + poam_val['errors']}")
    return {
        "report_id": report["report_id"],
        "generated_at": report.get("generated_at"),
        "integrity_sha256": report.get("integrity", {}).get("content_sha256", ""),
        "versions": report.get("versions", {}),
        "summary": report_to_summary(report),
        "oscal": {
            "assessment_results": ar,
            "poam": poam,
            "validation_ok": validated,
            "schema": ar_val.get("schema"),
        },
        "findings": findings,
    }


def get_diff(store: ReportStore, old_id: str, new_id: str) -> dict[str, Any]:
    d = diff_reports(store.load(_resolve(store, old_id)), store.load(_resolve(store, new_id)))
    return {"diff": d, "alerts": alerts_from_diff(d)}
