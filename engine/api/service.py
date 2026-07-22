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


def run_connector_posture(store: ReportStore, tenant: str, connector_id: str, *, kind: str,
                          config: Mapping[str, Any], signing_secret: str,
                          registry: FrameworkRegistry | None = None, attestations: Any = None,
                          attestation_keyring: Any = None, actor: str = "scheduler") -> dict[str, Any]:
    """
    The one path a connector run should take (Wave-J P0): collect → run the FULL
    unified posture pipeline (evaluate controls, verify, findings) → return the
    posture run + manifest. Used by BOTH the manual /run endpoint and the async
    worker, so a scheduled run evaluates controls exactly like a manual one.
    """
    collected = collect_snapshot(tenant, kind, config, signing_secret)
    run = run_posture(store, tenant=tenant, snapshot=collected["snapshot"],
                      manifest=collected["manifest"], connector_id=connector_id,
                      registry=registry, occurred_at=now_iso(), actor=actor,
                      data_mode="demo" if is_demo_kind(kind) else "live",
                      attestations=attestations, attestation_keyring=attestation_keyring)
    return {"run": run, "manifest": collected["manifest"]}


DEMO_CONNECTOR_KINDS = frozenset({"demo-aws"})


def is_demo_kind(kind: str) -> bool:
    return kind in DEMO_CONNECTOR_KINDS


def run_posture(store: ReportStore, *, tenant: str, snapshot: Mapping[str, Any],
                manifest: Mapping[str, Any] | None = None, connector_id: str | None = None,
                registry: FrameworkRegistry | None = None, occurred_at: str,
                actor: str = "system", run_id: str | None = None,
                data_mode: str = "live", attestations: Any = None,
                attestation_keyring: Any = None) -> dict[str, Any]:
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

    # 2. ingest config → assertions + verified, stored report (persists per-resource
    #    evidence). Approved attestations flow through so verified manual controls
    #    are preserved, not regressed to pending (Wave-J P0).
    ing = ingest_config(store, snapshot, tenant=tenant, registry=registry,
                        attestations=attestations, attestation_keyring=attestation_keyring)
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
        "data_mode": data_mode,   # "demo" (synthetic) | "live" — isolates demo evidence
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


# ── compliance workspace (Wave-I / Epic 4) ────────────────────────────────────
def _latest_report(store: ReportStore) -> dict[str, Any] | None:
    try:
        idx = store.latest(1)
        return store.load(idx[0].report_id) if idx else None
    except (FileNotFoundError, IndexError, ValueError):
        return None


def _freshness(last_assessed: str | None, cadence_days: int, now: str) -> str:
    if not last_assessed:
        return "unknown"
    try:
        delta = datetime.fromisoformat(now) - datetime.fromisoformat(last_assessed)
        return "stale" if delta.days > cadence_days else "fresh"
    except ValueError:
        return "unknown"


def _control_assertions(report: dict[str, Any] | None, control_id: str) -> list[dict[str, Any]]:
    """The config assertions backing a control (each carries its own freshness)."""
    if not report:
        return []
    return [a for a in report.get("config_assertions", [])
            if control_id in (a.get("control_ids") or [])]


def _evidence_freshness_for(assertions: list[dict[str, Any]], cadence_days: int,
                            now: str) -> tuple[str, str | None]:
    """Per-control freshness derived from the ACTUAL evidence backing it (the
    oldest contributing observation), not merely the report time. Returns
    (state, oldest_observed_at)."""
    observed: list[str] = []
    any_stale = False
    for a in assertions:
        fr = a.get("freshness") or {}
        if fr.get("stale"):
            any_stale = True
        col = fr.get("collected_at") or fr.get("as_of")
        if col:
            observed.append(col)
    if not observed:
        return "unknown", None
    oldest = min(observed)
    if any_stale:
        return "stale", oldest
    # also enforce the control's own cadence against the oldest evidence
    try:
        if (datetime.fromisoformat(now) - datetime.fromisoformat(oldest)).days > cadence_days:
            return "stale", oldest
    except ValueError:
        pass
    return "fresh", oldest


def _framework_maps(registry: FrameworkRegistry, cid: str) -> dict[str, list[str]]:
    return {
        "nist_csf": list(registry.cis_to_nist.get(cid, ()) or ()),
        "pci_dss": list(registry.cis_to_pci.get(cid, ()) or ()),
        "hipaa": list(registry.cis_to_hipaa.get(cid, ()) or ()),
    }


def _control_universe(report: dict[str, Any] | None,
                      registry: FrameworkRegistry) -> list[dict[str, Any]]:
    if report:
        return report["controls"]
    # no assessment yet → list the CIS controls from the crosswalk, ordered
    cids = sorted(registry.cis_to_nist.keys(),
                  key=lambda c: int(c.split()[-1]) if c.split()[-1].isdigit() else 999)
    return [{"control_id": c, "title": c, "status": "unknown"} for c in cids]


def list_control_workspace(store: ReportStore, tenant: str, *,
                           registry: FrameworkRegistry | None = None,
                           now: str | None = None) -> list[dict[str, Any]]:
    """Summary row per control: computed verdict + owner/applicability/freshness
    + framework counts + open-finding count."""
    from compliance_reporting.control_profile import ControlProfileStore  # noqa: PLC0415
    registry = registry or FrameworkRegistry.from_live()
    now = now or now_iso()
    report = _latest_report(store)
    last_assessed = report.get("generated_at") if report else None
    cps = ControlProfileStore(store.root)
    profiles = cps.all(tenant)
    open_by_ctrl: dict[str, int] = {}
    for f in _finding_store(store).list(open_only=True):
        cid = f.get("control_id")
        if cid:
            open_by_ctrl[cid] = open_by_ctrl.get(cid, 0) + 1

    rows = []
    for c in _control_universe(report, registry):
        cid = c["control_id"]
        prof = profiles.get(cid) or cps.get(tenant, cid)
        maps = _framework_maps(registry, cid)
        # freshness from the ACTUAL backing evidence (falls back to report time)
        assertions = _control_assertions(report, cid)
        fresh_state, oldest = _evidence_freshness_for(assertions, prof["test_cadence_days"], now)
        if fresh_state == "unknown":
            fresh_state = _freshness(last_assessed, prof["test_cadence_days"], now)
        rows.append({
            "control_id": cid, "title": c.get("title", cid), "status": c.get("status", "unknown"),
            "owner": prof["owner"], "applicability": prof["applicability"],
            "verification_method": prof["verification_method"],
            "test_cadence_days": prof["test_cadence_days"],
            "evidence_freshness": fresh_state,
            "oldest_evidence_at": oldest,
            "last_assessed": last_assessed,
            "open_findings": open_by_ctrl.get(cid, 0),
            "framework_counts": {k: len(v) for k, v in maps.items()},
        })
    return rows


def get_control_workspace(store: ReportStore, tenant: str, control_id: str, *,
                          registry: FrameworkRegistry | None = None,
                          now: str | None = None) -> dict[str, Any]:
    """Full workspace view for one control: verdict + governance profile + framework
    mappings + linked findings + exceptions + complete evidence lineage."""
    from compliance_reporting.control_profile import ControlProfileStore  # noqa: PLC0415
    from compliance_reporting.posture_run import PostureRunStore  # noqa: PLC0415
    registry = registry or FrameworkRegistry.from_live()
    now = now or now_iso()
    report = _latest_report(store)
    ctrl = next((c for c in (report["controls"] if report else []) if c["control_id"] == control_id), None)
    if ctrl is None and control_id not in registry.cis_to_nist:
        raise FileNotFoundError(f"unknown control {control_id}")
    ctrl = ctrl or {"control_id": control_id, "title": control_id, "status": "unknown"}

    prof = ControlProfileStore(store.root).get(tenant, control_id)
    last_assessed = report.get("generated_at") if report else None

    findings = [f for f in _finding_store(store).list() if f.get("control_id") == control_id]
    exceptions = [{"finding_id": f["finding_id"], **f["exception"]}
                  for f in findings if f.get("exception")]

    # link to the EXACT posture run that produced this report (not just latest)
    report_id = report.get("report_id") if report else None
    prs = PostureRunStore(store.root)
    pr = (prs.by_report(tenant, report_id) if report_id else None) or prs.latest(tenant)

    # per-assertion freshness backing this control
    assertions = _control_assertions(report, control_id)
    assertion_freshness = [{
        "spec_id": a.get("spec_id"), "status": a.get("status"),
        "freshness": a.get("freshness"),
        "evidence": [{"resource_id": e.get("resource_id"), "observed_at": e.get("observed_at"),
                      "raw_uri": e.get("raw_uri")} for e in (a.get("evidence") or [])],
    } for a in assertions]
    fresh_state, oldest = _evidence_freshness_for(assertions, prof["test_cadence_days"], now)
    if fresh_state == "unknown":
        fresh_state = _freshness(last_assessed, prof["test_cadence_days"], now)

    lineage = {
        "report_id": report_id,
        "report_integrity_sha256": (report.get("integrity", {}) or {}).get("content_sha256") if report else None,
        "evidence_mode": ctrl.get("evidence_mode"),
        "config_passing": ctrl.get("config_passing", []),
        "config_failing": ctrl.get("config_failing", []),
        "passing_tests": ctrl.get("passing_tests", []),
        "failing_tests": ctrl.get("failing_tests", []),
        "posture_run": None,
    }
    if pr:
        lineage["posture_run"] = {
            "run_id": pr["run_id"], "data_mode": pr.get("data_mode"),
            "snapshot_sha256": pr["evidence"]["snapshot_sha256"],
            "snapshot_uri": pr["evidence"]["raw_uri"], "report_id": pr["report_id"],
        }

    return {
        "control_id": control_id, "title": ctrl.get("title", control_id),
        "status": ctrl.get("status", "unknown"),
        "worst_severity": ctrl.get("worst_severity"),
        "profile": prof,
        "evidence_freshness": fresh_state,
        "oldest_evidence_at": oldest,
        "last_assessed": last_assessed,
        "assertion_freshness": assertion_freshness,   # per-assertion / per-evidence
        "framework_mappings": _framework_maps(registry, control_id),
        "linked_findings": findings,
        "exceptions": exceptions,
        "evidence_lineage": lineage,
    }


def update_control_profile(store: ReportStore, tenant: str, control_id: str,
                           patch: dict[str, Any], *, actor: str, updated_at: str) -> dict[str, Any]:
    from compliance_reporting.control_profile import ControlProfileStore, ControlProfileError  # noqa: PLC0415
    try:
        return ControlProfileStore(store.root).update(
            tenant, control_id, patch, updated_by=actor, updated_at=updated_at)
    except ControlProfileError as e:
        raise ValueError(str(e))


# ── audit-period workflow (Wave-I / Epic 5) ───────────────────────────────────
def _audit_store(store: ReportStore):
    from compliance_reporting.audit_period import AuditPeriodStore  # noqa: PLC0415
    return AuditPeriodStore(store.root)


def create_audit_period(store: ReportStore, tenant: str, *, name: str, boundary: str,
                        start_date: str, end_date: str, actor: str, at: str) -> dict[str, Any]:
    return _audit_store(store).create(tenant=tenant, name=name, boundary=boundary,
                                      start_date=start_date, end_date=end_date,
                                      created_by=actor, created_at=at)


def list_audit_periods(store: ReportStore, tenant: str) -> list[dict[str, Any]]:
    return _audit_store(store).list(tenant)


def get_audit_period(store: ReportStore, tenant: str, period_id: str) -> dict[str, Any]:
    p = _audit_store(store).get(tenant, period_id)
    if p is None:
        raise FileNotFoundError(f"unknown audit period {period_id}")
    return p


def add_evidence_request(store: ReportStore, tenant: str, period_id: str, *, control_id: str,
                        note: str, actor: str, at: str) -> dict[str, Any]:
    from compliance_reporting.audit_period import AuditPeriodError  # noqa: PLC0415
    try:
        return _audit_store(store).add_evidence_request(
            tenant, period_id, control_id=control_id, note=note, requested_by=actor, requested_at=at)
    except AuditPeriodError as e:
        raise ValueError(str(e))


def fulfill_evidence_request(store: ReportStore, tenant: str, period_id: str, req_id: str, *,
                            evidence_ref: str, actor: str, at: str) -> dict[str, Any]:
    from compliance_reporting.audit_period import AuditPeriodError  # noqa: PLC0415
    try:
        return _audit_store(store).fulfill_evidence_request(
            tenant, period_id, req_id, evidence_ref=evidence_ref, actor=actor, at=at)
    except AuditPeriodError as e:
        raise ValueError(str(e))


def _date_of(iso: str) -> str:
    return (iso or "")[:10]


def _report_in_window(store: ReportStore, start_date: str, end_date: str) -> str | None:
    """The latest report whose generated_at date falls within [start, end]."""
    in_window = [e for e in store.entries()
                 if start_date <= _date_of(e.generated_at) <= end_date]
    if not in_window:
        return None
    return max(in_window, key=lambda e: e.generated_at).report_id


def _evidence_sha(sha256: str) -> str:
    """Normalise + validate an evidence content address (64-char sha256 hex)."""
    sha = (sha256 or "").strip().lower()
    if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        raise ValueError("invalid evidence id — expected a 64-char sha256 hex digest")
    return sha


def get_evidence(store: ReportStore, sha256: str, *, now=None) -> dict:
    """Resolve a retained evidence object by its content address (FUR-CMP-007/008).

    Returns the raw event bytes (as text), the provenance envelope, a LIVE
    integrity re-verification (decrypted bytes re-hashed vs the address), and the
    retention posture (retain-until / expired under the configured policy, with an
    active legal hold overriding expiry). Raises ValueError for a malformed id and
    FileNotFoundError if nothing is retained under that address.
    """
    from compliance_reporting.evidence import EvidenceStore  # noqa: PLC0415
    from compliance_reporting.legal_hold import LegalHoldStore  # noqa: PLC0415
    from compliance_reporting.retention import retention_for  # noqa: PLC0415

    sha = _evidence_sha(sha256)
    ev = EvidenceStore(store.root)
    if not ev.exists(sha):
        raise FileNotFoundError(f"no retained evidence object for {sha}")
    envelope = ev.get_envelope(sha)
    integrity_verified = ev.verify_object(sha)
    raw_bytes = ev.get_raw(sha)

    hold_rec = LegalHoldStore(store.root).get(sha)
    on_hold = bool(hold_rec and hold_rec.get("active"))
    retention = retention_for(envelope.get("collected_at"), now=now)
    # an active legal hold freezes the object — never treat it as past-retention
    retention = {
        **retention,
        "expired": retention["expired"] and not on_hold,
        "on_legal_hold": on_hold,
        "legal_hold": hold_rec,
    }

    return {
        "sha256": sha,
        "raw_uri": f"furix-evidence://{sha}",
        "integrity_verified": integrity_verified,
        "size_bytes": len(raw_bytes),
        "raw": raw_bytes.decode("utf-8", errors="replace"),
        "envelope": envelope,
        "retention": retention,
    }


def place_legal_hold(store: ReportStore, sha256: str, *, reason: str, actor: str, at: str) -> dict:
    """Place a legal hold on a retained evidence object (overrides retention expiry)."""
    from compliance_reporting.evidence import EvidenceStore  # noqa: PLC0415
    from compliance_reporting.legal_hold import LegalHoldStore  # noqa: PLC0415
    sha = _evidence_sha(sha256)
    if not EvidenceStore(store.root).exists(sha):
        raise FileNotFoundError(f"no retained evidence object for {sha}")
    return LegalHoldStore(store.root).place(sha, reason=reason, actor=actor, at=at)


def release_legal_hold(store: ReportStore, sha256: str, *, actor: str, at: str, reason: str = "") -> dict:
    """Release an active legal hold (the record is retained soft for audit)."""
    from compliance_reporting.legal_hold import LegalHoldStore  # noqa: PLC0415
    sha = _evidence_sha(sha256)
    return LegalHoldStore(store.root).release(sha, actor=actor, at=at, reason=reason)


def list_legal_holds(store: ReportStore, *, active_only: bool = True) -> list:
    """List legal holds for a tenant (active by default)."""
    from compliance_reporting.legal_hold import LegalHoldStore  # noqa: PLC0415
    return LegalHoldStore(store.root).list(active_only=active_only)


def _verify_evidence_ref(store: ReportStore, ref: str) -> bool:
    """An evidence reference must be a furix-evidence://<sha256> that actually
    resolves to a retained, verifiable object — no arbitrary/dangling refs."""
    from compliance_reporting.evidence import EvidenceStore  # noqa: PLC0415
    prefix = "furix-evidence://"
    if not isinstance(ref, str) or not ref.startswith(prefix):
        return False
    sha = ref[len(prefix):]
    if len(sha) != 64:
        return False
    try:
        return EvidenceStore(store.root).verify_object(sha)
    except (OSError, ValueError):
        return False


def _audit_snapshot_payload(store: ReportStore, tenant: str, period: dict[str, Any],
                            report_id: str) -> dict[str, Any]:
    """The immutable content captured at sign-off: the audit package for the
    PERIOD'S report + the control workspace, bound to the period."""
    pkg = get_audit_package(store, report_id)  # raises IngestError if OSCAL doesn't validate
    workspace = list_control_workspace(store, tenant)
    return {
        "period": {k: period[k] for k in ("period_id", "name", "boundary",
                                          "start_date", "end_date")},
        "report_id": report_id,
        "evidence_requests": period["evidence_requests"],
        "audit_package": pkg,
        "control_workspace": workspace,
    }


def sign_off_audit_period(store: ReportStore, tenant: str, period_id: str, *,
                          reviewer: str, at: str, signer: Any = None,
                          require_signature: bool = False) -> dict[str, Any]:
    """
    Freeze the period with an IMMUTABLE, PERIOD-SCOPED, cryptographically-signed
    snapshot (Wave-J P1). Enforced before freezing:

    * every evidence request must be fulfilled, and each fulfilled reference must
      resolve to a retained, verifiable evidence object,
    * a report must exist WITHIN the period's date window (the snapshot binds to
      that report, not just "the latest"),
    * the snapshot is written to the write-once evidence store, and — when a
      signer is configured — asymmetrically signed (verifiable by public key).
    """
    from compliance_reporting.audit_period import AuditPeriodError  # noqa: PLC0415
    from compliance_reporting.evidence import EvidenceStore  # noqa: PLC0415
    period = get_audit_period(store, tenant, period_id)

    # 1. all evidence requests fulfilled + their references verifiable
    for req in period["evidence_requests"]:
        if req["status"] != "provided":
            raise ValueError(
                f"evidence request {req['req_id']} for {req['control_id']} is not fulfilled — "
                "all evidence requests must be provided before sign-off")
        if not _verify_evidence_ref(store, req.get("evidence_ref")):
            raise ValueError(
                f"evidence request {req['req_id']} references an unverifiable evidence object "
                f"({req.get('evidence_ref')!r}) — it must be a retained furix-evidence:// object")

    # 2. a report within the period window binds the snapshot
    report_id = _report_in_window(store, period["start_date"], period["end_date"])
    if report_id is None:
        raise ValueError(
            f"no assessment within the audit period window "
            f"[{period['start_date']} .. {period['end_date']}] — run a posture assessment first")

    try:
        payload = _audit_snapshot_payload(store, tenant, period, report_id)
    except IngestError as e:
        raise ValueError(f"cannot sign off: {e}")
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ev = EvidenceStore(store.root)
    obj = ev.put(raw, source="audit-snapshot", tenant=tenant)
    if not ev.verify_object(obj.sha256):
        raise ValueError("audit snapshot failed persistence verification")

    # 3. cryptographically sign the snapshot digest
    signature = None
    if signer is not None:
        signature = {
            "algorithm": signer.algorithm,
            "signature": signer.sign(obj.sha256.encode()),
            "public_key_pem": signer.public_key_pem(),
            "signed": obj.sha256,
        }
    elif require_signature:
        raise ValueError("audit sign-off requires a configured signing key in production")

    try:
        return _audit_store(store).record_signoff(
            tenant, period_id, reviewer=reviewer, at=at, report_id=report_id,
            snapshot_sha256=obj.sha256, snapshot_uri=f"furix-evidence://{obj.sha256}",
            signature=signature)
    except AuditPeriodError as e:
        raise ValueError(str(e))


def reopen_audit_period(store: ReportStore, tenant: str, period_id: str, *,
                        actor: str, at: str, reason: str) -> dict[str, Any]:
    from compliance_reporting.audit_period import AuditPeriodError  # noqa: PLC0415
    try:
        return _audit_store(store).record_reopen(tenant, period_id, actor=actor, at=at, reason=reason)
    except AuditPeriodError as e:
        raise ValueError(str(e))


def build_audit_zip(store: ReportStore, tenant: str, period_id: str) -> bytes:
    """A downloadable ZIP of the audit package. For a SIGNED-OFF period the ZIP is
    reconstructed from the IMMUTABLE signed snapshot (so it can never drift);
    otherwise it is built from the live current state."""
    import io  # noqa: PLC0415
    import zipfile  # noqa: PLC0415

    from compliance_reporting.evidence import EvidenceStore  # noqa: PLC0415
    period = get_audit_period(store, tenant, period_id)

    if period["signoffs"]:
        sha = period["signoffs"][-1]["snapshot_sha256"]
        payload = json.loads(EvidenceStore(store.root).get_raw(sha).decode("utf-8"))
        source = "signed-snapshot"
    else:
        report_id = (_report_in_window(store, period["start_date"], period["end_date"])
                     or "latest")
        payload = _audit_snapshot_payload(store, tenant, period, report_id)
        source = "live"

    pkg = payload["audit_package"]
    oscal = pkg.get("oscal", {})
    manifest = {
        "period": payload["period"], "status": period["status"], "frozen": period["frozen"],
        "signoffs": period["signoffs"], "reopenings": period["reopenings"],
        "evidence_requests": period["evidence_requests"],
        "report_id": pkg.get("report_id"),
        "report_integrity_sha256": pkg.get("integrity_sha256"),
        "oscal_validation_ok": oscal.get("validation_ok"),
        "package_source": source,
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("audit-manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
        zf.writestr("report-summary.json", json.dumps(pkg.get("summary", {}), indent=2, sort_keys=True))
        zf.writestr("oscal-assessment-results.json",
                    json.dumps(oscal.get("assessment_results", {}), indent=2, sort_keys=True))
        zf.writestr("oscal-poam.json", json.dumps(oscal.get("poam", {}), indent=2, sort_keys=True))
        zf.writestr("findings.json", json.dumps(pkg.get("findings", []), indent=2, sort_keys=True))
        zf.writestr("control-workspace.json",
                    json.dumps(payload.get("control_workspace", []), indent=2, sort_keys=True))
    return buf.getvalue()


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
    attestations: Any = None,
    attestation_keyring: Any = None,
) -> dict[str, Any]:
    """
    Ingest a config-posture snapshot (FUR-CMP-009). Combines it with the most
    recent detection batch (if any) so posture reflects both event evidence and
    config state, then builds + verifies + persists a report.

    Approved manual attestations (+ the tenant key ring) are threaded into the
    report build so a config/connector run NEVER regresses verified people/process
    controls back to pending (Wave-J P0).
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

    report = build_report(batch or [], registry=registry, config_snapshot=snap,
                          attestations=attestations, attestation_keyring=attestation_keyring,
                          tenant=tenant)
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
