"""
main.py
=======
FastAPI shell over the service layer. Every endpoint is authenticated,
authorized and tenant-scoped (FUR-CMP-004) and the surface is hardened
(FUR-SEC-004): bearer API keys with role+tenant claims, fail-closed authz,
per-tenant stores, rate limiting, body-size caps, safe error bodies and
security headers.

The heavy pipeline is imported lazily inside `service.ingest_batch`, so this
app starts (and read endpoints work) without torch/DB.

Run:  uvicorn api.main:app --host 0.0.0.0 --port 8000
Auth: send `Authorization: Bearer <api-key>` on every request except /api/health.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict
from threading import Lock

from fastapi import Depends, FastAPI, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from compliance_reporting.render_html import render_html_report
from compliance_reporting.settings import Settings

from compliance_reporting.admin_audit import AdminAuditLog
from compliance_reporting.attestation_store import AttestationError, AttestationStore
from compliance_reporting.connector_registry import ConnectorRegistry
from compliance_reporting.scim import ScimError, ScimUserStore
from compliance_reporting.work_queue import WorkQueue

from . import service
from .attest_keys import attestation_keyring_for
from .secrets_env import read_secret
from .auth import (
    AuthError, AuthRegistry, ForbiddenError, Principal,
    SCOPE_ADMIN, SCOPE_EXPORT, SCOPE_INGEST, SCOPE_READ,
)
from .jobs import JobManager
from .tenancy import TenantStores

# Fail-closed production readiness (addresses the audit's "silent optional"
# P0/P1s): in production a weak posture refuses to boot rather than serving.
from .preflight import run as _preflight  # noqa: E402
_preflight()

_settings = Settings.from_env()
_auth = AuthRegistry.from_env()
_stores = TenantStores(_settings.store_path)
_jobs = JobManager()

# per-tenant attestation submission/approval stores (Wave-F), cached
_attest_stores: dict[str, AttestationStore] = {}
_attest_lock = Lock()


def _attest_store_for(tenant: str) -> AttestationStore:
    with _attest_lock:
        s = _attest_stores.get(tenant)
        if s is None:
            s = AttestationStore(_stores.for_tenant(tenant).root)
            _attest_stores[tenant] = s
        return s


def _approved_attestations(tenant: str):
    """(attestations, keyring) for a tenant — only APPROVED, verified with the
    tenant key ring, so reports built during ingest can positively pass the
    people/process controls from human evidence."""
    ring = attestation_keyring_for(tenant)
    return _attest_store_for(tenant).approved_attestations(tenant), ring


# per-tenant connector registries (Wave-G), cached
_connector_regs: dict[str, ConnectorRegistry] = {}
_connector_lock = Lock()


def _connector_registry_for(tenant: str) -> ConnectorRegistry:
    with _connector_lock:
        r = _connector_regs.get(tenant)
        if r is None:
            r = ConnectorRegistry(_stores.for_tenant(tenant).root)
            _connector_regs[tenant] = r
        return r


# Connector manifests are mandatory-signed; the secret is server-only config
# (Docker-secret-friendly via FURIX_CONNECTOR_SIGNING_SECRET_FILE).
_CONNECTOR_SIGNING_SECRET = read_secret("FURIX_CONNECTOR_SIGNING_SECRET", "")


# ── enterprise runtime (Wave-I / Epic 6) ──────────────────────────────────────
def _admin_audit_for(tenant: str) -> AdminAuditLog:
    return AdminAuditLog(_stores.for_tenant(tenant).root)


def _record_admin(principal: Principal, action: str, *, target: str = "",
                  outcome: str = "ok", details: dict | None = None) -> None:
    """Append a tamper-evident entry to the administrative audit log."""
    try:
        _admin_audit_for(principal.tenant_id).append(
            tenant=principal.tenant_id, actor=principal.key_id, action=action,
            at=service.now_iso(), target=target, outcome=outcome, details=details or {})
    except Exception:  # noqa: BLE001 - auditing must never break the request path
        pass


def _work_queue_for(tenant: str) -> WorkQueue:
    return WorkQueue(_stores.for_tenant(tenant).root)


# Framework crosswalk registry — built once (live DB, else bundled snapshot).
_registry_cache: list = []


def _registry():
    if not _registry_cache:
        from compliance_reporting.registry import FrameworkRegistry  # noqa: PLC0415
        _registry_cache.append(FrameworkRegistry.from_live())
    return _registry_cache[0]


def _audit_signer():
    """Resolve the asymmetric signer for audit snapshots (Wave-J P1). Prefers an
    explicit PEM (or KMS) key; in development, persists a generated key so
    signatures are always real and later-verifiable; in production, returns None
    when unconfigured so sign-off fails closed."""
    from compliance_reporting.signing import LocalRsaSigner  # noqa: PLC0415
    pem = read_secret("FURIX_AUDIT_SIGNING_KEY_PEM")
    if pem:
        return LocalRsaSigner(pem)
    kms_key = os.environ.get("FURIX_AUDIT_KMS_KEY_ID")
    if kms_key:
        import boto3  # noqa: PLC0415
        from compliance_reporting.signing import KmsSigner  # noqa: PLC0415
        return KmsSigner(kms_key, boto3.client("kms"))
    if _is_production():
        return None  # fail-closed: require_signature will reject
    # development: persist a generated signing key alongside the store
    key_path = _stores.root.parent / "audit-signing-key.pem"
    if key_path.exists():
        return LocalRsaSigner(key_path.read_text(encoding="utf-8"))
    signer = LocalRsaSigner.generate()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(signer.private_key_pem(), encoding="utf-8")
    return signer


def _reject_demo_in_prod(kind: str) -> None:
    """Demo-tenant isolation: synthetic/demo connectors are refused in production
    so demo evidence can never be mistaken for, or mixed into, a real tenant."""
    if service.is_demo_kind(kind) and os.environ.get("FURIX_ENV", "development").lower() == "production":
        raise HTTPException(
            status_code=400,
            detail=f"demo connector kind {kind!r} is disabled in production — demo/synthetic "
                   "data is isolated from production tenants")

# Hardening knobs (env-overridable)
_MAX_BODY_BYTES = int(os.environ.get("FURIX_MAX_BODY_BYTES", str(50 * 1024 * 1024)))  # 50 MB
_MAX_INGEST_CHARS = int(os.environ.get("FURIX_MAX_INGEST_CHARS", str(20 * 1024 * 1024)))
_RATE_LIMIT = int(os.environ.get("FURIX_RATE_LIMIT_PER_MIN", "240"))  # per key, per minute

app = FastAPI(title="Furix Compliance API", version=_settings.engine_version)

# CORS — tight: only the configured dashboard origin(s), only the verbs/headers
# actually used. No wildcard.
_origins = os.environ.get("FURIX_CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _origins if o.strip()],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["authorization", "content-type"],
    max_age=600,
)


# ── security headers + body cap (applied to every response) ───────────────────
@app.middleware("http")
async def _harden(request: Request, call_next):
    clen = request.headers.get("content-length")
    if clen and clen.isdigit() and int(clen) > _MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "request body too large"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


# ── simple per-key fixed-window rate limiter ──────────────────────────────────
class _RateLimiter:
    def __init__(self, per_min: int):
        self.per_min = per_min
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def check(self, key: str) -> bool:
        if self.per_min <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            window = [t for t in self._hits[key] if now - t < 60.0]
            window.append(now)
            self._hits[key] = window
            return len(window) <= self.per_min


_rate = _RateLimiter(_RATE_LIMIT)


# ── auth dependency ───────────────────────────────────────────────────────────
def require(scope: str, action: str):
    """Build a dependency that authenticates, rate-limits and authorizes."""

    def _dep(authorization: str | None = Header(default=None)) -> Principal:
        try:
            principal = _auth.authenticate(authorization)
        except AuthError as e:
            raise HTTPException(status_code=401, detail=str(e),
                                headers={"WWW-Authenticate": "Bearer"})
        if not _rate.check(principal.key_id):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        try:
            _auth.authorize(principal, scope, action)
        except ForbiddenError as e:
            raise HTTPException(status_code=403, detail=str(e))
        return principal

    return _dep


def _store_for(principal: Principal, tenant: str | None):
    """Resolve the tenant store, enforcing cross-tenant access rules."""
    target = tenant or principal.tenant_id
    if target != principal.tenant_id and not principal.can_read_tenant(target):
        raise HTTPException(status_code=403, detail="cross-tenant access denied")
    try:
        return _stores.for_tenant(target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


def _handle(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except (FileNotFoundError, ValueError) as e:
        raise HTTPException(status_code=404, detail=str(e))
    except service.IngestError:
        # do not leak internal verification detail to the client
        raise HTTPException(status_code=422, detail="ingested batch failed verification")


class IngestBody(BaseModel):
    text: str = ""
    log_type: str = "auto"


class GenerateBody(BaseModel):
    count: int = 50
    attack_ratio: float = 0.35
    seed: int = 0


class ConfigBody(BaseModel):
    snapshot: dict = {}


# ── health / readiness (unauthenticated, minimal) ─────────────────────────────
@app.get("/api/health")
def health():
    """Liveness: the process is up and serving. Cheap; never touches deps."""
    return {"status": "ok", "engine_version": _settings.engine_version}


@app.get("/readyz")
@app.get("/api/readyz")
def readyz():
    """
    Readiness (deployment contract): 200 only when the service can actually do
    work — the tenant report-store root is writable, the job DB directory exists,
    and (in production) the fail-closed preflight has no blocking issues. Returns
    503 with the specific reasons otherwise, so an orchestrator holds traffic
    until the pod is genuinely ready.
    """
    checks: dict[str, Any] = {}
    reasons: list[str] = []

    # report store writable
    try:
        root = _stores.root
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".readyz"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        checks["report_store_writable"] = True
    except Exception as e:  # noqa: BLE001
        checks["report_store_writable"] = False
        reasons.append(f"report store not writable: {e}")

    # job DB directory present (durable jobs survive restarts)
    job_db = os.environ.get("FURIX_JOB_DB", "")
    if job_db:
        job_dir_ok = os.path.isdir(os.path.dirname(job_db) or ".")
        checks["job_db_dir"] = job_dir_ok
        if not job_dir_ok:
            reasons.append(f"FURIX_JOB_DB directory missing: {job_db}")
    else:
        checks["job_db_dir"] = None  # not configured (dev)

    # production preflight — in production, any outstanding preflight issue holds
    # readiness (weak keys, no durable job DB, unacknowledged TLS, etc.).
    is_prod = os.environ.get("FURIX_ENV", "development").lower() == "production"
    if is_prod:
        from .preflight import collect_issues  # noqa: PLC0415
        prod_issues = collect_issues()
        checks["preflight_issues"] = len(prod_issues)
        reasons += prod_issues
    else:
        checks["preflight_issues"] = None  # development: not gated on preflight

    ready = not reasons
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"ready": ready, "checks": checks, "reasons": reasons,
                 "engine_version": _settings.engine_version},
    )


# ── async ingest: submit a background job, poll GET /api/jobs/{id} ─────────────
@app.post("/api/ingest", status_code=202)
def ingest(body: IngestBody, principal: Principal = Depends(require(SCOPE_INGEST, "ingest"))):
    if not body.text.strip():
        raise HTTPException(status_code=400, detail="no log text provided")
    if len(body.text) > _MAX_INGEST_CHARS:
        raise HTTPException(status_code=413, detail="log payload too large")
    store = _store_for(principal, None)
    text, lt, tn = body.text, body.log_type, principal.tenant_id
    atts, ring = _approved_attestations(tn)
    job_id = _jobs.submit(
        lambda progress: service.ingest_batch(store, text, log_type=lt, tenant=tn,
                                              attestations=atts, attestation_keyring=ring,
                                              on_progress=progress),
        owner=principal.key_id,
    )
    return {"job_id": job_id}


def _is_production() -> bool:
    return os.environ.get("FURIX_ENV", "development").lower() == "production"


@app.post("/api/generate", status_code=202)
def generate(body: GenerateBody, principal: Principal = Depends(require(SCOPE_INGEST, "generate"))):
    # Synthetic log + demo config/attestation generation must NEVER write into a
    # real tenant's report history in production (Wave-J P0).
    if _is_production():
        raise HTTPException(
            status_code=403,
            detail="synthetic data generation (/api/generate) is disabled in production — "
                   "it writes demo config + attestations into the tenant's real report history")
    store = _store_for(principal, None)
    c, ar, sd, tn = max(0, body.count), body.attack_ratio, body.seed, principal.tenant_id
    job_id = _jobs.submit(
        lambda progress: service.generate_and_ingest(
            store, count=c, attack_ratio=ar, seed=sd, tenant=tn, on_progress=progress),
        owner=principal.key_id,
    )
    return {"job_id": job_id}


@app.post("/api/ingest-file", status_code=202)
async def ingest_file(file: UploadFile,
                      principal: Principal = Depends(require(SCOPE_INGEST, "ingest_file")),
                      log_type: str = "auto"):
    raw = (await file.read(_MAX_INGEST_CHARS + 1)).decode("utf-8", errors="replace")
    if not raw.strip():
        raise HTTPException(status_code=400, detail="empty file")
    if len(raw) > _MAX_INGEST_CHARS:
        raise HTTPException(status_code=413, detail="file too large")
    store = _store_for(principal, None)
    tn = principal.tenant_id
    atts, ring = _approved_attestations(tn)
    job_id = _jobs.submit(
        lambda progress: service.ingest_batch(store, raw, log_type=log_type, tenant=tn,
                                              attestations=atts, attestation_keyring=ring,
                                              on_progress=progress),
        owner=principal.key_id,
    )
    return {"job_id": job_id}


@app.post("/api/ingest-config", status_code=201)
def ingest_config(body: ConfigBody,
                  principal: Principal = Depends(require(SCOPE_INGEST, "ingest_config"))):
    """Ingest a config-posture snapshot → positive assertions → met controls."""
    if not body.snapshot or not body.snapshot.get("resources"):
        raise HTTPException(status_code=400, detail="snapshot has no resources")
    store = _store_for(principal, None)
    atts, ring = _approved_attestations(principal.tenant_id)
    return _handle(service.ingest_config, store, body.snapshot, tenant=principal.tenant_id,
                   attestations=atts, attestation_keyring=ring)


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str, principal: Principal = Depends(require(SCOPE_READ, "job_status"))):
    job = _jobs.get(job_id)
    if not job or getattr(job, "owner", principal.key_id) != principal.key_id:
        # do not reveal the existence of another principal's job
        raise HTTPException(status_code=404, detail="no such job")
    return job.to_dict()


@app.get("/api/reports")
def reports(principal: Principal = Depends(require(SCOPE_READ, "list_reports")),
            tenant: str | None = None):
    return service.list_reports(_store_for(principal, tenant))


@app.get("/api/report/{report_id}")
def report(report_id: str, principal: Principal = Depends(require(SCOPE_READ, "get_report")),
           tenant: str | None = None):
    return _handle(service.get_report, _store_for(principal, tenant), report_id)


@app.get("/api/report/{report_id}/html", response_class=HTMLResponse)
def report_html(report_id: str, principal: Principal = Depends(require(SCOPE_READ, "report_html")),
                tenant: str | None = None):
    rep = _handle(service.get_report, _store_for(principal, tenant), report_id)
    return HTMLResponse(render_html_report(rep))


@app.get("/api/frameworks")
def frameworks(principal: Principal = Depends(require(SCOPE_READ, "frameworks")),
               report: str = "latest", tenant: str | None = None):
    return _handle(service.get_frameworks, _store_for(principal, tenant), report)


@app.get("/api/summary")
def summary(principal: Principal = Depends(require(SCOPE_READ, "summary")),
            report: str = "latest", tenant: str | None = None):
    return _handle(service.get_summary, _store_for(principal, tenant), report)


@app.get("/api/trend")
def trend(principal: Principal = Depends(require(SCOPE_READ, "trend")),
          tenant: str | None = None):
    return service.get_trend(_store_for(principal, tenant))


# ── finding / exception lifecycle (Wave 5) ────────────────────────────────────
class TransitionBody(BaseModel):
    action: str
    reason: str = ""
    occurred_at: str
    payload: dict = {}


@app.post("/api/findings/derive", status_code=201)
def derive_findings(occurred_at: str,
                    principal: Principal = Depends(require(SCOPE_INGEST, "derive_findings")),
                    report: str = "latest"):
    store = _store_for(principal, None)
    return _handle(service.derive_findings, store, report, tenant=principal.tenant_id,
                   actor=principal.key_id, occurred_at=occurred_at)


@app.get("/api/findings")
def findings(principal: Principal = Depends(require(SCOPE_READ, "list_findings")),
             tenant: str | None = None, as_of: str | None = None, open_only: bool = False):
    return service.list_findings(_store_for(principal, tenant), as_of=as_of, open_only=open_only)


@app.get("/api/findings/{finding_id}/history")
def finding_history(finding_id: str,
                    principal: Principal = Depends(require(SCOPE_READ, "finding_history")),
                    tenant: str | None = None):
    return service.finding_history(_store_for(principal, tenant), finding_id)


@app.post("/api/findings/{finding_id}/transition")
def transition_finding(finding_id: str, body: TransitionBody,
                       principal: Principal = Depends(require(SCOPE_INGEST, "transition_finding"))):
    # Risk acceptance is an approval authority — require the admin scope.
    if body.action == "accept_risk" and not principal.has(SCOPE_ADMIN):
        raise HTTPException(status_code=403, detail="risk acceptance requires approver (admin) authority")
    store = _store_for(principal, None)
    return _handle(service.transition_finding, store, finding_id, body.action,
                   actor=principal.key_id, occurred_at=body.occurred_at,
                   reason=body.reason, payload=body.payload)


# ── attestation submission / approval (Wave-F) ────────────────────────────────
class AttestationBody(BaseModel):
    attestation: dict = {}
    as_of: str | None = None


class AttestationDecisionBody(BaseModel):
    decided_at: str
    reason: str = ""


@app.get("/api/attestations")
def list_attestations(principal: Principal = Depends(require(SCOPE_READ, "list_attestations")),
                      tenant: str | None = None, status: str | None = None):
    target = _store_for(principal, tenant)  # enforces cross-tenant rules
    del target
    tn = tenant or principal.tenant_id
    return _attest_store_for(tn).list(tn, status=status)


@app.post("/api/attestations", status_code=201)
def submit_attestation(body: AttestationBody,
                       principal: Principal = Depends(require(SCOPE_INGEST, "submit_attestation"))):
    tn = principal.tenant_id
    ring = attestation_keyring_for(tn)
    try:
        return _attest_store_for(tn).submit(
            body.attestation, tenant=tn, keyring=ring, submitted_by=principal.key_id,
            submitted_at=service.now_iso(), as_of=body.as_of)
    except AttestationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/attestations/{att_id}/approve")
def approve_attestation(att_id: str, body: AttestationDecisionBody,
                        principal: Principal = Depends(require(SCOPE_INGEST, "approve_attestation"))):
    # Approval is an authority act (segregation of duty) — require admin.
    if not principal.has(SCOPE_ADMIN):
        raise HTTPException(status_code=403, detail="attestation approval requires admin authority")
    tn = principal.tenant_id
    try:
        result = _attest_store_for(tn).approve(
            att_id, tenant=tn, approved_by=principal.key_id, decided_at=body.decided_at,
            reason=body.reason)
        _record_admin(principal, "attestation.approve", target=att_id,
                      details={"status": result["status"]})
        return result
    except AttestationError as e:
        # unknown id → 404; a rule violation (self-approval, duplicate, bad state) → 400
        raise HTTPException(status_code=404 if "unknown" in str(e) else 400, detail=str(e))


@app.post("/api/attestations/{att_id}/reject")
def reject_attestation(att_id: str, body: AttestationDecisionBody,
                       principal: Principal = Depends(require(SCOPE_INGEST, "reject_attestation"))):
    if not principal.has(SCOPE_ADMIN):
        raise HTTPException(status_code=403, detail="attestation rejection requires admin authority")
    tn = principal.tenant_id
    try:
        return _attest_store_for(tn).reject(
            att_id, tenant=tn, rejected_by=principal.key_id, decided_at=body.decided_at,
            reason=body.reason)
    except AttestationError as e:
        raise HTTPException(status_code=404 if "unknown" in str(e) else 400, detail=str(e))


# ── connectors: scheduled collection + health (Wave-G) ────────────────────────
class ConnectorBody(BaseModel):
    connector_id: str
    kind: str = "demo-aws"
    schedule_seconds: int = 86400
    config: dict = {}


def _connector_signing_secret() -> str | None:
    if _CONNECTOR_SIGNING_SECRET:
        return _CONNECTOR_SIGNING_SECRET
    # dev convenience only — never a silent secret in production
    if os.environ.get("FURIX_ENV", "development").lower() != "production":
        return "furix-dev-connector-secret"
    return None


@app.get("/api/connectors")
def list_connectors(principal: Principal = Depends(require(SCOPE_READ, "list_connectors")),
                    tenant: str | None = None):
    tn = (tenant or principal.tenant_id)
    _store_for(principal, tenant)  # enforce cross-tenant rules
    return _connector_registry_for(tn).list(tn, now=int(time.time()))


@app.post("/api/connectors", status_code=201)
def register_connector(body: ConnectorBody,
                       principal: Principal = Depends(require(SCOPE_INGEST, "register_connector"))):
    if not principal.has(SCOPE_ADMIN):
        raise HTTPException(status_code=403, detail="registering a connector requires admin authority")
    if body.schedule_seconds < 60:
        raise HTTPException(status_code=400, detail="schedule_seconds must be >= 60")
    _reject_demo_in_prod(body.kind)
    tn = principal.tenant_id
    now = int(time.time())
    reg = _connector_registry_for(tn)
    reg.register(tenant=tn, connector_id=body.connector_id, kind=body.kind,
                 schedule_seconds=body.schedule_seconds, now=now, config=body.config)
    _record_admin(principal, "connector.register", target=body.connector_id,
                  details={"kind": body.kind})
    # return the health-enriched record
    return next(c for c in reg.list(tn, now=now) if c["connector_id"] == body.connector_id)


@app.post("/api/connectors/{connector_id}/run")
def run_connector(connector_id: str,
                  principal: Principal = Depends(require(SCOPE_INGEST, "run_connector"))):
    if not principal.has(SCOPE_ADMIN):
        raise HTTPException(status_code=403, detail="running a connector requires admin authority")
    secret = _connector_signing_secret()
    if not secret:
        raise HTTPException(status_code=400,
                            detail="connector manifest signing secret not configured "
                                   "(set FURIX_CONNECTOR_SIGNING_SECRET); manifests are mandatory-signed")
    tn = principal.tenant_id
    reg = _connector_registry_for(tn)
    job = reg.get(tn, connector_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"unknown connector {connector_id}")
    _reject_demo_in_prod(job["kind"])
    store = _store_for(principal, None)
    now = int(time.time())
    atts, ring = _approved_attestations(tn)
    # A connector run executes the FULL unified posture pipeline (evaluates
    # controls, verifies, opens findings) — not a manifest-only collection
    # (Wave-J P0). Health is recorded from the signed manifest.
    try:
        out = service.run_connector_posture(
            store, tn, connector_id, kind=job["kind"], config=job.get("config", {}) or {},
            signing_secret=secret, registry=_registry(), attestations=atts,
            attestation_keyring=ring, actor=principal.key_id)
        reg.record_run(tn, connector_id, now=now, manifest=out["manifest"], error=None)
        _record_admin(principal, "connector.run", target=connector_id,
                      details={"report_id": out["run"]["report_id"]})
    except Exception as e:  # noqa: BLE001
        reg.record_run(tn, connector_id, now=now, manifest=None, error=str(e))
        _record_admin(principal, "connector.run", target=connector_id, outcome="error",
                      details={"error": str(e)[:200]})
        raise HTTPException(status_code=422, detail=f"connector run failed: {e}")
    return next(c for c in reg.list(tn, now=now) if c["connector_id"] == connector_id)


# ── unified posture-run pipeline (Wave-H) ─────────────────────────────────────
@app.post("/api/connectors/{connector_id}/posture-run", status_code=201)
def connector_posture_run(connector_id: str,
                          principal: Principal = Depends(require(SCOPE_INGEST, "posture_run"))):
    """Run the full pipeline for a connector: collect → evidence → reconcile →
    assertions → verified report → findings, recorded as one linked-ID run."""
    if not principal.has(SCOPE_ADMIN):
        raise HTTPException(status_code=403, detail="running a posture run requires admin authority")
    secret = _connector_signing_secret()
    if not secret:
        raise HTTPException(status_code=400,
                            detail="connector manifest signing secret not configured "
                                   "(set FURIX_CONNECTOR_SIGNING_SECRET)")
    tn = principal.tenant_id
    reg = _connector_registry_for(tn)
    job = reg.get(tn, connector_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"unknown connector {connector_id}")
    _reject_demo_in_prod(job["kind"])
    store = _store_for(principal, None)
    now = int(time.time())
    data_mode = "demo" if service.is_demo_kind(job["kind"]) else "live"
    atts, ring = _approved_attestations(tn)
    try:
        collected = service.collect_snapshot(tn, job["kind"], job.get("config", {}) or {}, secret)
        run = service.run_posture(store, tenant=tn, snapshot=collected["snapshot"],
                                  manifest=collected["manifest"], connector_id=connector_id,
                                  occurred_at=service.now_iso(), actor=principal.key_id,
                                  data_mode=data_mode, attestations=atts, attestation_keyring=ring)
        reg.record_run(tn, connector_id, now=now, manifest=collected["manifest"], error=None)
        _record_admin(principal, "connector.posture_run", target=connector_id,
                      details={"report_id": run["report_id"], "run_id": run["run_id"],
                               "data_mode": data_mode})
        return run
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001 - record the failure on the connector, surface 422
        reg.record_run(tn, connector_id, now=now, manifest=None, error=str(e))
        _record_admin(principal, "connector.posture_run", target=connector_id,
                      outcome="error", details={"error": str(e)[:200]})
        raise HTTPException(status_code=422, detail=f"posture run failed: {e}")


@app.get("/api/posture-runs")
def posture_runs(principal: Principal = Depends(require(SCOPE_READ, "list_posture_runs")),
                 tenant: str | None = None):
    tn = tenant or principal.tenant_id
    _store_for(principal, tenant)  # enforce cross-tenant rules
    return service.list_posture_runs(_stores.for_tenant(tn), tn)


@app.get("/api/posture-runs/{run_id}")
def posture_run(run_id: str,
                principal: Principal = Depends(require(SCOPE_READ, "get_posture_run")),
                tenant: str | None = None):
    tn = tenant or principal.tenant_id
    _store_for(principal, tenant)
    return _handle(service.get_posture_run, _stores.for_tenant(tn), tn, run_id)


# ── audit-period workflow (Wave-I / Epic 5) ───────────────────────────────────
class AuditPeriodBody(BaseModel):
    name: str
    boundary: str = ""
    start_date: str
    end_date: str


class EvidenceRequestBody(BaseModel):
    control_id: str
    note: str = ""


class FulfillBody(BaseModel):
    evidence_ref: str


class ReopenBody(BaseModel):
    reason: str = ""


@app.post("/api/audit-periods", status_code=201)
def create_audit_period(body: AuditPeriodBody,
                        principal: Principal = Depends(require(SCOPE_INGEST, "create_audit_period"))):
    if not principal.has(SCOPE_ADMIN):
        raise HTTPException(status_code=403, detail="creating an audit period requires admin authority")
    store = _store_for(principal, None)
    return service.create_audit_period(store, principal.tenant_id, name=body.name,
                                       boundary=body.boundary, start_date=body.start_date,
                                       end_date=body.end_date, actor=principal.key_id,
                                       at=service.now_iso())


@app.get("/api/audit-periods")
def list_audit_periods(principal: Principal = Depends(require(SCOPE_READ, "list_audit_periods")),
                       tenant: str | None = None):
    store = _store_for(principal, tenant)
    return service.list_audit_periods(store, tenant or principal.tenant_id)


@app.get("/api/audit-periods/{period_id}")
def get_audit_period(period_id: str,
                     principal: Principal = Depends(require(SCOPE_READ, "get_audit_period")),
                     tenant: str | None = None):
    store = _store_for(principal, tenant)
    return _handle(service.get_audit_period, store, tenant or principal.tenant_id, period_id)


@app.post("/api/audit-periods/{period_id}/evidence-requests", status_code=201)
def add_evidence_request(period_id: str, body: EvidenceRequestBody,
                         principal: Principal = Depends(require(SCOPE_INGEST, "add_evidence_request"))):
    store = _store_for(principal, None)
    try:
        return service.add_evidence_request(store, principal.tenant_id, period_id,
                                            control_id=body.control_id, note=body.note,
                                            actor=principal.key_id, at=service.now_iso())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/audit-periods/{period_id}/evidence-requests/{req_id}/fulfill")
def fulfill_evidence_request(period_id: str, req_id: str, body: FulfillBody,
                             principal: Principal = Depends(require(SCOPE_INGEST, "fulfill_evidence_request"))):
    store = _store_for(principal, None)
    try:
        return service.fulfill_evidence_request(store, principal.tenant_id, period_id, req_id,
                                                evidence_ref=body.evidence_ref,
                                                actor=principal.key_id, at=service.now_iso())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/audit-periods/{period_id}/signoff")
def signoff_audit_period(period_id: str,
                         principal: Principal = Depends(require(SCOPE_EXPORT, "signoff_audit_period"))):
    # Sign-off (freeze) is a reviewer act — the export scope (auditor/admin).
    store = _store_for(principal, None)
    try:
        result = service.sign_off_audit_period(
            store, principal.tenant_id, period_id, reviewer=principal.key_id,
            at=service.now_iso(), signer=_audit_signer(), require_signature=_is_production())
        so = result["signoffs"][-1]
        _record_admin(principal, "audit_period.signoff", target=period_id,
                      details={"snapshot_sha256": so["snapshot_sha256"], "report_id": so["report_id"],
                               "signed": bool(so.get("signature"))})
        return result
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/audit-periods/{period_id}/reopen")
def reopen_audit_period(period_id: str, body: ReopenBody,
                        principal: Principal = Depends(require(SCOPE_INGEST, "reopen_audit_period"))):
    if not principal.has(SCOPE_ADMIN):
        raise HTTPException(status_code=403, detail="reopening a frozen period requires admin authority")
    store = _store_for(principal, None)
    try:
        result = service.reopen_audit_period(store, principal.tenant_id, period_id,
                                             actor=principal.key_id, at=service.now_iso(),
                                             reason=body.reason)
        _record_admin(principal, "audit_period.reopen", target=period_id,
                      details={"reason": body.reason})
        return result
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/audit-periods/{period_id}/package.zip")
def download_audit_package(period_id: str,
                           principal: Principal = Depends(require(SCOPE_EXPORT, "download_audit_package"))):
    # Auditor-only (export scope): the self-contained, downloadable evidence ZIP.
    store = _store_for(principal, None)
    try:
        data = service.build_audit_zip(store, principal.tenant_id, period_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except (ValueError, service.IngestError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return Response(content=data, media_type="application/zip",
                    headers={"content-disposition": f'attachment; filename="audit-{period_id}.zip"'})


# ── compliance workspace (Wave-I / Epic 4) ────────────────────────────────────
class ControlProfileBody(BaseModel):
    owner: str | None = None
    applicability: str | None = None
    applicability_rationale: str | None = None
    implementation_narrative: str | None = None
    verification_method: str | None = None
    verification_description: str | None = None
    test_cadence_days: int | None = None


@app.get("/api/compliance/controls")
def compliance_controls(principal: Principal = Depends(require(SCOPE_READ, "compliance_controls")),
                        tenant: str | None = None):
    store = _store_for(principal, tenant)
    return service.list_control_workspace(store, tenant or principal.tenant_id,
                                          registry=_registry(), now=service.now_iso())


@app.get("/api/compliance/controls/{control_id}")
def compliance_control_detail(control_id: str,
                              principal: Principal = Depends(require(SCOPE_READ, "compliance_control")),
                              tenant: str | None = None):
    store = _store_for(principal, tenant)
    return _handle(service.get_control_workspace, store, tenant or principal.tenant_id,
                   control_id, registry=_registry(), now=service.now_iso())


@app.put("/api/compliance/controls/{control_id}")
def update_compliance_control(control_id: str, body: ControlProfileBody,
                              principal: Principal = Depends(require(SCOPE_INGEST, "update_control"))):
    store = _store_for(principal, None)
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        result = service.update_control_profile(store, principal.tenant_id, control_id, patch,
                                                actor=principal.key_id, updated_at=service.now_iso())
        _record_admin(principal, "control.profile_update", target=control_id,
                      details={"fields": sorted(patch.keys())})
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── enterprise runtime: admin audit log + queue + SCIM (Wave-I / Epic 6) ──────
@app.get("/api/admin/audit-log")
def admin_audit_log(principal: Principal = Depends(require(SCOPE_READ, "admin_audit_log")),
                    tenant: str | None = None, limit: int = 200):
    if not principal.has(SCOPE_ADMIN):
        raise HTTPException(status_code=403, detail="the administrative audit log requires admin authority")
    tn = tenant or principal.tenant_id
    _store_for(principal, tenant)
    return _admin_audit_for(tn).list(tn, limit=limit)


@app.get("/api/admin/audit-log/verify")
def admin_audit_verify(principal: Principal = Depends(require(SCOPE_READ, "admin_audit_verify")),
                       tenant: str | None = None):
    if not principal.has(SCOPE_ADMIN):
        raise HTTPException(status_code=403, detail="audit-log verification requires admin authority")
    tn = tenant or principal.tenant_id
    _store_for(principal, tenant)
    return _admin_audit_for(tn).verify(tn)


@app.get("/api/admin/queue/stats")
def admin_queue_stats(principal: Principal = Depends(require(SCOPE_READ, "queue_stats"))):
    if not principal.has(SCOPE_ADMIN):
        raise HTTPException(status_code=403, detail="queue stats require admin authority")
    return _work_queue_for(principal.tenant_id).stats(principal.tenant_id)


# ── SCIM 2.0 user provisioning ────────────────────────────────────────────────
def _scim_store(principal: Principal) -> ScimUserStore:
    return ScimUserStore(_stores.for_tenant(principal.tenant_id).root, principal.tenant_id)


def _scim_error(e: ScimError):
    return JSONResponse(
        status_code=e.status,
        content={"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                 "detail": str(e), "status": str(e.status)})


@app.post("/scim/v2/Users", status_code=201)
def scim_create_user(body: dict,
                     principal: Principal = Depends(require(SCOPE_ADMIN, "scim_create"))):
    try:
        return _scim_store(principal).create(body, now=service.now_iso())
    except ScimError as e:
        return _scim_error(e)


@app.get("/scim/v2/Users")
def scim_list_users(principal: Principal = Depends(require(SCOPE_ADMIN, "scim_list")),
                    filter: str | None = None):
    user_name = None
    if filter and "userName eq " in filter:
        user_name = filter.split("userName eq ", 1)[1].strip().strip('"')
    return _scim_store(principal).list(user_name=user_name)


@app.get("/scim/v2/Users/{user_id}")
def scim_get_user(user_id: str,
                  principal: Principal = Depends(require(SCOPE_ADMIN, "scim_get"))):
    try:
        return _scim_store(principal).get(user_id)
    except ScimError as e:
        return _scim_error(e)


@app.put("/scim/v2/Users/{user_id}")
def scim_replace_user(user_id: str, body: dict,
                      principal: Principal = Depends(require(SCOPE_ADMIN, "scim_replace"))):
    try:
        result = _scim_store(principal).replace(user_id, body, now=service.now_iso())
        _record_admin(principal, "scim.replace", target=user_id)
        return result
    except ScimError as e:
        return _scim_error(e)


@app.delete("/scim/v2/Users/{user_id}")
def scim_deactivate_user(user_id: str,
                         principal: Principal = Depends(require(SCOPE_ADMIN, "scim_delete"))):
    # SCIM deprovisioning: deactivate (soft) so the identity + audit trail persist.
    try:
        _scim_store(principal).set_active(user_id, False, now=service.now_iso())
        _record_admin(principal, "scim.deprovision", target=user_id)
        return Response(status_code=204)
    except ScimError as e:
        return _scim_error(e)


# ── OSCAL + auditor workspace (Wave 5) ────────────────────────────────────────
@app.get("/api/oscal")
def oscal(principal: Principal = Depends(require(SCOPE_EXPORT, "oscal")),
          report: str = "latest", kind: str = "assessment-results",
          as_of: str | None = None, tenant: str | None = None):
    return _handle(service.get_oscal, _store_for(principal, tenant), report, kind=kind, as_of=as_of)


@app.get("/api/audit/export")
def audit_export(principal: Principal = Depends(require(SCOPE_EXPORT, "audit_export")),
                 report: str = "latest", as_of: str | None = None, tenant: str | None = None):
    return _handle(service.get_audit_package, _store_for(principal, tenant), report, as_of=as_of)


@app.get("/api/diff")
def diff(old: str, new: str,
         principal: Principal = Depends(require(SCOPE_READ, "diff")),
         tenant: str | None = None):
    return _handle(service.get_diff, _store_for(principal, tenant), old, new)
