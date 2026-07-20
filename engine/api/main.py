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
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from compliance_reporting.render_html import render_html_report
from compliance_reporting.settings import Settings

from compliance_reporting.attestation_store import AttestationError, AttestationStore
from compliance_reporting.connector_registry import ConnectorRegistry, ConnectorScheduler

from . import service
from .attest_keys import attestation_keyring_for
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


# Connector manifests are mandatory-signed; the secret is server-only config.
_CONNECTOR_SIGNING_SECRET = os.environ.get("FURIX_CONNECTOR_SIGNING_SECRET", "")

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


# ── health (unauthenticated, minimal) ─────────────────────────────────────────
@app.get("/api/health")
def health():
    return {"status": "ok", "engine_version": _settings.engine_version}


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


@app.post("/api/generate", status_code=202)
def generate(body: GenerateBody, principal: Principal = Depends(require(SCOPE_INGEST, "generate"))):
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
    return _handle(service.ingest_config, store, body.snapshot, tenant=principal.tenant_id)


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
        return _attest_store_for(tn).approve(
            att_id, tenant=tn, approved_by=principal.key_id, decided_at=body.decided_at,
            reason=body.reason)
    except AttestationError as e:
        raise HTTPException(status_code=404, detail=str(e))


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
        raise HTTPException(status_code=404, detail=str(e))


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
    tn = principal.tenant_id
    now = int(time.time())
    reg = _connector_registry_for(tn)
    reg.register(tenant=tn, connector_id=body.connector_id, kind=body.kind,
                 schedule_seconds=body.schedule_seconds, now=now, config=body.config)
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
    if reg.get(tn, connector_id) is None:
        raise HTTPException(status_code=404, detail=f"unknown connector {connector_id}")
    runner = service.make_connector_runner(tn, secret)
    return ConnectorScheduler(reg).run_one(tn, connector_id, runner, now=int(time.time()))


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
