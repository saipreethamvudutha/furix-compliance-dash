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

from . import service
from .auth import AuthError, AuthRegistry, ForbiddenError, Principal, SCOPE_INGEST, SCOPE_READ
from .jobs import JobManager
from .tenancy import TenantStores

_settings = Settings.from_env()
_auth = AuthRegistry.from_env()
_stores = TenantStores(_settings.store_path)
_jobs = JobManager()

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
    job_id = _jobs.submit(
        lambda progress: service.ingest_batch(store, text, log_type=lt, tenant=tn,
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
    job_id = _jobs.submit(
        lambda progress: service.ingest_batch(store, raw, log_type=log_type, tenant=tn,
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


@app.get("/api/diff")
def diff(old: str, new: str,
         principal: Principal = Depends(require(SCOPE_READ, "diff")),
         tenant: str | None = None):
    return _handle(service.get_diff, _store_for(principal, tenant), old, new)
