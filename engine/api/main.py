"""
main.py
=======
FastAPI shell over the service layer. Deliberately thin: every endpoint is a few
lines that call `service`. The heavy pipeline is imported lazily inside
`service.ingest_batch`, so this app starts (and most endpoints work) without
torch/DB — only POST /api/ingest needs the full engine + a populated database.

Run:  uvicorn api.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from compliance_reporting.history import ReportStore
from compliance_reporting.render_html import render_html_report
from compliance_reporting.settings import Settings
from fastapi.responses import HTMLResponse, JSONResponse

from . import service

_settings = Settings.from_env()
_store = ReportStore(_settings.store_path)

app = FastAPI(title="Furix Compliance API", version=_settings.engine_version)

# CORS — allow the dashboard origin(s); override with FURIX_CORS_ORIGINS (comma-sep).
_origins = os.environ.get("FURIX_CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware, allow_origins=[o.strip() for o in _origins if o.strip()],
    allow_methods=["*"], allow_headers=["*"],
)


class IngestBody(BaseModel):
    text: str = ""
    log_type: str = "auto"


class GenerateBody(BaseModel):
    count: int = 50
    attack_ratio: float = 0.35
    seed: int = 0


def _handle(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except (FileNotFoundError, ValueError) as e:
        raise HTTPException(status_code=404, detail=str(e))
    except service.IngestError as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.get("/api/health")
def health():
    return {"status": "ok", "engine_version": _settings.engine_version,
            "reports": len(_store.entries())}


@app.post("/api/ingest")
def ingest(body: IngestBody):
    if not body.text.strip():
        raise HTTPException(status_code=400, detail="no log text provided")
    return _handle(service.ingest_batch, _store, body.text, log_type=body.log_type)


@app.post("/api/generate")
def generate(body: GenerateBody):
    return _handle(service.generate_and_ingest, _store,
                   count=body.count, attack_ratio=body.attack_ratio, seed=body.seed)


@app.post("/api/ingest-file")
async def ingest_file(file: UploadFile, log_type: str = "auto"):
    raw = (await file.read()).decode("utf-8", errors="replace")
    if not raw.strip():
        raise HTTPException(status_code=400, detail="empty file")
    return _handle(service.ingest_batch, _store, raw, log_type=log_type)


@app.get("/api/reports")
def reports():
    return service.list_reports(_store)


@app.get("/api/report/{report_id}")
def report(report_id: str):
    return _handle(service.get_report, _store, report_id)


@app.get("/api/report/{report_id}/html", response_class=HTMLResponse)
def report_html(report_id: str):
    rep = _handle(service.get_report, _store, report_id)
    return HTMLResponse(render_html_report(rep))


@app.get("/api/frameworks")
def frameworks(report: str = "latest"):
    return _handle(service.get_frameworks, _store, report)


@app.get("/api/summary")
def summary(report: str = "latest"):
    return _handle(service.get_summary, _store, report)


@app.get("/api/trend")
def trend():
    return service.get_trend(_store)


@app.get("/api/diff")
def diff(old: str, new: str):
    return _handle(service.get_diff, _store, old, new)
