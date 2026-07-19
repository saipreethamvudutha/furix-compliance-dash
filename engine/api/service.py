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
    analyzer: Analyzer | None = None,
    registry: FrameworkRegistry | None = None,
    deliver: bool = True,
    on_progress: Callable[[int, int, str], None] | None = None,
) -> dict[str, Any]:
    """
    Run each log line through the analyzer, build + verify a report, persist it,
    and (if a prior report exists) diff + deliver regression alerts.

    on_progress(processed, total, phase) is called during analysis and at each
    finalization phase, for the background-job progress bar.

    Returns {report_id, summary, frameworks, verification, alerts}.
    Raises IngestError if the built report fails verification.
    """
    analyzer = analyzer or _default_analyzer()
    registry = registry or FrameworkRegistry.from_live()

    typed_lines = classify_lines(split_log_lines(text), log_type)
    total = len(typed_lines)
    results = []
    for i, (detected_type, line) in enumerate(typed_lines):
        results.append({"log_type": detected_type, "result": dict(analyzer(line, detected_type))})
        if on_progress:
            on_progress(i + 1, total, "analyzing")

    if on_progress:
        on_progress(total, total, "finalizing")
    report = build_report(results, registry=registry)
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
    analyzer: Analyzer | None = None,
    registry: FrameworkRegistry | None = None,
    on_progress: Callable[[int, int, str], None] | None = None,
) -> dict[str, Any]:
    """Generate synthetic logs and ingest them (the dashboard 'Generate demo logs' path)."""
    from log_generator.generate import generate  # noqa: PLC0415

    lines = generate(count=count, attack_ratio=attack_ratio, types=types, seed=seed)
    return ingest_batch(store, "\n".join(lines), log_type="auto",
                        analyzer=analyzer, registry=registry, on_progress=on_progress)


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


def get_frameworks(store: ReportStore, report_id: str = "latest") -> list[dict[str, Any]]:
    return report_to_frameworks(store.load(_resolve(store, report_id)))


def get_summary(store: ReportStore, report_id: str = "latest") -> dict[str, Any]:
    return report_to_summary(store.load(_resolve(store, report_id)))


def get_trend(store: ReportStore) -> list[dict[str, Any]]:
    return store.trend()


def get_diff(store: ReportStore, old_id: str, new_id: str) -> dict[str, Any]:
    d = diff_reports(store.load(_resolve(store, old_id)), store.load(_resolve(store, new_id)))
    return {"diff": d, "alerts": alerts_from_diff(d)}
