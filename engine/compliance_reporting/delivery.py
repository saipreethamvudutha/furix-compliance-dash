"""
delivery.py
===========
Alert delivery sinks — the last mile that turns a regression (from
diff.alerts_from_diff) into a notification a human actually sees. Computing
alerts and delivering them are separated on purpose: diff.py decides *what*
changed for the worse; this module decides *where* that goes.

Sinks (all stdlib, no third-party dependency):
  * ConsoleSink   — human-readable to stdout/stderr
  * JsonlSink     — append structured alerts to a durable .jsonl audit file
  * WebhookSink   — POST a JSON payload (Slack-compatible) to a URL
  * MultiSink     — fan out to several sinks; one failing sink never blocks
                    the others (delivery is best-effort and logged)

Design rules:
  * A sink NEVER raises to its caller — a broken webhook must not crash a
    compliance run. Failures are captured and returned as DeliveryResult.
  * WebhookSink refuses non-https URLs unless explicitly allowed, and never
    puts alert content in the URL (no data in query strings).
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence


@dataclass
class DeliveryResult:
    sink: str
    delivered: int
    ok: bool
    error: str = ""


class AlertSink(Protocol):
    def send(self, alerts: Sequence[Mapping[str, Any]], *, context: Mapping[str, Any]) -> DeliveryResult:
        ...


def _severity_rank(a: Mapping[str, Any]) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(a.get("severity", "low"), 9)


# ── console ───────────────────────────────────────────────────────────────────
@dataclass
class ConsoleSink:
    stream: Any = None  # defaults to sys.stdout at send time (testable)

    def send(self, alerts, *, context) -> DeliveryResult:
        out = self.stream or sys.stdout
        try:
            if not alerts:
                out.write("compliance alerts: none (no regressions)\n")
            else:
                out.write(f"compliance alerts: {len(alerts)}\n")
                for a in sorted(alerts, key=_severity_rank):
                    out.write(f"  [{a.get('severity','?').upper()}] {a['type']}: {a['message']}\n")
            out.flush()
            return DeliveryResult("console", len(alerts), True)
        except Exception as exc:  # pragma: no cover - stream failure is rare
            return DeliveryResult("console", 0, False, str(exc))


# ── jsonl audit file ──────────────────────────────────────────────────────────
@dataclass
class JsonlSink:
    path: Path

    def send(self, alerts, *, context) -> DeliveryResult:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                for a in sorted(alerts, key=_severity_rank):
                    record = {**a, "context": dict(context)}
                    fh.write(json.dumps(record, sort_keys=True) + "\n")
                fh.flush()
            return DeliveryResult("jsonl", len(alerts), True)
        except Exception as exc:
            return DeliveryResult("jsonl", 0, False, str(exc))


# ── webhook (Slack-compatible) ────────────────────────────────────────────────
@dataclass
class WebhookSink:
    url: str
    allow_insecure: bool = False
    timeout: float = 5.0

    def _payload(self, alerts, context) -> dict[str, Any]:
        header = (
            f"Furix compliance: {len(alerts)} regression alert(s)"
            + (f" — {context.get('new_report_id','')[:8]}" if context.get("new_report_id") else "")
        )
        lines = [header] + [
            f"[{a.get('severity','?').upper()}] {a['type']}: {a['message']}"
            for a in sorted(alerts, key=_severity_rank)
        ]
        # Slack accepts {"text": ...}; generic receivers get the structured list too.
        return {"text": "\n".join(lines), "alerts": list(alerts), "context": dict(context)}

    def send(self, alerts, *, context) -> DeliveryResult:
        if not alerts:
            return DeliveryResult("webhook", 0, True)
        if not self.url.startswith("https://") and not self.allow_insecure:
            return DeliveryResult("webhook", 0, False, "refusing non-https webhook URL")
        data = json.dumps(self._payload(alerts, context)).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                status = getattr(resp, "status", 200)
            ok = 200 <= status < 300
            return DeliveryResult("webhook", len(alerts), ok, "" if ok else f"HTTP {status}")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return DeliveryResult("webhook", 0, False, str(exc))


# ── fan-out ───────────────────────────────────────────────────────────────────
@dataclass
class MultiSink:
    sinks: list[AlertSink] = field(default_factory=list)

    def send(self, alerts, *, context) -> list[DeliveryResult]:
        results = []
        for sink in self.sinks:
            try:
                results.append(sink.send(alerts, context=context))
            except Exception as exc:  # a sink must never break the run
                results.append(DeliveryResult(type(sink).__name__, 0, False, str(exc)))
        return results


def deliver_alerts(
    alerts: Sequence[Mapping[str, Any]],
    sinks: Sequence[AlertSink],
    *,
    context: Mapping[str, Any] | None = None,
) -> list[DeliveryResult]:
    """Convenience: fan alerts out to several sinks, best-effort."""
    return MultiSink(list(sinks)).send(alerts, context=context or {})
