"""
settings.py
===========
Centralized, environment-overridable configuration for the reporting engine.
Enterprise deployments configure via env vars; nothing here is hard-coded into
logic elsewhere. All values have safe defaults so the package runs with zero
configuration (the dev/test path).

Env vars (all optional):
  FURIX_REPORT_STORE        path to the report store           (default: _report_store)
  FURIX_ALERT_JSONL         path to append alert audit records  (default: <store>/alerts.jsonl)
  FURIX_ALERT_WEBHOOK       https URL for regression alerts     (default: unset → no webhook)
  FURIX_WEBHOOK_ALLOW_HTTP  "1" to permit non-https webhooks    (default: off)
  FURIX_FRAMEWORK_DROP_PCT  framework drop that triggers alert  (default: 5.0)

The engine version is deliberately NOT env-overridable (FUR-CMP-019): a
version is a property of the build, not of the deployment, and every report,
export and API banner must agree on one manifest.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .versions import ENGINE_VERSION


@dataclass(frozen=True)
class Settings:
    store_path: Path
    engine_version: str
    alert_jsonl: Path
    alert_webhook: str
    webhook_allow_http: bool
    framework_drop_threshold: float

    @classmethod
    def from_env(cls) -> "Settings":
        store = Path(os.environ.get("FURIX_REPORT_STORE", "_report_store"))
        return cls(
            store_path=store,
            engine_version=ENGINE_VERSION,
            alert_jsonl=Path(os.environ.get("FURIX_ALERT_JSONL", str(store / "alerts.jsonl"))),
            alert_webhook=os.environ.get("FURIX_ALERT_WEBHOOK", ""),
            webhook_allow_http=os.environ.get("FURIX_WEBHOOK_ALLOW_HTTP", "") == "1",
            framework_drop_threshold=float(os.environ.get("FURIX_FRAMEWORK_DROP_PCT", "5.0")),
        )

    def build_sinks(self):
        """Construct the alert sinks implied by the environment."""
        from .delivery import ConsoleSink, JsonlSink, WebhookSink

        sinks = [ConsoleSink(), JsonlSink(self.alert_jsonl)]
        if self.alert_webhook:
            sinks.append(WebhookSink(self.alert_webhook, allow_insecure=self.webhook_allow_http))
        return sinks
