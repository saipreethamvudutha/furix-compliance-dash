"""
exceptions.py
=============
Finding → remediation → exception lifecycle (Wave 5, FUR-CMP-013).

An at-risk control produces a **Finding**. A finding has an owner and a due
date, moves through a remediation workflow, and can be granted a time-boxed
**risk-acceptance exception** (with a compensating control and an approver)
that expires. Nothing is deleted: the store is **event-sourced** — every state
change appends an immutable event recording the actor, authority, previous and
new state, reason, timestamp, and a content-derived event id (the audit's
"handover rule"). Current state is a projection over that log.

Lifecycle
---------
    OPEN ─▶ IN_PROGRESS ─▶ REMEDIATED ─▶ RETEST_PENDING ─▶ CLOSED
      │                                        │
      └────────────▶ RISK_ACCEPTED ────────────┘   (exception, with expiry)
                          │
                          └────────▶ EXPIRED   (acceptance lapsed → back at risk)

A CLOSED finding requires a passing retest. A RISK_ACCEPTED finding carries an
approver, rationale, compensating control and an expiry; once `as_of` passes the
expiry it is EXPIRED and the control is at risk again — an accepted risk can
never silently become permanent.

Determinism: event ids are uuid5 over (finding_id, seq, actor, to_state,
reason, occurred_at). Times are explicit inputs (occurred_at / as_of), never
wall-clock, so the store is reproducible and testable.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, Iterable

_EVENT_NS = uuid.UUID("c1d2e3f4-a5b6-47c8-9d0e-1f2a3b4c5d6e")

# lifecycle states
OPEN = "open"
IN_PROGRESS = "in_progress"
REMEDIATED = "remediated"
RETEST_PENDING = "retest_pending"
CLOSED = "closed"
RISK_ACCEPTED = "risk_accepted"
EXPIRED = "expired"

OPEN_STATES = frozenset({OPEN, IN_PROGRESS, REMEDIATED, RETEST_PENDING, RISK_ACCEPTED, EXPIRED})
TERMINAL_STATES = frozenset({CLOSED})

# allowed transitions: from_state -> {actions}. Each action names a to_state.
_TRANSITIONS: dict[str, dict[str, str]] = {
    OPEN:           {"start": IN_PROGRESS, "accept_risk": RISK_ACCEPTED, "remediate": REMEDIATED},
    IN_PROGRESS:    {"remediate": REMEDIATED, "accept_risk": RISK_ACCEPTED},
    REMEDIATED:     {"request_retest": RETEST_PENDING, "reopen": OPEN},
    RETEST_PENDING: {"retest_pass": CLOSED, "retest_fail": OPEN},
    RISK_ACCEPTED:  {"expire": EXPIRED, "revoke": OPEN, "remediate": REMEDIATED},
    EXPIRED:        {"reaccept": RISK_ACCEPTED, "start": IN_PROGRESS, "remediate": REMEDIATED},
    CLOSED:         {"reopen": OPEN},
}


class LifecycleError(Exception):
    """An illegal transition or missing required field."""


@dataclass
class FindingEvent:
    finding_id: str
    seq: int
    action: str
    from_state: str
    to_state: str
    actor: str
    reason: str
    occurred_at: str
    payload: dict[str, Any] = field(default_factory=dict)
    event_id: str = ""

    def compute_id(self) -> str:
        basis = f"{self.finding_id}|{self.seq}|{self.actor}|{self.to_state}|{self.reason}|{self.occurred_at}"
        return str(uuid.uuid5(_EVENT_NS, basis))

    def to_dict(self) -> dict[str, Any]:
        d = {
            "finding_id": self.finding_id, "seq": self.seq, "action": self.action,
            "from_state": self.from_state, "to_state": self.to_state, "actor": self.actor,
            "reason": self.reason, "occurred_at": self.occurred_at, "payload": self.payload,
            "event_id": self.event_id or self.compute_id(),
        }
        return d


def new_finding_id(tenant: str, control_id: str, framework_id: str, discovered_report: str) -> str:
    """Stable finding identity — same control in the same framework/tenant is one finding."""
    return str(uuid.uuid5(_EVENT_NS, f"{tenant}|{framework_id}|{control_id}|{discovered_report}"))


def project(events: list[dict[str, Any]], *, as_of: str | None = None) -> dict[str, Any]:
    """
    Fold an ordered event list into the finding's current state, then apply
    time-based expiry (RISK_ACCEPTED past its expiry → EXPIRED) if `as_of` given.
    """
    if not events:
        return {}
    events = sorted(events, key=lambda e: e["seq"])
    first, last = events[0], events[-1]
    state = last["to_state"]
    meta = dict(first.get("payload", {}))
    for e in events:                       # accumulate the latest known fields
        meta.update({k: v for k, v in e.get("payload", {}).items() if v is not None})
    proj = {
        "finding_id": first["finding_id"],
        "state": state,
        "control_id": meta.get("control_id"),
        "framework_id": meta.get("framework_id"),
        "severity": meta.get("severity"),
        "owner": meta.get("owner"),
        "due_date": meta.get("due_date"),
        "discovered_report": meta.get("discovered_report"),
        "exception": meta.get("exception"),
        "retest": meta.get("retest"),
        "events": len(events),
        "last_actor": last["actor"],
        "last_reason": last["reason"],
        "updated_at": last["occurred_at"],
    }
    # apply expiry deterministically against an explicit as_of
    if state == RISK_ACCEPTED and as_of and proj.get("exception", {}).get("expiry"):
        try:
            if datetime.fromisoformat(as_of) >= datetime.fromisoformat(proj["exception"]["expiry"]):
                proj["state"] = EXPIRED
                proj["expired"] = True
        except ValueError:
            pass
    return proj


class FindingStore:
    """Event-sourced, append-only per-tenant finding lifecycle store."""

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.path = self.root / "findings.jsonl"
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    # ── low level ──────────────────────────────────────────────────────────────
    def _all_events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(ln) for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def _events_for(self, finding_id: str) -> list[dict[str, Any]]:
        return [e for e in self._all_events() if e["finding_id"] == finding_id]

    def _append(self, event: FindingEvent) -> dict[str, Any]:
        rec = event.to_dict()
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec

    # ── public API ─────────────────────────────────────────────────────────────
    def open_finding(self, finding_id: str, *, control_id: str, framework_id: str,
                     severity: str, actor: str, occurred_at: str, owner: str | None = None,
                     due_date: str | None = None, discovered_report: str | None = None,
                     reason: str = "control at risk") -> dict[str, Any]:
        """Create a finding in OPEN (idempotent: re-opening an existing id is a no-op)."""
        existing = self._events_for(finding_id)
        if existing:
            return project(existing)
        ev = FindingEvent(
            finding_id=finding_id, seq=1, action="open", from_state="", to_state=OPEN,
            actor=actor, reason=reason, occurred_at=occurred_at,
            payload={"control_id": control_id, "framework_id": framework_id,
                     "severity": severity, "owner": owner, "due_date": due_date,
                     "discovered_report": discovered_report},
        )
        self._append(ev)
        return project(self._events_for(finding_id))

    def transition(self, finding_id: str, action: str, *, actor: str, occurred_at: str,
                   reason: str = "", payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Apply a lifecycle action, enforcing the allowed transition graph."""
        events = self._events_for(finding_id)
        if not events:
            raise LifecycleError(f"unknown finding {finding_id}")
        current = project(events)["state"]
        allowed = _TRANSITIONS.get(current, {})
        if action not in allowed:
            raise LifecycleError(f"illegal action {action!r} from state {current!r}")
        to_state = allowed[action]
        self._validate(action, payload or {})
        ev = FindingEvent(
            finding_id=finding_id, seq=len(events) + 1, action=action,
            from_state=current, to_state=to_state, actor=actor, reason=reason,
            occurred_at=occurred_at, payload=payload or {},
        )
        self._append(ev)
        return project(self._events_for(finding_id))

    @staticmethod
    def _validate(action: str, payload: dict[str, Any]) -> None:
        if action == "accept_risk":
            exc = payload.get("exception") or {}
            for req in ("approver", "rationale", "compensating_control", "expiry"):
                if not exc.get(req):
                    raise LifecycleError(f"accept_risk requires exception.{req}")
        if action == "retest_pass":
            if not (payload.get("retest") or {}).get("report_id"):
                raise LifecycleError("retest_pass requires retest.report_id")

    # ── reads ──────────────────────────────────────────────────────────────────
    def get(self, finding_id: str, *, as_of: str | None = None) -> dict[str, Any]:
        return project(self._events_for(finding_id), as_of=as_of)

    def history(self, finding_id: str) -> list[dict[str, Any]]:
        return sorted(self._events_for(finding_id), key=lambda e: e["seq"])

    def list(self, *, as_of: str | None = None, open_only: bool = False) -> list[dict[str, Any]]:
        by_id: dict[str, list[dict[str, Any]]] = {}
        for e in self._all_events():
            by_id.setdefault(e["finding_id"], []).append(e)
        out = [project(evs, as_of=as_of) for evs in by_id.values()]
        if open_only:
            out = [f for f in out if f["state"] in OPEN_STATES]
        return sorted(out, key=lambda f: (f.get("severity") or "", f["finding_id"]))
