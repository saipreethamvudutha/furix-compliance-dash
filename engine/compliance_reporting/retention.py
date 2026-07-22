"""
retention.py
============
Retention policy for immutable evidence (FUR-CMP-008).

Compliance frameworks mandate a MINIMUM retention for evidence / audit records:
HIPAA 6 years (45 CFR §164.316(b)(2)(i)), PCI DSS 12 months (Req 10.5.1), and so
on. Furix evidence objects are content-addressed and **write-once**, so retention
is not stamped onto the sealed envelope — it is computed at READ time from the
object's `collected_at` plus a configurable policy. That way a policy change (or
a stricter framework coming into scope) applies uniformly to every object without
rewriting anything immutable.

The effective policy is the STRICTEST (longest) applicable minimum. For a
HIPAA-covered entity that is 6 years, which also satisfies PCI's 12 months.

Configuration (env):
  FURIX_RETENTION_CLASS   governing framework key (default "hipaa")
  FURIX_RETENTION_DAYS    explicit override in days (wins over the class table)

Legal hold (see legal_hold.py) overrides expiry: evidence under an active hold is
never treated as past-retention, regardless of this policy.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

# Minimum retention by framework, in days. Longer is always compliant; these are
# the regulatory floors. The demo tenant (a health insurer) is HIPAA-governed.
FRAMEWORK_RETENTION_DAYS: dict[str, int] = {
    "hipaa": 2190,      # 6 years  (§164.316(b)(2)(i))
    "pci_dss": 365,     # 12 months (Req 10.5.1)
    "sox": 2555,        # 7 years
    "soc2": 365,        # 1 year (typical audit cycle)
    "iso27001": 1095,   # 3 years (common)
    "gdpr": 365,        # 1 year (varies by purpose; conservative floor)
}


def default_class() -> str:
    return os.environ.get("FURIX_RETENTION_CLASS", "hipaa").lower()


def policy_days() -> int:
    """Effective retention window in days: explicit override, else the class."""
    env = os.environ.get("FURIX_RETENTION_DAYS", "")
    if env.strip().isdigit():
        return int(env.strip())
    return FRAMEWORK_RETENTION_DAYS.get(default_class(), FRAMEWORK_RETENTION_DAYS["hipaa"])


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def retention_for(collected_at: str | None, *, now: datetime | None = None) -> dict:
    """Compute the retention posture for an object collected at `collected_at`.

    Returns: class, retention_days, retain_until (ISO or None), expired (bool),
    days_remaining (int or None). `now` is injectable for deterministic tests.
    """
    now = now or datetime.now(timezone.utc)
    days = policy_days()
    base = _parse_iso(collected_at)
    if base is None:
        # No usable collection time → cannot compute an expiry; treat as retained.
        return {
            "class": default_class(),
            "retention_days": days,
            "retain_until": None,
            "expired": False,
            "days_remaining": None,
        }
    until = base + timedelta(days=days)
    return {
        "class": default_class(),
        "retention_days": days,
        "retain_until": until.isoformat(timespec="seconds"),
        "expired": now > until,
        "days_remaining": (until - now).days,
    }
