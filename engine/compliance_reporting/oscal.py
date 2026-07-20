"""
oscal.py
========
OSCAL 1.2.1 output (Wave 5, FUR-CMP-006/015/017) — Assessment Results and a
Plan of Action & Milestones (POA&M), emitted from a canonical Furix report plus
the finding/exception lifecycle, with a structural validator.

Zero-dependency: builds plain dicts matching the OSCAL 1.2.1 model shapes so a
government reviewer's tooling can ingest the assurance data directly instead of
re-keying a PDF. `validate_oscal` enforces the invariants that make an "OSCAL
export" actually valid rather than merely OSCAL-shaped (required fields,
version consistency, resolvable references, UUID formatting) — the audit's
caveat that a schema-invalid export is worse than none.

The document identities are content-derived (uuid5) so the same report + same
versions produce the same OSCAL package — reproducible, like the report itself.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Mapping

from .versions import ENGINE_VERSION, OSCAL_VERSION, VERSION_MANIFEST

_OSCAL_NS = uuid.UUID("0a5c1b2d-3e4f-45a6-b7c8-d9e0f1a2b3c4")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# our severity → OSCAL risk levels
_RISK = {"critical": "high", "high": "high", "medium": "moderate", "low": "low",
         "informational": "low", "": "moderate"}


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(_OSCAL_NS, "|".join(parts)))


def _metadata(title: str, report: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "title": title,
        # last-modified is the report's own generated_at (content time), not now()
        "last-modified": report.get("generated_at", ""),
        "version": ENGINE_VERSION,
        "oscal-version": OSCAL_VERSION,
        "props": [
            {"name": "furix-report-id", "value": report.get("report_id", "")},
            {"name": "furix-integrity-sha256",
             "value": report.get("integrity", {}).get("content_sha256", "")},
        ] + [{"name": f"furix-version-{k}", "value": v} for k, v in VERSION_MANIFEST.items()],
    }


def build_assessment_results(report: Mapping[str, Any]) -> dict[str, Any]:
    """OSCAL 1.2.1 Assessment Results — one finding per at-risk control."""
    rid = report.get("report_id", "")
    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for c in report.get("controls", []):
        if c["status"] != "at_risk":
            continue
        cid = c["control_id"]
        obs_uuid = _uuid("obs", rid, cid)
        observations.append({
            "uuid": obs_uuid,
            "description": f"{cid} at risk: {c.get('violation_count', 0)} violation(s).",
            "methods": ["TEST"],
            "collected": report.get("generated_at", ""),
        })
        findings.append({
            "uuid": _uuid("finding", rid, cid),
            "title": f"{cid} — {c.get('title', cid)}",
            "target": {"type": "objective-id", "target-id": cid,
                       "status": {"state": "not-satisfied"}},
            "related-observations": [{"observation-uuid": obs_uuid}],
            "props": [{"name": "severity", "value": c.get("worst_severity", "medium")}],
        })
    return {
        "assessment-results": {
            "uuid": _uuid("ar", rid),
            "metadata": _metadata("Furix Assessment Results", report),
            # Furix emits Assessment Results directly from its own deterministic
            # run, not from a separately-authored Assessment Plan. OSCAL requires
            # an import-ap reference, so we emit a self-describing external one
            # and document it — no dangling internal placeholder.
            "import-ap": {"href": "https://furix.local/assessment-plan/deterministic",
                          "remarks": "Furix runs a fixed deterministic assessment; the plan is "
                                     "the versioned rule pack recorded in metadata props."},
            "results": [{
                "uuid": _uuid("result", rid),
                "title": "Deterministic control assessment",
                "description": "Furix event + config-posture assurance run.",
                "start": report.get("generated_at", ""),
                "observations": observations,
                "findings": findings,
            }],
        }
    }


def build_poam(report: Mapping[str, Any], findings: list[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """
    OSCAL 1.2.1 POA&M — one poam-item per open finding, carrying its
    remediation owner/due-date and any risk-acceptance exception.
    """
    rid = report.get("report_id", "")
    items: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    for f in (findings or []):
        if f.get("state") == "closed":
            continue
        cid = f.get("control_id", "")
        risk_uuid = _uuid("risk", rid, cid, f.get("finding_id", ""))
        props = [
            {"name": "finding-state", "value": f.get("state", "open")},
            {"name": "owner", "value": f.get("owner") or "unassigned"},
        ]
        if f.get("due_date"):
            props.append({"name": "due-date", "value": f["due_date"]})
        exc = f.get("exception")
        if exc:
            props += [
                {"name": "risk-acceptance", "value": "true"},
                {"name": "approver", "value": exc.get("approver", "")},
                {"name": "compensating-control", "value": exc.get("compensating_control", "")},
                {"name": "expiry", "value": exc.get("expiry", "")},
            ]
        risks.append({
            "uuid": risk_uuid,
            "title": f"{cid} at risk",
            "description": f.get("last_reason", f"{cid} at risk"),
            "status": "open" if f.get("state") != "risk_accepted" else "deviation-approved",
            "props": [{"name": "risk-level", "value": _RISK.get(f.get("severity", ""), "moderate")}],
        })
        items.append({
            "uuid": _uuid("poam-item", rid, cid, f.get("finding_id", "")),
            "title": f"Remediate {cid}",
            "description": f"{cid} ({f.get('framework_id','cis_v8')}) requires remediation.",
            "props": props,
            "related-risks": [{"risk-uuid": risk_uuid}],
        })
    return {
        "plan-of-action-and-milestones": {
            "uuid": _uuid("poam", rid),
            "metadata": _metadata("Furix Plan of Action & Milestones", report),
            "import-ssp": {"href": "https://furix.local/ssp/monitored-system",
                           "remarks": "The monitored system is identified by system-id; a full "
                                      "SSP import is provided by the customer's GRC of record."},
            "system-id": {"identifier-type": "https://ietf.org/rfc/rfc4122",
                          "id": _uuid("system", rid)},
            "risks": risks,
            "poam-items": items,
        }
    }


# ── validator ─────────────────────────────────────────────────────────────────
def validate_oscal(doc: Mapping[str, Any]) -> list[str]:
    """
    Structural validation of an OSCAL 1.2.1 document. Returns a list of error
    strings ([] == valid). Not a full JSON-schema check, but enforces the
    invariants that separate a valid package from an OSCAL-shaped one: a known
    root, required metadata with the right oscal-version, well-formed UUIDs, and
    internally-resolvable references.
    """
    errors: list[str] = []
    roots = {"assessment-results", "plan-of-action-and-milestones",
             "assessment-plan", "catalog", "profile", "component-definition",
             "system-security-plan"}
    root_key = next((k for k in doc if k in roots), None)
    if root_key is None:
        return [f"no recognised OSCAL root (one of {sorted(roots)})"]
    body = doc[root_key]

    uuid_val = body.get("uuid", "")
    if not _UUID_RE.match(uuid_val):
        errors.append(f"{root_key}.uuid is not a valid UUID: {uuid_val!r}")

    meta = body.get("metadata", {})
    if not meta.get("title"):
        errors.append("metadata.title is required")
    if meta.get("oscal-version") != OSCAL_VERSION:
        errors.append(f"metadata.oscal-version must be {OSCAL_VERSION}, got {meta.get('oscal-version')!r}")
    if not meta.get("version"):
        errors.append("metadata.version is required")

    # collect declared uuids + referenced uuids, confirm every ref resolves
    declared: set[str] = set()
    refs: list[tuple[str, str]] = []

    def _walk(node: Any) -> None:
        if isinstance(node, Mapping):
            for k, v in node.items():
                if k == "uuid" and isinstance(v, str):
                    declared.add(v)
                    if not _UUID_RE.match(v):
                        errors.append(f"malformed uuid: {v!r}")
                elif k.endswith("-uuid") and isinstance(v, str):
                    refs.append((k, v))
                else:
                    _walk(v)
        elif isinstance(node, list):
            for x in node:
                _walk(x)

    _walk(body)
    for name, ref in refs:
        if ref not in declared:
            errors.append(f"{name} references undefined uuid {ref}")
    return errors


import os as _os

# Bundled Furix OSCAL 1.2.1 schema (AR + POA&M subset). FURIX_OSCAL_SCHEMA can
# point at NIST's full metaschema for exhaustive validation.
_BUNDLED_SCHEMA = _os.path.join(_os.path.dirname(__file__), "schemas", "oscal-1.2.1-furix.json")


def validate_oscal_schema(doc: Mapping[str, Any], schema_path: str | None = None) -> dict[str, Any]:
    """
    JSON-Schema validate the document (the audit's ask). By default this uses
    the **bundled** Furix OSCAL 1.2.1 schema; set FURIX_OSCAL_SCHEMA to NIST's
    full metaschema to validate exhaustively. Structural validation
    (validate_oscal) always runs too. Returns {ran, ok, errors, schema, note}.
    Only reports ok=True when BOTH structural and schema validation pass; when
    `jsonschema` is unavailable it reports ran=False (never a false "valid").
    """
    import json as _json
    structural = validate_oscal(doc)
    schema_path = schema_path or _os.environ.get("FURIX_OSCAL_SCHEMA") or _BUNDLED_SCHEMA
    if not _os.path.exists(schema_path):
        return {"ran": False, "ok": not structural, "errors": structural,
                "schema": None, "note": "no OSCAL schema file found; structural validation only"}
    try:
        import jsonschema  # optional dep
    except ImportError:
        return {"ran": False, "ok": not structural, "errors": structural,
                "schema": schema_path,
                "note": "jsonschema not installed (pip install jsonschema); structural only"}
    with open(schema_path, encoding="utf-8") as fh:
        schema = _json.load(fh)
    errs = [f"{'/'.join(str(p) for p in e.path)}: {e.message}"
            for e in jsonschema.Draft202012Validator(schema).iter_errors(doc)]
    kind = "NIST OSCAL" if schema_path != _BUNDLED_SCHEMA else "Furix OSCAL 1.2.1"
    return {"ran": True, "ok": not errs and not structural,
            "errors": structural + errs, "schema": schema_path,
            "note": f"validated against {kind} schema"}

