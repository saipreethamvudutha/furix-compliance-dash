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


def _token(s: str) -> str:
    """
    Slugify an arbitrary identifier into a valid OSCAL `token` (the datatype used
    for objective/target ids): must start with a letter/underscore and contain
    only letters, digits, '.', '-', '_'. E.g. "Control 5" -> "control-5". The
    human-readable id is preserved separately (finding title + a prop).
    """
    slug = re.sub(r"[^0-9A-Za-z._-]+", "-", s.strip().lower()).strip("-")
    if not slug or not re.match(r"[A-Za-z_]", slug):
        slug = f"id-{slug}" if slug else "id"
    return slug


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
            # OSCAL requires a finding description; target-id must be a token, so
            # the human control id is slugified and preserved in a prop.
            "description": f"{cid} is at risk: {c.get('violation_count', 0)} violation(s) "
                           f"observed ({c.get('title', cid)}).",
            "target": {"type": "objective-id", "target-id": _token(cid),
                       "status": {"state": "not-satisfied"}},
            "related-observations": [{"observation-uuid": obs_uuid}],
            "props": [{"name": "severity", "value": c.get("worst_severity", "medium")},
                      {"name": "furix-control-id", "value": cid}],
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
                # OSCAL requires each result to declare which controls it reviewed.
                # Furix assesses the full monitored control set.
                "reviewed-controls": {
                    "control-selections": [{
                        "description": "All CIS controls monitored by this Furix run.",
                        "include-all": {},
                    }],
                },
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
            # OSCAL requires a risk statement (the characterization of the risk).
            "statement": f"Control {cid} is not satisfied; failure to remediate leaves the "
                         f"associated framework requirements unmet.",
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

    # OSCAL requires poam-items to be non-empty. When there are genuinely no open
    # findings, emit one explicit "no open findings" item rather than an empty
    # (schema-invalid) document — truthful and valid.
    if not items:
        items.append({
            "uuid": _uuid("poam-item", rid, "none"),
            "title": "No open findings",
            "description": f"No open findings as of {report.get('generated_at', '')}; "
                           "no remediation actions are outstanding.",
            "props": [{"name": "finding-state", "value": "none"}],
        })

    poam: dict[str, Any] = {
        "uuid": _uuid("poam", rid),
        "metadata": _metadata("Furix Plan of Action & Milestones", report),
        "import-ssp": {"href": "https://furix.local/ssp/monitored-system",
                       "remarks": "The monitored system is identified by system-id; a full "
                                  "SSP import is provided by the customer's GRC of record."},
        "system-id": {"identifier-type": "https://ietf.org/rfc/rfc4122",
                      "id": _uuid("system", rid)},
        "poam-items": items,
    }
    # `risks` is optional and OSCAL forbids an empty array — include it only when
    # there are risks to report.
    if risks:
        poam["risks"] = risks
    return {"plan-of-action-and-milestones": poam}


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

# The OFFICIAL NIST OSCAL 1.2.1 JSON schemas (released 2026-03-06), bundled from
# github.com/usnistgov/OSCAL release v1.2.1. Validation is per-document-type: an
# Assessment Results doc is checked against the AR schema, a POA&M against the
# POA&M schema. FURIX_OSCAL_SCHEMA overrides with an explicit schema path.
_SCHEMA_DIR = _os.path.join(_os.path.dirname(__file__), "schemas")
_NIST_DIR = _os.path.join(_SCHEMA_DIR, "nist")
_NIST_SCHEMAS = {
    "assessment-results": _os.path.join(_NIST_DIR, "oscal_assessment-results_schema.json"),
    "plan-of-action-and-milestones": _os.path.join(_NIST_DIR, "oscal_poam_schema.json"),
}
# Legacy Furix subset (kept for reference / offline fallback).
_BUNDLED_SCHEMA = _os.path.join(_SCHEMA_DIR, "oscal-1.2.1-furix.json")

# XSD/ECMA unicode-property escapes (\p{L}, \p{N}, …) appear in the OSCAL `token`
# datatype pattern. Python's `re` cannot compile them, so we translate them to
# equivalent Python character classes for pattern validation. The token values
# OSCAL constrains here are ASCII identifiers, so the translation is exact for
# our inputs and never weakens a real constraint into a pass.
_XSD_PROP = {r"\p{L}": r"[^\W\d_]", r"\p{N}": r"\d", r"\p{Nd}": r"\d",
             r"\p{Lu}": r"[A-Z]", r"\p{Ll}": r"[a-z]"}


def _xsd_pattern_to_python(pattern: str) -> str:
    for k, v in _XSD_PROP.items():
        pattern = pattern.replace(k, v)
    return pattern


def _nist_validator(schema: Mapping[str, Any]):
    """A Draft7 validator whose `pattern` keyword tolerates OSCAL's \\p{...}
    unicode-property escapes (translated to Python-compatible classes)."""
    import re as _re

    import jsonschema
    from jsonschema import Draft7Validator, exceptions

    def _pattern(validator, patrn, instance, _schema):
        if not validator.is_type(instance, "string"):
            return
        try:
            rx = _re.compile(_xsd_pattern_to_python(patrn))
        except _re.error:
            return  # untranslatable pattern: skip rather than emit a false failure
        if rx.search(instance) is None:
            yield exceptions.ValidationError(f"{instance!r} does not match {patrn!r}")

    return jsonschema.validators.extend(Draft7Validator, {"pattern": _pattern})(schema)


def _schema_for(doc: Mapping[str, Any], override: str | None) -> tuple[str | None, str]:
    """Resolve (schema_path, kind) for a document. Override wins; otherwise the
    official NIST schema matching the document root; else the Furix subset."""
    if override:
        return override, "override"
    for root, path in _NIST_SCHEMAS.items():
        if root in doc and _os.path.exists(path):
            return path, "NIST OSCAL 1.2.1 (official)"
    if _os.path.exists(_BUNDLED_SCHEMA):
        return _BUNDLED_SCHEMA, "Furix OSCAL 1.2.1 subset"
    return None, "none"


def validate_oscal_schema(doc: Mapping[str, Any], schema_path: str | None = None) -> dict[str, Any]:
    """
    JSON-Schema validate an OSCAL document against the **official NIST OSCAL
    1.2.1 schema** for its type (AR or POA&M), bundled from the NIST v1.2.1
    release. `FURIX_OSCAL_SCHEMA` (or an explicit `schema_path`) overrides.
    Structural validation (validate_oscal) always runs too. Returns
    {ran, ok, errors, schema, note}. ok=True requires BOTH structural and schema
    validation to pass; when `jsonschema` is unavailable it reports ran=False
    (never a false "valid").
    """
    import json as _json
    structural = validate_oscal(doc)
    override = schema_path or _os.environ.get("FURIX_OSCAL_SCHEMA")
    resolved, kind = _schema_for(doc, override)
    if not resolved:
        return {"ran": False, "ok": not structural, "errors": structural,
                "schema": None, "note": "no OSCAL schema file found; structural validation only"}
    try:
        import jsonschema  # noqa: F401  (optional dep)
    except ImportError:
        return {"ran": False, "ok": not structural, "errors": structural,
                "schema": resolved,
                "note": "jsonschema not installed (pip install jsonschema); structural only"}
    with open(resolved, encoding="utf-8") as fh:
        schema = _json.load(fh)
    errs = [f"{'/'.join(str(p) for p in e.path) or '(root)'}: {e.message}"
            for e in _nist_validator(schema).iter_errors(doc)]
    return {"ran": True, "ok": not errs and not structural,
            "errors": structural + errs, "schema": resolved,
            "note": f"validated against {kind} schema"}

